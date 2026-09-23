//! CMD_SIGN_USEROP — Coinbase-Smart-Wallet-style sign command (all SHA-256).
//!
//! After the Coinbase Smart Wallet port, every signature on the wallet is a
//! SPHINCS+C10 sig over a purely-SHA-256 digest (no keccak on the sign path —
//! STM32U585 has HW SHA-256 but no keccak accelerator). The on-chain wallet
//! owns an array of 64-byte C10 owners: owner index 0 is the immutable
//! bootstrap key; owner index 1 is the per-chain slot-0 key (added by the
//! factory on deploy); higher indices are slot keys added by the bootstrap
//! when the previous slot hits its 65,536-sig cap.
//!
//! Three flows, selected by the companion-supplied flags field:
//!
//!   * **Deploy** (`FLAG_INCLUDE_INIT_CODE` only, slot_index = 0)
//!     The wallet doesn't yet exist on this chain. Firmware:
//!       1. Derives slot-0 for `(chain_id, 0)`.
//!       2. Signs `sha256("pqwallet-factory-add-slot" || chain_id ||
//!          slot0PkSeed || slot0PkRoot)` with the bootstrap key — this
//!          is the `factorySig` that unlocks `createAccount` on-chain.
//!       3. Assembles the factory-call `initCode` carrying `factorySig`.
//!       4. Signs the user's single UserOp (with `initCode` attached)
//!          using slot-0.
//!     Output: initCode + Type 2 sig wrapper (`ownerIndex = 1`).
//!
//!   * **Rotation** (`FLAG_REGISTER_SLOT` only, slot_index ≥ 1)
//!     slot N-1 is exhausted / compromised. Firmware:
//!       1. Derives slot-N for `(chain_id, slot_index)`.
//!       2. Builds an internal `addOwnerBytes(slot_N_owner_bytes)` UserOp,
//!          signs its SHA-256 sphincs digest with the bootstrap key.
//!       3. Builds the user's UserOp (nonce = base+1), signs with slot-N.
//!     Output: Type 1 sig wrapper (`ownerIndex = 0`) + Type 2 sig wrapper
//!     (`ownerIndex = slot_index + 1`).
//!
//!   * **Normal** (neither flag)
//!     Slot-N is already registered on-chain. Firmware:
//!       1. Derives (or reuses cached) slot-N.
//!       2. Signs the user's UserOp with slot-N.
//!     Output: Type 2 sig wrapper only.
//!
//! `FLAG_INCLUDE_INIT_CODE` and `FLAG_REGISTER_SLOT` are mutually exclusive
//! — first deploy cannot simultaneously be a rotation (slot-0 is set by the
//! factory atomically, no separate addOwner needed).
//!
//! Firmware is still stateless: slot keys are derived on demand from
//! `(master_entropy, chain_id, slot_index)` and cached in SRAM across the
//! unlock session. Bootstrap key regen happens only on rotation/deploy paths.
//!
//! Every signature is verified locally before being written to NS
//! (fault-injection guard, double-evaluated).

use sphincs_tz_shared::{
    NscStatus, C10_SIG_LEN, COW_ORDER_TRAILER_MAX_LEN, ERC7730_MAX_TRAILER_LEN,
    FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT, GPV2_SETTLEMENT_ADDRESS, MAX_SIGN_RESPONSE_LEN,
    MAX_TX_LEN, PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SAFE_V1_PAYLOAD_MAX, SET_PRE_SIGNATURE_SELECTOR,
    SIGN_USEROP_HEADER_LEN, SIG_WRAPPER_LEN,
};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, Zeroizing};

/// Domain tag the firmware signs when authorising slot-0 on a new chain.
/// MUST match `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, ENTRY_POINT_V06, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use crate::names::{verify_name_bundle, NameResolver, MAX_NAME_BUNDLES, MAX_NAME_BUNDLE_LEN};
use crate::selectors::{
    parse_self_attest_bundle, verify_selector_bundle, SelectorMeta, MAX_SELECTOR_BUNDLE_LEN,
    MAX_SELF_ATTEST_BUNDLE_LEN,
};
use crate::tx::display::pick_sign_pages_with_erc7730_evidence;
use crate::tx::eip1559::{Eip1559Tx, UserOpDisplayFields, U256};
use crate::ui;

/// Reserve enough room to TOCTOU-snapshot the largest valid input the
/// gateway will accept. The trailing `1 + MAX_NAME_BUNDLES * (2 +
/// MAX_NAME_BUNDLE_LEN)` block is the address-name bundle section.
/// Two selector trailers sit between `safe_v1` and the names section
/// (mutually exclusive at parse time): the curated Merkle-bundle slot
/// followed by the self-attest slot.
const SNAP_LEN: usize = SIGN_USEROP_HEADER_LEN
    + MAX_TX_LEN
    + 2 + MAX_ERC20_BUNDLE_LEN
    + 2 // reserved compatibility length field; must be 0
    + 2 + COW_ORDER_TRAILER_MAX_LEN
    + 2 + SAFE_V1_PAYLOAD_MAX
    + 2 + MAX_SELECTOR_BUNDLE_LEN
    + 2 + MAX_SELF_ATTEST_BUNDLE_LEN
    + 2 + ERC7730_MAX_TRAILER_LEN
    + 1 + MAX_NAME_BUNDLES * (2 + MAX_NAME_BUNDLE_LEN);

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// derefs (TOCTOU snapshot read + signed-response write) happen only
/// after `validate_ns_{read,write}_ptr` proves each range is fully
/// NS-classified. `static mut` driver state (`SE`, `SLOT_CACHE`,
/// `SNAP_BUF`) is touched under the single-threaded dispatcher
/// invariant + `HandlerGuard` (HIGH-7).
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::ui::confirm::{confirm_checked, ConfirmResult};

    // HIGH-7 fix: mark the handler as busy so SysTick's background
    // idle-wipe path cannot zero out `master_secret` while we still
    // hold a stack-local copy of it. Dropped on scope exit.
    let _busy = super::HandlerGuard::enter();

    ui::show_status("Sign", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_USEROP_HEADER_LEN || total_len > SNAP_LEN {
        ui::show_status("Sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): route the NS-pointer gates
    // through the Hamming-distant sentinel (`check_true_into_sentinel`)
    // rather than a bare `if !validate(...)`. A single instruction-skip /
    // stuck-at on a plain reject branch falls through into the handler body
    // with an unvalidated pointer — NS then picks an `out_ptr` into secure
    // SRAM and the response write below becomes an OOB write across the
    // S/NS boundary. The sentinel comparison closes the value / stuck-at-
    // register class (a random faulted value is not `OK_SENTINEL`), but NOT the
    // one-skip-of-the-reject-branch residual on its own (finding F5): a precise
    // skip of the `if != OK_SENTINEL` branch still falls through. That residual
    // is closed by RE-VALIDATING the write extent immediately before the output
    // write (§15 below), so a single glitch must skip two spatially-distant
    // reject branches. Same idiom as the §14 6492 re-validation in
    // cmd_sign_offchain.rs. (The FI-bypass count itself is validated by the
    // deferred rainbow instruction-skip sweep on the real ELF, not in-repo.)
    crate::fi::scrub_sentinel_register();
    let read_ptr_ok =
        crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(args.arg0, total_len));
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    let write_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if write_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // Shared with the sibling sign handlers via `super::SIGN_SNAP_BUF`
    // (one buffer for all three; safe because the dispatcher is
    // non-reentrant — see the buffer's doc comment). The const assert pins
    // this handler's protocol max ≤ the shared buffer so the `..total_len`
    // slice below (with `total_len <= SNAP_LEN`, checked at the header
    // length gate above) can never overrun.
    const _: () = assert!(SNAP_LEN <= super::SIGN_SNAP_BUF_LEN);
    // `ui-px`: the screen transcript overlays the buffer beyond SNAP_LEN.
    #[cfg(feature = "ui-px")]
    const _: () = assert!(super::SIGN_SNAP_BUF_LEN - SNAP_LEN >= pqsigner_ui_px::SCREENS_BYTES);
    // M1 fix: wipe any leftover payload from the PREVIOUS sign before
    // we fill it with this request.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    // The pixel UI (`ui-px`) overlays its screen transcript on the tail of the
    // shared buffer beyond this handler's own snapshot maximum — disjoint
    // bytes, split once here so no two live borrows overlap.
    let (snap_full, px_scratch) =
        (&mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF)).split_at_mut(SNAP_LEN);
    let snap = &mut snap_full[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // The wallet and factory are frozen to the canonical EntryPoint v0.6
    // singleton. Treat the companion field as an assertion, never as signing
    // authority: compare it twice through independent fail-closed sentinel
    // gates before parsing any other request field, then feed only
    // `ENTRY_POINT_V06` into every digest below. Even an instruction skip over
    // one reject cannot turn hostile wire bytes into a signed domain, and the
    // second spatially separate gate still rejects the mismatch under the
    // single-fault model.
    // SAFETY: the validated fixed header contains bytes 32..52 in the local
    // S-world snapshot. Volatile aggregate reads keep the two FI samples
    // independent under LTO instead of allowing common-subexpression folding.
    let supplied_entry_point_a =
        unsafe { core::ptr::read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>()) };
    let entry_point_match_a = supplied_entry_point_a.ct_eq(&ENTRY_POINT_V06).unwrap_u8();
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_a) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "wrong EntryPoint");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    crate::fi::wait_random();
    // SAFETY: same validated snapshot range; deliberately re-read volatile
    // after the randomized gap for an independent second sample.
    let supplied_entry_point_b =
        unsafe { core::ptr::read_volatile(snap.as_ptr().add(32).cast::<[u8; 20]>()) };
    let entry_point_match_b = supplied_entry_point_b.ct_eq(&ENTRY_POINT_V06).unwrap_u8();
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(entry_point_match_b) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "wrong EntryPoint");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();

    // ── 4. Parse header (big-endian, fixed offsets) ────────────────
    let chain_id = u64::from_be_bytes([
        snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
    ]);
    // F-11 hardening: parse flags from the snapshot twice with a
    // randomised gap between, then halt on mismatch. The snapshot lives
    // in S-world SRAM (no NS races), so a divergence is necessarily a
    // glitch on the register/load path between the two reads. The
    // recheck below — after slot_index / account_index are derived —
    // catches faults that land *between* the parse and the gate.
    let flags_a = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    crate::fi::wait_random();
    let flags_b = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_a != flags_b {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let flags = flags_a;
    // FI structure preserved: `flags` is read twice (above) + rechecked below;
    // this only routes the bitfield EXTRACTION through the Kani-proven
    // `decode_flags` kernel (`#[inline]` → identical codegen under LTO).
    let (include_init_code, register_slot, account_index, slot_index) =
        crate::aa::userop::decode_flags(flags);

    #[cfg(all(feature = "e2e-test", feature = "ui-lcd"))]
    {
        static mut E2E_CALL_NO: u8 = 0;
        // SAFETY: category 5 — `E2E_CALL_NO` is a `static mut` debug-
        // only counter compiled in only under `e2e-test` + `ui-lcd`.
        // Single-threaded non-reentrant dispatcher serialises access;
        // not present in production builds.
        let n = unsafe {
            E2E_CALL_NO = E2E_CALL_NO.wrapping_add(1);
            E2E_CALL_NO
        };
        let title: &str = match n {
            1 => "e2e Sign 1/4",
            2 => "e2e Sign 2/4",
            3 => "e2e Sign 3/4",
            4 => "e2e Sign 4/4",
            _ => "e2e Sign ?",
        };
        let kind = if include_init_code {
            "Deploy"
        } else if register_slot {
            "T1+T2"
        } else {
            "T2 only"
        };
        ui::show_status(title, kind);
    }
    let mut companion_sender = [0u8; 20];
    companion_sender.copy_from_slice(&snap[12..32]);

    let mut nonce = [0u8; 32];
    nonce.copy_from_slice(&snap[52..84]);
    let mut call_gas_limit = [0u8; 32];
    call_gas_limit.copy_from_slice(&snap[84..116]);
    let mut verification_gas_limit = [0u8; 32];
    verification_gas_limit.copy_from_slice(&snap[116..148]);
    let mut pre_verification_gas = [0u8; 32];
    pre_verification_gas.copy_from_slice(&snap[148..180]);
    let mut max_fee_per_gas = [0u8; 32];
    max_fee_per_gas.copy_from_slice(&snap[180..212]);
    let mut max_priority_fee_per_gas = [0u8; 32];
    max_priority_fee_per_gas.copy_from_slice(&snap[212..244]);
    let mut paymaster_and_data_hash = [0u8; 32];
    paymaster_and_data_hash.copy_from_slice(&snap[244..276]);
    let mut to_address = [0u8; 20];
    to_address.copy_from_slice(&snap[276..296]);
    let mut value = [0u8; 32];
    value.copy_from_slice(&snap[296..328]);
    // Kani-proven `validate_data_len`: keeps the inner-tx data slice
    // `snap[HEADER_LEN..HEADER_LEN+data_len]` (cut below) in bounds + caps it at
    // MAX_TX_LEN, so no companion `data_len` can drive an OOB read.
    let data_len = match crate::aa::userop::validate_data_len(
        total_len,
        u16::from_be_bytes([snap[328], snap[329]]),
    ) {
        Some(d) => d,
        None => {
            ui::show_status("Sign", "bad data_len");
            return NscStatus::InvalidPointer as u32;
        }
    };

    // Flag-combination invariants (post-Coinbase-port):
    //   * INCLUDE_INIT_CODE and REGISTER_SLOT are mutually exclusive —
    //     first-deploy bundles its slot-0 registration into the factory
    //     call, so there is never a separate addOwner UserOp on deploy.
    //   * INCLUDE_INIT_CODE requires slot_index == 0 (the factory can
    //     only pre-register the canonical slot 0).
    //   * REGISTER_SLOT requires slot_index >= 1 (rotation only; slot-0
    //     is already added by the factory on deploy).
    if include_init_code && register_slot {
        ui::show_status("Sign", "incompatible flags");
        return NscStatus::InvalidPointer as u32;
    }
    if include_init_code && slot_index != 0 {
        ui::show_status("Sign", "init_code needs slot0");
        return NscStatus::InvalidPointer as u32;
    }
    if register_slot && slot_index == 0 {
        ui::show_status("Sign", "register needs slot>=1");
        return NscStatus::InvalidPointer as u32;
    }

    // F-11 belt-and-braces: re-derive flags / slot_index from the
    // snapshot and re-run the three sanity gates. A single-shot fault
    // on the derived values would have to land twice (once before each
    // gate) to bypass; an instruction-skip fault on a single conjunct
    // is caught by the second check refreshing the inputs from snap[].
    crate::fi::wait_random();
    let flags_recheck = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_recheck != flags {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    // Same kernel as the first decode (the redundant read + this full-field
    // recheck ARE the F-11 countermeasure). Account index is load-bearing: it
    // selects the mnemonic-derived sender checked below.
    let (include_init_code_r, register_slot_r, account_index_r, slot_index_r) =
        crate::aa::userop::decode_flags(flags_recheck);
    if include_init_code_r != include_init_code
        || register_slot_r != register_slot
        || account_index_r != account_index
        || slot_index_r != slot_index
    {
        ui::show_status("Sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    if include_init_code_r && register_slot_r {
        ui::show_status("Sign", "fi flag conflict");
        return NscStatus::InternalError as u32;
    }
    if include_init_code_r && slot_index_r != 0 {
        ui::show_status("Sign", "fi init_code slot");
        return NscStatus::InternalError as u32;
    }
    if register_slot_r && slot_index_r == 0 {
        ui::show_status("Sign", "fi register slot");
        return NscStatus::InternalError as u32;
    }

    // CRIT-17: refuse nonce-seq overflow. v0.6 nonces are 192-bit key | 64-bit seq.
    // When REGISTER_SLOT is set, Type 2 nonce = base + 1 — overflowing the
    // seq would carry into the key field and silently change the nonce key.
    if register_slot && nonce[24..32] == [0xFFu8; 8] {
        ui::show_status("Nonce seq", "overflow");
        return NscStatus::InvalidPointer as u32;
    }
    // Derive the exact nonce of the transaction UserOp before rendering.
    // REGISTER_SLOT emits a separate Type-1 UserOp at `nonce`; the displayed
    // and signed Type-2 transaction is at `nonce + 1` within the same lane.
    // The overflow gate above proves this increment cannot carry into key192.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

    let inner_data: &[u8] = &snap[SIGN_USEROP_HEADER_LEN..SIGN_USEROP_HEADER_LEN + data_len];

    // ── 5. Parse optional trailers ─────────────────────────────────
    //
    // Three independently-optional length-prefixed trailers (ERC-20
    // bundle, reserved compatibility slot, native CoW EIP-712), followed by the
    // address-name bundles section. Each uses the same
    // `[u16 BE len][payload]` framing, delegated to the `trailer`
    // helper so bounds-checking and error-label routing stay
    // consistent. Absent trailer == trailer with len == 0.
    let mut cursor = SIGN_USEROP_HEADER_LEN + data_len;

    let erc20 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_ERC20_BUNDLE_LEN,
        "bad erc20 bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = erc20.next_cursor;

    // Reserved compatibility slot. The 2-byte length field is kept for
    // wire-offset stability of the trailers that follow. `max_len = 0`
    // makes the read fail-closed: a non-zero declared length is rejected,
    // and no payload bytes are ever parsed.
    let reserved_v1 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        0,
        "reserved slot must be 0",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = reserved_v1.next_cursor;

    // CoW order trailer: canonical(204) [|| sell_len(2) || sell_bundle
    // || buy_len(2) || buy_bundle]. Companion sends the whole trailer;
    // no NS-side injection: token metadata is decoded on-device from the
    // ERC-20 bundles. Absent is
    // legal for non-CoW tx — the CoW downgrade-mitigation gate below
    // enforces presence when needed.
    //
    // Inlined instead of `trailer::read_optional_u16_prefixed` so the
    // OLED distinguishes the two failure modes (oversized declared
    // length vs. declared length overflowing the payload) — makes
    // companion-vs-NS-router layout disagreements trivial to triage.
    let cow_order = if cursor + 2 > total_len {
        super::trailer::Trailer {
            start: cursor,
            len: 0,
            next_cursor: cursor,
        }
    } else {
        let declared = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        let payload_start = cursor + 2;
        if declared > COW_ORDER_TRAILER_MAX_LEN {
            // Dump four values across the 4-line OLED:
            //   line 1: "Sign v3 len>cap"
            //   line 2: "d=XXXX (data_len)"
            //   line 3: "e=XXXX r=XXXX   "   (erc20 + reserved declared len)
            //   line 4: "v3=XXXX        "
            // Expected happy values for a CoW swap on Base:
            //   d=00a4 (164), e=0000, r=0000, v3=0790 (or 02cc bare).
            const HEX: &[u8] = b"0123456789abcdef";
            let d = data_len as u16;
            let e = erc20.len as u16;
            let r = reserved_v1.len as u16;
            let v = declared as u16;

            let mut line2 = [b' '; 16];
            line2[0] = b'd';
            line2[1] = b'=';
            line2[2] = HEX[((d >> 12) & 0xF) as usize];
            line2[3] = HEX[((d >> 8) & 0xF) as usize];
            line2[4] = HEX[((d >> 4) & 0xF) as usize];
            line2[5] = HEX[(d & 0xF) as usize];

            let mut line3 = [b' '; 16];
            line3[0] = b'e';
            line3[1] = b'=';
            line3[2] = HEX[((e >> 12) & 0xF) as usize];
            line3[3] = HEX[((e >> 8) & 0xF) as usize];
            line3[4] = HEX[((e >> 4) & 0xF) as usize];
            line3[5] = HEX[(e & 0xF) as usize];
            line3[7] = b'r';
            line3[8] = b'=';
            line3[9] = HEX[((r >> 12) & 0xF) as usize];
            line3[10] = HEX[((r >> 8) & 0xF) as usize];
            line3[11] = HEX[((r >> 4) & 0xF) as usize];
            line3[12] = HEX[(r & 0xF) as usize];

            let mut line4 = [b' '; 16];
            line4[0] = b'v';
            line4[1] = b'3';
            line4[2] = b'=';
            line4[3] = HEX[((v >> 12) & 0xF) as usize];
            line4[4] = HEX[((v >> 8) & 0xF) as usize];
            line4[5] = HEX[((v >> 4) & 0xF) as usize];
            line4[6] = HEX[(v & 0xF) as usize];

            let d2 = ui::display();
            d2.clear();
            d2.draw_line(0, "Sign v3 len>cap");
            d2.draw_line(1, core::str::from_utf8(&line2).unwrap_or(""));
            d2.draw_line(2, core::str::from_utf8(&line3).unwrap_or(""));
            d2.draw_line(3, core::str::from_utf8(&line4).unwrap_or(""));
            d2.flush();
            return NscStatus::InvalidPointer as u32;
        }
        if payload_start + declared > total_len {
            ui::show_status("Sign", "v3 len > payload");
            return NscStatus::InvalidPointer as u32;
        }
        super::trailer::Trailer {
            start: payload_start,
            len: declared,
            next_cursor: payload_start + declared,
        }
    };
    cursor = cow_order.next_cursor;

    // 5a-bis. Optional Safe-multisig `approveHash` clear-sign trailer
    // (`safe_v1`). Layout: canonical(281) || u16 raw_data_len ||
    // raw_data. Absence is legal for non-Safe tx; the downgrade gate
    // below mandates presence whenever the inner calldata claims to
    // be `approveHash(bytes32)`.
    let safe_v1 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        SAFE_V1_PAYLOAD_MAX,
        "bad safe bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = safe_v1.next_cursor;

    // 5a-ter. Optional function-selector → text-signature trailer
    // (curated path). Layout is the same `[u16 BE len][bundle]` framing
    // every other trailer uses. The DB itself lives on the host
    // (companion app/stub) — only its 32-byte Merkle root rides in the
    // secure image. Absence is legal — when missing, the calldata may
    // still render typed args via the self-attest trailer below, or
    // fall back to blind-sign. Sits BEFORE the names section so the
    // names `[count:u8]` framing remains the very last thing in the
    // payload.
    let selector_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_SELECTOR_BUNDLE_LEN,
        "bad selector bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = selector_trailer.next_cursor;

    // 5a-quater. Optional self-attest selector trailer. Wire layout:
    // `selector(4) || text_sig_len(1) || text_sig(<=63)`. No Merkle
    // proof — this path is for selectors that the curated DB doesn't
    // cover. The firmware verifies internal consistency only:
    //   (a) `keccak256(text_sig)[..4] == bundle.selector`
    //   (b) `bundle.selector == calldata[..4]` (cross-check below)
    //   (c) the existing strict ABI walker rejects shape mismatch.
    // The trusted UI surfaces the weakened trust on its banner — see
    // `SelectorProvenance::SelfAttest`. Mutual exclusion with the
    // curated trailer is enforced below: companions must pick exactly
    // one path per call.
    let self_attest_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        MAX_SELF_ATTEST_BUNDLE_LEN,
        "bad self-attest",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = self_attest_trailer.next_cursor;

    // ── 5a-quinquies. Optional ERC-7730 clear-signing descriptor ───
    //
    // Wire layout: `[u16 BE len][payload]`. The payload is either one exact
    // legacy bundle or the capability-gated versioned proof-set envelope. A
    // proof set retains ordered, zero-copy raw handles for the outer and
    // optional child legacy bundles; the outer remains the top-level
    // descriptor while an authenticated enrolled child may render in scope.
    //
    // Verified inline against the firmware-pinned
    // `ERC7730_DESCRIPTORS_ROOT` (Phase 2 emits this root from the
    // host pipeline). Cross-checked against `(chain_id, to_address)`
    // so a hostile companion cannot pair a USDC descriptor with a
    // transfer to an attacker-controlled contract — see invariant
    // discussion in `pqsigner_erc7730::binding::cross_check_contract`.
    //
    // Sits BEFORE the names section so the names `[count:u8]` framing
    // remains the very last thing in the payload.
    //
    // NOT mutually exclusive with the selector / self-attest trailers
    // — Phase 4's renderer picks the best one per priority ladder.
    let erc7730_trailer = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        ERC7730_MAX_TRAILER_LEN,
        "bad erc7730",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = erc7730_trailer.next_cursor;

    // Parse and retain the exact rooted proof set here, but do not grant it
    // display authority yet. The complete contract context (trusted sender,
    // display nonce/value, and signed calldata) exists only after section 6.
    // Section 6a reparses the entire payload twice and re-derives the nested
    // binding around a randomized gap before the set can reach the renderer.
    // A present malformed trailer hard-refuses below; only true absence maps
    // to `None`, where the independently pinned known-call filter still
    // prevents omission downgrade for every registry-known tuple.
    let erc7730_candidate: Option<crate::tx::erc7730::VerifiedProofSet<'_>> = if erc7730_trailer
        .len
        > 0
    {
        let bytes = &snap[erc7730_trailer.start..erc7730_trailer.start + erc7730_trailer.len];
        match crate::tx::erc7730::verify_erc7730_proof_set(
            bytes,
            &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
        ) {
            Ok(v) => Some(v),
            Err(_e) => {
                ui::show_status("Sign", "7730 bundle fail");
                return NscStatus::InvalidPointer as u32;
            }
        }
    } else {
        None
    };

    // ── 5b. Optional address-name bundles ─────────────────────────
    //
    // Zero or more merkle-verified (chain_id, address, name) bundles.
    // The companion emits up to MAX_NAME_BUNDLES entries, one per
    // address it found in its local names DB across the tx's display
    // surface (tx.to, ERC-20 recipient/spender, paymaster, ...). The
    // secure world verifies each bundle against NAMES_DB_ROOT and
    // collects the survivors into a NameResolver for the display
    // layer.
    //
    // Absence of this trailer is legal — legacy callers that never
    // upgrade their NS code still produce a zero-trailer sign request.
    // Framing differs from the three trailers above (1-byte count +
    // variable-count 2-byte-len entries), so it parses inline.
    let names_count = if cursor < total_len {
        snap[cursor] as usize
    } else {
        0
    };
    let names_start;
    if names_count > 0 {
        cursor += 1;
        names_start = cursor;
        if names_count > MAX_NAME_BUNDLES {
            ui::show_status("Sign", "bad names count");
            return NscStatus::InvalidPointer as u32;
        }
        for _ in 0..names_count {
            if cursor + 2 > total_len {
                ui::show_status("Sign", "bad names frame");
                return NscStatus::InvalidPointer as u32;
            }
            let l = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
            cursor += 2;
            if l > MAX_NAME_BUNDLE_LEN || cursor + l > total_len {
                ui::show_status("Sign", "bad names len");
                return NscStatus::InvalidPointer as u32;
            }
            cursor += l;
        }
    } else {
        names_start = cursor;
    }

    if cursor != total_len {
        ui::show_status("Sign", "trailing bytes");
        return NscStatus::InvalidPointer as u32;
    }

    // Bind the untrusted wire sender to the deterministic CREATE2 address for
    // this mnemonic + account index before any sender-dependent verifier or
    // trusted-display confirmation. Downstream code intentionally uses ONLY
    // the published address, never `companion_sender`; even a skipped reject
    // branch therefore cannot produce a signature for an arbitrary wallet.
    let mut sender_binding_slot = super::cmd_get_wallet_address::SenderBinding::fail_closed();
    let mut sender_binding_cfi = crate::fi::CfiCounter::new();
    // Materialize the fail-closed slot even under LTO. If the following `bl`
    // is instruction-skipped, only the materialized fail-closed slot remains.
    // SAFETY: unique local slot; volatile store is deliberately observable.
    unsafe {
        core::ptr::write_volatile(
            core::ptr::addr_of_mut!(sender_binding_slot),
            super::cmd_get_wallet_address::SenderBinding::fail_closed(),
        );
        super::cmd_get_wallet_address::bind_userop_sender(
            account_index,
            &companion_sender,
            &mut sender_binding_slot,
            &mut sender_binding_cfi,
        );
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // Read the derived sender twice. A skipped/corrupted aggregate word-load
    // must be detected before the local copy can reach any verifier or hash.
    // SAFETY: the slot is initialized before the call and remains live here.
    let sender =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.sender)) };
    crate::fi::wait_random();
    // SAFETY: same as the first sender read.
    let sender_check =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.sender)) };
    let sender_reads_agree = sender.ct_eq(&sender_check).unwrap_u8();
    // SAFETY: the scalar fields were initialized before the call and the
    // helper publishes them with volatile stores.
    let binding_verdict =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.verdict)) };
    // SAFETY: same initialized caller-owned slot.
    let binding_error =
        unsafe { core::ptr::read_volatile(core::ptr::addr_of!(sender_binding_slot.error)) };
    if sender_binding_cfi
        .check_into_sentinel(super::cmd_get_wallet_address::SENDER_BIND_CFI_EXPECTED)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(sender_reads_agree) == 1)
        != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if binding_verdict != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "wrong wallet");
        return binding_error as u32;
    }

    // ── 6. Build display-time Eip1559Tx shim ───────────────────────
    let display_nonce = u64::from_be_bytes([
        type2_nonce[24],
        type2_nonce[25],
        type2_nonce[26],
        type2_nonce[27],
        type2_nonce[28],
        type2_nonce[29],
        type2_nonce[30],
        type2_nonce[31],
    ]);
    let display_max_fee = U256(max_fee_per_gas);
    let display_max_prio = U256(max_priority_fee_per_gas);
    let call_gas_u128 = u128_saturating_from_u256(&call_gas_limit);
    let ver_gas_u128 = u128_saturating_from_u256(&verification_gas_limit);
    let pre_ver_u128 = u128_saturating_from_u256(&pre_verification_gas);
    let display_gas_limit: u64 = ver_gas_u128
        .saturating_add(call_gas_u128)
        .saturating_add(pre_ver_u128)
        .min(u64::MAX as u128) as u64;

    let tx_for_display = Eip1559Tx {
        chain_id,
        nonce: display_nonce,
        max_priority_fee_per_gas: display_max_prio,
        max_fee_per_gas: display_max_fee,
        gas_limit: display_gas_limit,
        to: Some(to_address),
        value: U256(value),
        data_len,
        access_list_count: 0,
        signing_hash: [0u8; 32],
        userop_fields: Some(UserOpDisplayFields {
            // This display object describes the Type-2 transaction the user
            // is authorizing.  During slot rotation the companion-supplied
            // base nonce belongs to the preceding Type-1 registration, while
            // the transaction is signed at base+1.
            nonce: U256(type2_nonce),
            call_gas_limit: U256(call_gas_limit),
            verification_gas_limit: U256(verification_gas_limit),
            pre_verification_gas: U256(pre_verification_gas),
        }),
    };

    // ── 6a. FI-bind the complete ERC-7730 proof set and nested call ──
    //
    // The initial pure derivation establishes the exact binding the renderer
    // must reproduce. The non-inlined proof then reparses the complete raw
    // legacy/wrapper payload twice, requires the exact same verified set, and
    // independently re-derives that binding around a randomized gap. Both the
    // caller-owned volatile verdict and CFI transcript are consumed twice
    // before the set gains display authority. Any present invalid evidence is
    // a hard refusal; it cannot be erased into a weaker fallback route.
    let (erc7730_verified, erc7730_nested_binding) = if let Some(set) = erc7730_candidate.as_ref() {
        let expected_nested = match crate::tx::erc7730::derive_nested_call(
            &tx_for_display,
            inner_data,
            set,
            &sender,
        ) {
            Ok(binding) => binding,
            Err(_) => {
                ui::show_status("Sign", "7730 binding fail");
                return NscStatus::InvalidPointer as u32;
            }
        };

        let mut bind_verdict_slot = 0u32;
        // SAFETY: unique initialized local; volatile so LTO cannot erase the
        // fail state if the proof call is fault-skipped.
        unsafe {
            core::ptr::write_volatile(&mut bind_verdict_slot, crate::fi::FAIL_SENTINEL);
        }
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        let mut bind_cfi = crate::fi::CfiCounter::new();
        crate::tx::erc7730::prove_contract_proof_set_binding(
            set,
            &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
            &tx_for_display,
            inner_data,
            &sender,
            expected_nested.as_ref(),
            &mut bind_verdict_slot,
            &mut bind_cfi,
        );
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);

        // Gate A consumes independently materialized verdict and CFI proofs.
        // SAFETY: local remains live and the callee borrow ended.
        let bind_verdict_a = unsafe { core::ptr::read_volatile(&bind_verdict_slot) };
        let bind_cfi_verdict_a =
            bind_cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED);
        let bind_all_ok_a = bind_verdict_a == crate::fi::OK_SENTINEL
            && bind_cfi_verdict_a == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        let bind_gate_a =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_all_ok_a));
        crate::fi::scrub_sentinel_register();
        if bind_gate_a != crate::fi::OK_SENTINEL {
            ui::show_status("Sign", "7730 binding fail");
            return NscStatus::InternalError as u32;
        }

        crate::fi::wait_random();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: same live local, independently re-read after the randomized
        // gap instead of trusting gate A's cache.
        let bind_verdict_b = unsafe { core::ptr::read_volatile(&bind_verdict_slot) };
        let bind_cfi_verdict_b =
            bind_cfi.check_into_sentinel(crate::tx::erc7730::CFI_CONTRACT_BIND_EXPECTED);
        let bind_all_ok_b = bind_verdict_b == crate::fi::OK_SENTINEL
            && bind_cfi_verdict_b == crate::fi::OK_SENTINEL;
        crate::fi::scrub_sentinel_register();
        let bind_gate_b =
            crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_all_ok_b));
        crate::fi::scrub_sentinel_register();
        if bind_gate_b != crate::fi::OK_SENTINEL {
            ui::show_status("Sign", "7730 binding fail");
            return NscStatus::InternalError as u32;
        }

        #[cfg(feature = "debug-log")]
        {
            let c = &set.outer.descriptor.ir.contract;
            secure_log!(
                "[ERC-7730] matched: chain={} contract=0x{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x} ir_len={} nested={}",
                set.outer.descriptor.ir.chain_id,
                c[0], c[1], c[2], c[3],
                c[16], c[17], c[18], c[19],
                set.outer.descriptor.ir.raw.len(),
                expected_nested.is_some(),
            );
        }
        (Some(*set), expected_nested)
    } else {
        (None, None)
    };

    // ── 7. Verify optional trailers ────────────────────────────────

    // 7a. ERC-20 bundle metadata attribution is resolved in §7c-bis-erc20
    // below — AFTER the Safe-context verifications (`safe_v1_verified` /
    // `safe_exec_verified`). The acceptance gate admits a bundle whose
    // token sits inside a Safe-flow multiSend record, and those disjuncts
    // MUST require the corresponding Safe context to have actually verified
    // (not just inspect raw companion trailer bytes — audit 2026-06-28).
    // Computing it here would force the disjuncts to run before the Safe
    // verdicts exist.

    // 7b. Reserved compatibility slot. Aave clear-signing flows through
    // the native ERC-7730 verifier (§7c-quinquies / `erc7730_verified`).
    // The wire slot is parsed as a zero-length field above (`reserved_v1`).

    // 7c. `safe_v1` Safe-multisig `approveHash` cross-check —
    // 8-step native pipeline (length → selector → calldata len →
    // chain pin → safe-address pin → operation gate → data_hash bind
    // → safeTxHash bind). The approveHash digest is in the calldata
    // itself, so the firmware recomputes both
    // keccak chains and byte-compares.
    //
    // Runs BEFORE the v3 CoW verify (7c-ter): a Safe-wrapped CoW
    // presign anchors the v3 binding to the SafeTx's inner raw_data and
    // to the Safe's address, so the CoW verify needs the verified Safe
    // context first. Nothing in between reads `cow_order_verified`.
    let safe_v1_verified = if safe_v1.len > 0 {
        let v = crate::tx::eip712::safe::verify_and_bind_trailer(
            &snap[safe_v1.start..safe_v1.start + safe_v1.len],
            inner_data,
            chain_id,
            &to_address,
        );
        // FI-hardened verdict (audit L-10): mirror the batch dispatcher —
        // double-evaluate the verify result through a Hamming-distant
        // sentinel with `wait_random` between, so a single glitch that
        // flips the bind verdict also has to defeat the sentinel compare.
        // Fail closed to `None`.
        let ok = v.is_some();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
            != crate::fi::OK_SENTINEL
        {
            None
        } else {
            v
        }
    } else {
        None
    };

    // 7c-bis. Safe-multisig `execTransaction(...)` decode — no trailer
    // needed; the SafeTx fields are encoded directly into the function
    // arguments, so the firmware decodes them straight out of
    // `inner_data` once the selector matches. Companion of the
    // approveHash path above for the case where the wallet is the
    // EOA-equivalent actually triggering execution (carrying co-signers'
    // approvals in the `signatures` argument).
    // Reserve the selector under a caller-owned, fail-initialized FI/CFI
    // receipt. The strict verifier runs independently of that classification;
    // two resolution gates accept only {claimed + verified} or {unclaimed +
    // unverified}. A stuck-at-false classifier therefore cannot reinterpret a
    // malformed or disallowed Safe call as an ordinary blind-sign route.
    let mut safe_exec_claim = crate::tx::eip712::safe::ExecClaimReceipt::fail_closed();
    let mut safe_exec_claim_cfi = crate::fi::CfiCounter::new();
    // SAFETY: unique initialized local; volatile materialization makes a
    // skipped non-inlined proof call leave an unusable receipt.
    unsafe {
        core::ptr::write_volatile(
            &mut safe_exec_claim,
            crate::tx::eip712::safe::ExecClaimReceipt::fail_closed(),
        )
    };
    crate::tx::eip712::safe::prove_exec_transaction_claim(
        inner_data,
        &mut safe_exec_claim,
        &mut safe_exec_claim_cfi,
    );
    let mut safe_exec_verified: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
    let mut safe_exec_verified_check: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
    let mut safe_exec_verify_cfi_a = crate::fi::CfiCounter::new();
    let mut safe_exec_verify_cfi_b = crate::fi::CfiCounter::new();
    // SAFETY: distinct initialized caller-owned outputs. A skipped verifier
    // call leaves `None`, and its independent CFI counter remains short.
    unsafe {
        core::ptr::write_volatile(&mut safe_exec_verified, None);
        core::ptr::write_volatile(&mut safe_exec_verified_check, None);
    }
    crate::tx::eip712::safe::verify_and_bind_exec_into(
        inner_data,
        chain_id,
        &to_address,
        &mut safe_exec_verified,
        &mut safe_exec_verify_cfi_a,
    );
    crate::fi::wait_random();
    crate::tx::eip712::safe::verify_and_bind_exec_into(
        inner_data,
        chain_id,
        &to_address,
        &mut safe_exec_verified_check,
        &mut safe_exec_verify_cfi_b,
    );

    crate::fi::scrub_sentinel_register();
    let safe_claim_cfi_verdict_a =
        safe_exec_claim_cfi.check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_a_cfi_verdict_a = safe_exec_verify_cfi_a
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_b_cfi_verdict_a = safe_exec_verify_cfi_b
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_resolution_verdict_a = crate::tx::eip712::safe::exec_claim_resolution_proof(
        &safe_exec_claim,
        safe_exec_verified.as_ref(),
        safe_exec_verified_check.as_ref(),
    );
    if safe_claim_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_verify_a_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_verify_b_cfi_verdict_a != crate::fi::OK_SENTINEL
        || safe_resolution_verdict_a != crate::fi::OK_SENTINEL
    {
        ui::show_status("Safe sign", "exec parse fail");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    crate::fi::wait_random();
    let safe_claim_cfi_verdict_b =
        safe_exec_claim_cfi.check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_a_cfi_verdict_b = safe_exec_verify_cfi_a
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_verify_b_cfi_verdict_b = safe_exec_verify_cfi_b
        .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let safe_resolution_verdict_b = crate::tx::eip712::safe::exec_claim_resolution_proof(
        &safe_exec_claim,
        safe_exec_verified.as_ref(),
        safe_exec_verified_check.as_ref(),
    );
    if safe_claim_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_verify_a_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_verify_b_cfi_verdict_b != crate::fi::OK_SENTINEL
        || safe_resolution_verdict_b != crate::fi::OK_SENTINEL
    {
        ui::show_status("Safe sign", "exec parse fail");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();

    // 7c-bis-erc20. ERC-20 bundle → authenticated display metadata
    // (deferred from §7a).
    //
    // This layer proves only the Merkle leaf and chain. Surface-specific
    // attribution happens after dispatch against signed facts: outer target
    // for a direct ERC-20 call, descriptor-resolved tokenPath for ERC-7730,
    // or a verified Safe direct/MultiSend target. Keeping that decision out of
    // raw trailer routing both closes RT-ERC20-01 and preserves legitimate
    // metadata for direct protocol calls such as `deposit(asset, amount)`.
    let chain_verified_meta: Option<Erc20Metadata<'_>> = if erc20.len > 0 {
        let bundle_slice = &snap[erc20.start..erc20.start + erc20.len];
        match verify_erc20_bundle(bundle_slice) {
            Some(meta) if meta.chain_id == chain_id => Some(meta),
            None => None,
            Some(_) => None,
        }
    } else {
        None
    };

    // 7c-ter. Native CoW EIP-712 pipeline: canonical decode, chain/shape
    // checks, orderUid cross-check, and optional Merkle-verified token
    // metadata for each leg. Returns
    // `None` on any failure; no partial-success fallback. See
    // `tx::eip712::cowswap::verify_and_bind_trailer` for specifics.
    //
    // The binding target depends on the Safe context resolved above:
    // for a direct order the trailer binds to `inner_data` with
    // `uid.owner == sender`; for a Safe-wrapped presign it binds to the
    // SafeTx's inner raw_data with `uid.owner == the Safe` (GPv2's
    // settlement sees the Safe as `msg.sender` at execution). One call
    // site, one resolver — see `safe::cow_binding` for the fail-closed
    // argument.
    let cow_bind = crate::tx::eip712::safe::resolve_cow_binding(
        inner_data,
        &sender,
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
    );
    let cow_order_verified = if cow_order.len > 0 {
        let v = crate::tx::eip712::cowswap::verify_and_bind_trailer(
            &snap[cow_order.start..cow_order.start + cow_order.len],
            cow_bind.calldata,
            chain_id,
            &cow_bind.owner,
        );
        // FI-hardened verdict: same sentinel double-eval as the safe_v1
        // bind above and the batch dispatcher's COW_ORDER arm (this call
        // site historically lacked the envelope — closed for parity).
        // Fail closed to `None`.
        let ok = v.is_some();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
            != crate::fi::OK_SENTINEL
        {
            None
        } else {
            v
        }
    } else {
        None
    };

    // 7c-quater. Selector → text-signature bundle.
    //
    // Two parallel paths, mutually exclusive at the wire level:
    //
    //   * Curated (Phase-1+2): Merkle-verified bundle pulled from the
    //     host-side DB whose root is baked into the firmware image.
    //     One canonical text_sig per selector — adversarial 4byte
    //     collisions are dropped at curation time.
    //   * Self-attest (Phase-2b): companion-supplied (selector, text_sig)
    //     pair. Firmware verifies `keccak256(text_sig)[..4] == selector`
    //     and the existing ABI walker checks shape match. A patient
    //     attacker can find a same-shape colliding text_sig with ~2³²
    //     keccak ops, so the trusted UI uses a louder banner for this
    //     path (see SelectorProvenance::SelfAttest).
    //
    // Both paths run the cross-check `bundle.selector == calldata[..4]`
    // after parsing, so a host that signs a perfectly-valid bundle for
    // selector A while supplying calldata starting with selector B
    // cannot mislead the trusted UI either way.
    //
    // If both trailers are present, we refuse the request. A confused
    // companion sending both is a bug; the alternative ("silently
    // prefer curated") would give an attacker plausible deniability if
    // the user later complains the wrong banner showed.
    if selector_trailer.len > 0 && self_attest_trailer.len > 0 {
        ui::show_status("Sign", "both selector trailers");
        return NscStatus::InvalidPointer as u32;
    }

    let selector_verified: Option<SelectorMeta<'_>> = if selector_trailer.len > 0 {
        let bundle_slice =
            &snap[selector_trailer.start..selector_trailer.start + selector_trailer.len];
        match verify_selector_bundle(bundle_slice) {
            Some(meta) => {
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    Some(meta)
                } else {
                    None
                }
            }
            None => None,
        }
    } else if self_attest_trailer.len > 0 {
        let bundle_slice =
            &snap[self_attest_trailer.start..self_attest_trailer.start + self_attest_trailer.len];
        match parse_self_attest_bundle(bundle_slice) {
            Some(meta) => {
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    Some(meta)
                } else {
                    None
                }
            }
            None => None,
        }
    } else {
        None
    };

    // 7d. Downgrade-mitigation gate.
    //
    // The v1 clear-sign flow only binds the setPreSignature calldata
    // to a static "Pre-sign CowSwap order" string. That's safe — but
    // if an attacker strips the v3 trailer from a CoW UserOp, the
    // user would confirm that static string instead of the rich
    // 8-page v3 display and end up pre-signing an orderUid they never
    // saw the contents of. So: for CoW setPreSignature specifically,
    // require v3 verification. No fallback.
    let cow_selector = inner_data.len() >= 4 && &inner_data[..4] == SET_PRE_SIGNATURE_SELECTOR;
    let cow_target = to_address == GPV2_SETTLEMENT_ADDRESS;
    if cow_selector && cow_target && cow_order_verified.is_none() {
        ui::show_status("CoW sign", "v3 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Safe-wrapped twin of the gate above. `via_safe` is true exactly
    // when a *verified* Safe context's inner call claims setPreSignature
    // on the GPv2 settlement (see `safe::cow_binding`) — in that case a
    // verified v3 trailer is mandatory too. Without this gate a hostile
    // companion could strip the trailer and the order would fall to the
    // generic blind-sign inner page; a user habituated to the rich CoW
    // display might confirm it anyway. Same failure mode covers
    // malformed presign calldata and `signed == false` (revocation is
    // unsupported, exactly like the direct path).
    if cow_bind.via_safe && cow_order_verified.is_none() {
        ui::show_status("CoW sign", "v3 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Direct-path CoW target gate (audit 2026-06-26 — direct-path target
    // unshown). A verified DIRECT (non-Safe-wrapped) v3 order renders via
    // `render_cowswap_pages`, which shows the order but NOT the UserOp call
    // target. The signed `executeWithOffchainCount(...)` forwards
    // `to_address.call{value}(data)` to an arbitrary target, so unless it IS
    // the GPv2 settlement singleton the user would confirm a trusted CoW
    // screen while signing a call (and any `value`) to an attacker-chosen,
    // never-displayed address. The Safe-wrapped path already pins the inner
    // target via `safe_inner_is_cow_presign`; this is its direct-arm twin.
    // A legitimate direct presign always targets GPv2, so this never refuses
    // a well-formed CoW UserOp.
    if !crate::tx::eip712::safe::direct_cow_target_ok(
        cow_order_verified.is_some(),
        cow_bind.via_safe,
        &to_address,
    ) {
        ui::show_status("CoW sign", "bad target");
        return NscStatus::InvalidPointer as u32;
    }

    // Symmetric Safe `approveHash` gate. If the inner calldata claims
    // to be `approveHash(bytes32)`, a `safe_v1` trailer is mandatory.
    // Without this gate a hostile NS could strip the trailer and
    // coerce the user into blind-signing the bytes32 hash with no
    // visibility into what SafeTx it commits to.
    //
    // Keyed on the SELECTOR ALONE (like the CoW `setPreSignature` gate
    // above), NOT an exact calldata length: `Safe.approveHash(bytes32)`
    // ignores trailing calldata on-chain, so the old `len == 36` test was
    // a parser differential — `selector ‖ hash ‖ 0x00` (37 B) skipped the
    // gate AND failed `safe_v1` verify, falling to a generic blind-sign of
    // an approveHash that pre-approves an arbitrary SafeTx (audit
    // 2026-06-28). `is_approve_hash_claim` closes the differential.
    if crate::tx::eip712::safe::is_approve_hash_claim(inner_data) && safe_v1_verified.is_none() {
        ui::show_status("Safe sign", "safe_v1 required");
        return NscStatus::InvalidPointer as u32;
    }

    // MultiSend gate. When a verified Safe context's inner call claims
    // an allowlisted MultiSendCallOnly DELEGATECALL, the payload must
    // pass every hard rule (strict framing, per-record operation == 0,
    // record cap, at most one presign claim) AND fit the trusted-
    // display page budget — a record the user never sees is exactly
    // the attack class this flow closes, so overflow refuses instead
    // of truncating. One shared decision (`multisend_sign_gate`) for
    // this handler and the batch handler. Reserved pages here: the
    // dispatcher's native-value page when the outer UserOp carries
    // ETH, plus the two ERC-8213 fingerprint pages appended below.
    {
        // Native-value page (when outer value != 0) + mandatory full signer
        // and target pages + worst-case non-zero nonce-lane page + the
        // mandatory UserOp gas-triple page (F10) + 2 ERC-8213 fingerprint pages
        // + 2 gas/fee pages (the dispatcher splices the gas pages for the Safe
        // surface — audit 2026-06-19) + the paymaster page when paymasterAndData
        // is non-empty (audit 2026-06-27).
        let reserved = usize::from(value.iter().any(|&b| b != 0))
            + usize::from(paymaster_and_data_hash != SHA256_EMPTY)
            + usize::from(include_init_code) * crate::tx::display::DEPLOYMENT_MODE_PAGES
            + crate::tx::display::SIGNER_IDENTITY_PAGES
            + crate::tx::display::TARGET_IDENTITY_PAGES
            + crate::tx::display::NONZERO_NONCE_LANE_PAGES
            + crate::tx::display::USEROP_GAS_PAGES
            + 2
            + 2;
        match crate::tx::display::multisend_sign_gate(
            safe_v1_verified.as_ref(),
            safe_exec_verified.as_ref(),
            cow_order_verified.as_ref(),
            reserved,
        ) {
            crate::tx::display::MultisendGate::Reject(reason) => {
                ui::show_status("Safe sign", reason);
                return NscStatus::InvalidPointer as u32;
            }
            crate::tx::display::MultisendGate::NotMultiSend
            | crate::tx::display::MultisendGate::Ok => {}
        }
    }

    // 7d-bis. The opt-in forced-blind branch is terminal and exists only for
    // an exact steady-state Type-2 request with a clean, explicit empty
    // ERC-7730 slot. Classification runs only after every existing
    // Safe/CoW/protected-call gate above has completed. A non-candidate resumes
    // the ordinary renderer below unchanged; no terminal failure may downgrade
    // into that path.
    #[cfg(feature = "erc7730-forced-blind")]
    {
        let request = super::cmd_sign_userop_forced::ForcedRequest {
            wire: &snap[..total_len],
            account_index,
            slot_index,
            sender,
            chain_id,
            nonce: type2_nonce,
            call_gas_limit,
            verification_gas_limit,
            pre_verification_gas,
            max_fee_per_gas,
            max_priority_fee_per_gas,
            target: to_address,
            value,
            tx: &tx_for_display,
            calldata: inner_data,
        };
        match super::cmd_sign_userop_forced::classify(&request) {
            super::cmd_sign_userop_forced::ForcedRoute::ContinueOrdinary => {}
            super::cmd_sign_userop_forced::ForcedRoute::Candidate(eligibility) => {
                return unsafe {
                    super::cmd_sign_userop_forced::run(args, eligibility, request)
                };
            }
            super::cmd_sign_userop_forced::ForcedRoute::Fatal => {
                ui::show_status("Sign refused", "forced classify");
                return NscStatus::InternalError as u32;
            }
        }
    }

    // 7e. Address-name bundles.
    //
    // Every bundle crosses the Merkle gate against NAMES_DB_ROOT.
    // Bundles that don't verify are silently dropped — the affected
    // address just renders as 40-hex, which is always safe. A bundle
    // IS verified against the DB but the (chain_id, address) pair in
    // the verified metadata is NOT necessarily the tx chain_id or
    // tx.to; the resolver matches those against the tx-derived values
    // at display time.
    let mut resolver = NameResolver::new();
    {
        let mut walk = names_start;
        for _ in 0..names_count {
            let l = u16::from_be_bytes([snap[walk], snap[walk + 1]]) as usize;
            walk += 2;
            let bundle_slice = &snap[walk..walk + l];
            if let Some(meta) = verify_name_bundle(bundle_slice) {
                resolver.push(meta);
            }
            walk += l;
        }
    }

    // ── 8. Render + confirm ────────────────────────────────────────
    //
    // The priority ladder (CoW → Safe → ERC-7730 → known-call refusal →
    // value/ERC-20/typed/blind) lives in `display::pick_sign_pages`.
    //
    // Slot rotation is its own affirmative-consent step: when
    // `FLAG_REGISTER_SLOT` is set the firmware also emits a Type 1
    // `addOwnerBytes` UserOp that consumes one of the wallet's
    // `MAX_BOOTSTRAP_USES` budget items on chain. Without a separate
    // confirm a hostile companion could silently set the flag on every
    // routine UserOp and drain the bootstrap reserve at twice the rate
    // the user thinks they're authorising. The Type 1 sig is gated by
    // the on-chain monotonic cap regardless; this gate just makes the
    // cost visible to the user.
    if register_slot {
        let mut rotate_pages = crate::tx::display::build_slot_rotation_pages(slot_index);
        let signer_pages_before = rotate_pages.len;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_from_page(
            &mut rotate_pages,
            account_index,
            &sender,
            &mut signer_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let signer_cfi_verdict =
            signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let signer_page_verdict = crate::tx::display::from_page_proof(
            &rotate_pages,
            signer_pages_before,
            account_index,
            &sender,
        );
        if signer_cfi_verdict != crate::fi::OK_SENTINEL
            || signer_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        let nonce_lane_pages_before = rotate_pages.len;
        let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_nonce_lane_page(
            &mut rotate_pages,
            &nonce,
            &mut nonce_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let nonce_lane_cfi_verdict =
            nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let nonce_lane_page_verdict = crate::tx::display::nonce_lane_page_proof(
            &rotate_pages,
            nonce_lane_pages_before,
            &nonce,
        );
        if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        // The rotation consent contributes a Type-1 signature over the same
        // UserOperation gas words. Keep its confirmation boundary subject to
        // the same handler-owned exact gas-page invariant as the Type-2
        // confirmation below and as every batch confirmation.
        let gas_lane_pages_before = rotate_pages.len;
        let mut gas_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_userop_gas_page(
            &mut rotate_pages,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
            &mut gas_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Sign refused", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof(
            &rotate_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
            &rotate_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_final_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_final_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Sign refused", "gas conflict");
            return NscStatus::InternalError as u32;
        }
        let (cr, cr_verdict) = confirm_checked(rotate_pages.as_slice());
        match cr {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
        // FI belt (UI1 / work-todo #12c): reach signing ONLY on the affirmative
        // sentinel born at confirm's accept branch. A skipped reject-arm return
        // is caught here; fail closed (zeroize + reject).
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }
    // `include_init_code` changes the released response, the Type-2 digest,
    // and whether the bootstrap key signs a factory authorization. Bind that
    // mode to the exact public deployment context before the cancellable main
    // confirmation; the receipt is published only from its affirmative arm.
    let deployment_context = crate::tx::display::DeploymentConfirmContext::new(
        include_init_code,
        chain_id,
        account_index,
        slot_index,
        sender,
        type2_nonce,
        PQ_SMART_WALLET_FACTORY,
    );
    let mut deployment_confirm_receipt = crate::tx::display::DeploymentConfirmReceipt::new();
    deployment_confirm_receipt.fail_initialize();
    let legacy_fee_pages_required = crate::tx::display::legacy_fee_pages_required(
        cow_order_verified.is_some(),
        safe_v1_verified.is_some(),
        safe_exec_verified.is_some(),
    );
    let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();
    dispatch_page_proofs.fail_initialize();
    let mut pages = match pick_sign_pages_with_erc7730_evidence(
        &tx_for_display,
        inner_data,
        &sender,
        cow_order_verified.as_ref(),
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
        erc7730_verified.as_ref(),
        erc7730_nested_binding.as_ref(),
        chain_verified_meta.as_ref(),
        selector_verified.as_ref(),
        &resolver,
        &mut dispatch_page_proofs,
    ) {
        Ok(p) => p,
        // Fail closed for any mandatory render failure: native-value/gas page
        // budget, Safe accounting, a verified ERC-7730 descriptor that cannot
        // render exactly, or a firmware-known call whose proof was omitted /
        // malformed / mis-bound. None may downgrade to a weaker confirmation.
        Err(()) => {
            ui::show_status("Sign refused", "render refused");
            return NscStatus::InternalError as u32;
        }
    };
    // Paymaster WYSIWYS gate (audit 2026-06-27). `paymaster_and_data_hash` is
    // folded into the signed sphincs digest below, so the signature commits
    // to whatever paymaster the companion chose — but no renderer surfaces
    // it. A companion can route an otherwise-benign UserOp through a
    // token-paymaster the user previously approved, draining ERC-20 as "gas"
    // behind the confirm (the "Worst-case ETH" page actively misdirects). The
    // firmware only has sha256(paymasterAndData) so it cannot show *which*
    // paymaster, but it appends a loud "! PAYMASTER SET" page whenever one is
    // present. FI-hardened (sentinel skip-on-empty) and fails CLOSED on a
    // full buffer — refuse rather than sign a sponsor the user never saw.
    let paymaster_pages_before = pages.len;
    let mut paymaster_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_paymaster_page(
        &mut pages,
        &paymaster_and_data_hash,
        &mut paymaster_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "paymaster unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let paymaster_cfi_verdict =
        paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let paymaster_page_verdict = crate::tx::display::paymaster_page_proof(
        &pages,
        paymaster_pages_before,
        &paymaster_and_data_hash,
    );
    if paymaster_cfi_verdict != crate::fi::OK_SENTINEL
        || paymaster_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "paymaster unshown");
        return NscStatus::InternalError as u32;
    }
    // Account/signer identity is mandatory on every UserOp confirmation.
    // `sender` is the mnemonic-derived, independently cross-checked address,
    // never the companion field. Append-only publication preserves every
    // renderer/paymaster page that has already been built and proved.
    let signer_pages_before = pages.len;
    let mut signer_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_from_page(&mut pages, account_index, &sender, &mut signer_cfi)
        .is_err()
    {
        ui::show_status("Sign refused", "signer unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let signer_cfi_verdict =
        signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let signer_page_verdict =
        crate::tx::display::from_page_proof(&pages, signer_pages_before, account_index, &sender);
    if signer_cfi_verdict != crate::fi::OK_SENTINEL || signer_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "signer unshown");
        return NscStatus::InternalError as u32;
    }
    // The exact outer contract target is mandatory even when the semantic
    // renderer (notably ERC-7730) does not show it itself. Append after the
    // proven signer page and independently prove the full page materialized.
    let target_pages_before = pages.len;
    let mut target_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_target_page(&mut pages, &to_address, &mut target_cfi).is_err() {
        ui::show_status("Sign refused", "target unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let target_cfi_verdict =
        target_cfi.check_into_sentinel(crate::tx::display::TARGET_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let target_page_verdict =
        crate::tx::display::target_page_proof(&pages, target_pages_before, &to_address);
    if target_cfi_verdict != crate::fi::OK_SENTINEL || target_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "target unshown");
        return NscStatus::InternalError as u32;
    }
    // EntryPoint v0.6's high 192 nonce bits select an independently
    // executable lane. Lane zero stays compact; every non-zero lane is shown
    // in full and independently FI-proved so two lane-distinct UserOps cannot
    // hide behind the same low-64 `Nonce:` row.
    let nonce_lane_pages_before = pages.len;
    let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_nonce_lane_page(&mut pages, &type2_nonce, &mut nonce_lane_cfi)
        .is_err()
    {
        ui::show_status("Sign refused", "lane unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let nonce_lane_cfi_verdict =
        nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let nonce_lane_page_verdict =
        crate::tx::display::nonce_lane_page_proof(&pages, nonce_lane_pages_before, &type2_nonce);
    if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
        || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "lane unshown");
        return NscStatus::InternalError as u32;
    }
    // EntryPoint v0.6 commits callGasLimit, verificationGasLimit, and
    // preVerificationGas as three independent, ordered 256-bit words. The
    // generic Safe/CoW envelope only showed their saturated u64 aggregate, so a
    // gas-split permutation with the same sum rendered identically (F10). Bind
    // all three exact values on their own page, independently FI-proved, so no
    // permutation can hide behind the aggregate. The handler is the sole page
    // producer for every render path; the pre/post scans reject any duplicate
    // or conflicting gas-shaped page.
    let gas_lane_pages_before = pages.len;
    let mut gas_lane_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_userop_gas_page(
        &mut pages,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
        &mut gas_lane_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "gas unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let gas_lane_cfi_verdict =
        gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof(
        &pages,
        gas_lane_pages_before,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
    );
    if gas_lane_cfi_verdict != crate::fi::OK_SENTINEL
        || gas_lane_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "gas unshown");
        return NscStatus::InternalError as u32;
    }
    // ERC-8213 fingerprint — show the calldata digest as the last
    // page so a user can cross-check against `cast` / `viem`. Cap is
    // `MAX_PAGES` = 31; `multisend_sign_gate` reserves the full signer and
    // target pages, the conditional nonce-lane page, and these two fingerprint
    // pages. If the buffer is nonetheless full we
    // fail closed (F5): the fingerprint binds the displayed intent to the
    // signed calldata, so dropping it silently and signing anyway breaks that
    // binding.
    let calldata_fingerprint = pqsigner_tx_core::erc8213::calldata_digest(inner_data);
    let fingerprint_pages_before = pages.len;
    let fingerprint_kind = crate::tx::display::erc8213::Kind::CalldataDigest(calldata_fingerprint);
    let mut fingerprint_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::erc8213::append_fingerprint_page(
        &mut pages,
        fingerprint_kind,
        &mut fingerprint_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "fp unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let fingerprint_cfi_verdict =
        fingerprint_cfi.check_into_sentinel(crate::tx::display::erc8213::FINGERPRINT_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let fingerprint_page_verdict = crate::tx::display::erc8213::fingerprint_page_proof(
        &pages,
        fingerprint_pages_before,
        fingerprint_kind,
    );
    if fingerprint_cfi_verdict != crate::fi::OK_SENTINEL
        || fingerprint_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fp incomplete");
        return NscStatus::InternalError as u32;
    }
    // Deployment is a UserOp-level mode, so append its exact factory page
    // after the semantic calldata fingerprint and prove the completed-skip
    // path when initCode is absent. A full page budget refuses atomically.
    let deployment_pages_before = pages.len;
    let mut deployment_page_cfi = crate::fi::CfiCounter::new();
    if crate::tx::display::enforce_deployment_page(
        &mut pages,
        &deployment_context,
        &mut deployment_page_cfi,
    )
    .is_err()
    {
        ui::show_status("Sign refused", "deploy unshown");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let deployment_cfi_verdict = deployment_page_cfi
        .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let deployment_page_verdict = crate::tx::display::deployment_page_proof(
        &pages,
        deployment_pages_before,
        &deployment_context,
    );
    if deployment_cfi_verdict != crate::fi::OK_SENTINEL
        || deployment_page_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "deploy unshown");
        return NscStatus::InternalError as u32;
    }
    // Recompute the canonical gas page and scan the COMPLETE page set after
    // every later append. The insertion-completion proof above establishes the
    // one-page length transition; this final-boundary proof prevents a later
    // duplicate or gas-shaped conflict from reaching confirmation.
    crate::fi::scrub_sentinel_register();
    let gas_lane_final_cfi_verdict =
        gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
        &pages,
        gas_lane_pages_before,
        &call_gas_limit,
        &verification_gas_limit,
        &pre_verification_gas,
    );
    if gas_lane_final_cfi_verdict != crate::fi::OK_SENTINEL
        || gas_lane_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "gas conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let paymaster_final_cfi_verdict =
        paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let paymaster_final_verdict = crate::tx::display::paymaster_final_set_proof(
        &pages,
        paymaster_pages_before,
        &paymaster_and_data_hash,
    );
    if paymaster_final_cfi_verdict != crate::fi::OK_SENTINEL
        || paymaster_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "paymaster changed");
        return NscStatus::InternalError as u32;
    }
    // Recheck the dispatcher-owned native/legacy-fee suffix against the
    // complete transcript after paymaster, identity, nonce, exact-gas and
    // fingerprint appends. This also rechecks the caller-owned dispatcher CFI
    // receipts immediately before the pages cross the confirmation boundary.
    crate::fi::scrub_sentinel_register();
    let mut dispatch_final_verdict_slot = 0u32;
    // SAFETY: unique live local. The volatile FAIL state is load-bearing: if
    // the non-inlined final proof is fault-skipped, stale stack/register data
    // cannot authorize the confirmation below.
    unsafe {
        core::ptr::write_volatile(&mut dispatch_final_verdict_slot, crate::fi::FAIL_SENTINEL);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    dispatch_page_proofs.final_set_proof(
        &pages,
        &tx_for_display,
        legacy_fee_pages_required,
        &mut dispatch_final_verdict_slot,
    );
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: the slot remains live and is not concurrently written.
    let dispatch_final_verdict_a =
        unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
    crate::fi::scrub_sentinel_register();
    let dispatch_final_gate_a = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(dispatch_final_verdict_a == crate::fi::OK_SENTINEL)
    });
    crate::fi::scrub_sentinel_register();
    if dispatch_final_gate_a != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "value/fee conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::wait_random();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: this is a second independent volatile read after a randomized
    // gap; it deliberately does not reuse gate A's cached evidence.
    let dispatch_final_verdict_b =
        unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
    crate::fi::scrub_sentinel_register();
    let dispatch_final_gate_b = crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(dispatch_final_verdict_b == crate::fi::OK_SENTINEL)
    });
    crate::fi::scrub_sentinel_register();
    if dispatch_final_gate_b != crate::fi::OK_SENTINEL {
        ui::show_status("Sign refused", "value/fee conflict");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    if crate::tx::display::erc8213::fingerprint_final_set_proof(
        &pages,
        fingerprint_pages_before,
        fingerprint_kind,
    ) != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "fp changed");
        return NscStatus::InternalError as u32;
    }
    crate::fi::scrub_sentinel_register();
    let deployment_final_cfi_verdict = deployment_page_cfi
        .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
    crate::fi::scrub_sentinel_register();
    let deployment_final_verdict = crate::tx::display::deployment_final_set_proof(
        &pages,
        deployment_pages_before,
        &deployment_context,
    );
    if deployment_final_cfi_verdict != crate::fi::OK_SENTINEL
        || deployment_final_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Sign refused", "deploy changed");
        return NscStatus::InternalError as u32;
    }
    // Pixel trusted UI (`ui-px`, pilot = the Safe flow): the proven `pages`
    // stay the proof substrate; the Safe route is re-emitted as design
    // screens, bound to them by `px_lift::transcript_proof`, and confirmed
    // through the design's grammar. Every other route — and every build
    // without `ui-px` — keeps the page dialog.
    // The facts every trailer page above was painted from, for the pixel
    // route's native trailer twins (`tx::display::trailer_screens`): the
    // same values, never the pages and never companion bytes.
    let px_trailer_facts = crate::tx::display::TrailerFacts {
        tx: &tx_for_display,
        legacy_fee_required: legacy_fee_pages_required,
        paymaster_and_data_hash: &paymaster_and_data_hash,
        account_index,
        sender: &sender,
        target: &to_address,
        nonce: &type2_nonce,
        call_gas: &call_gas_limit,
        verification_gas: &verification_gas_limit,
        pre_verification_gas: &pre_verification_gas,
        fingerprint: fingerprint_kind,
        deployment: &deployment_context,
    };
    let px_decision = px_route_confirm(
        px_scratch,
        &pages,
        chain_id,
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
        cow_order_verified.as_ref(),
        chain_verified_meta.as_ref(),
        &resolver,
        &px_trailer_facts,
    );
    // Whether the pixel UI owns this confirmation (and therefore its ending).
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    let px_route = px_decision.is_some();
    let (cr, cr_verdict) = match px_decision {
        Some(Ok(r)) => r,
        Some(Err(reason)) => {
            ui::show_status("Sign refused", reason);
            return NscStatus::InternalError as u32;
        }
        None => confirm_checked(pages.as_slice()),
    };
    match cr {
        ConfirmResult::Confirmed => {
            // Second, spatially separate re-proof of the NS-resident glyph
            // atlas the pixel dialog just painted with (the first sits in
            // `px_confirm_safe`): the handler does not trust the returned
            // tuple alone, same A/B shape as the dispatch final gates.
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::fi::scrub_sentinel_register();
                if crate::ui::px::assets::atlas_root_proof() != crate::fi::OK_SENTINEL {
                    super::zeroize_sensitive_state();
                    ui::show_status("Sign refused", "px atlas");
                    return NscStatus::InternalError as u32;
                }
                crate::fi::scrub_sentinel_register();
            }
        }
        ConfirmResult::Cancelled => {
            #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
            if px_route {
                crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Declined);
                return NscStatus::UserRejected as u32;
            }
            ui::show_status("Cancelled", "");
            return NscStatus::UserRejected as u32;
        }
        ConfirmResult::IdleWipe => {
            super::zeroize_sensitive_state();
            return NscStatus::IdleWipe as u32;
        }
    }
    // FI belt (UI1 / work-todo #12c): reach signing ONLY on the affirmative
    // sentinel born at confirm's accept branch. A skipped reject-arm return is
    // caught here; fail closed (zeroize + reject).
    if cr_verdict != crate::fi::OK_SENTINEL {
        super::zeroize_sensitive_state();
        return NscStatus::UserRejected as u32;
    }
    if deployment_confirm_receipt
        .record_confirmed(&deployment_context)
        .is_err()
    {
        super::zeroize_sensitive_state();
        return NscStatus::InternalError as u32;
    }

    // ── 9. Reconstruct entropy + derive slot master ────────────────
    //
    // HIGH-6: wrap every stack-local secret in Zeroizing.
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|s| s.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut *entropy_blob) {
            Ok(l) => l,
            Err(_) => return NscStatus::InternalError as u32,
        }
    };
    let mut entropy = Zeroizing::new(
        match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &*master_secret,
        ) {
            Ok(e) => e,
            Err(_) => return NscStatus::CryptoError as u32,
        },
    );
    let slot_master_entropy: Zeroizing<[u8; 32]> = Zeroizing::new(
        crate::crypto::slot_master_entropy_from_entropy(&*entropy, account_index),
    );

    // ── 10. Build Type 2 callData: executeWithOffchainCount(...) ───
    //
    // The on-chain wallet's slot-authorised execute path also publishes
    // the firmware's per-slot off-chain sig counter, so the calldata
    // here commits to `(ownerIndex, newOffchainCount, target, value,
    // data)`. `newOffchainCount` is the firmware's local count *for
    // this slot*, read from secure-flash page 123.
    let t2_owner_index = (slot_index as u64) + 1;
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // The on-chain wallet's `_setOffchainSigCount` reverts on
    // non-monotonic input. The firmware's best estimate of the
    // on-chain `offchainSigCount[i]` is `last_userop_count` — the
    // value committed by the previous Type 2 sign for this slot. If
    // the local `offchain_count` view has fallen below that mark
    // (e.g. a partial compaction lost a `COUNT` entry, or this is the
    // first sign after a fresh-from-seed restore that surfaced a
    // stale `USEROP` snapshot from the prior incarnation), promote
    // `new_offchain_count` to the high-water mark and repair the
    // local off-chain counter so cmd_sign_offchain's gap arithmetic
    // and the `slotUses + offchainSigCount <= MAX_SLOT_USES` cap
    // continue to operate on a consistent base. Without this, the
    // sign here would still produce a valid C10 sig but the on-chain
    // verification would revert — wasting the slot's hypertree
    // budget AND surfacing as "Sig commit FAIL" the next time
    // `last_userop_count_set` enforced its old strict-monotonic
    // check.
    // F-10 hardening (audit 2026-06-18 — bring this gate to the off-chain
    // gate's bar, cmd_sign_offchain.rs §6): read each counter TWICE with a
    // randomised delay between and refuse on disagreement, so a single
    // stuck-at fault on the value-holding register after a good flash scan
    // cannot carry a faulted count into the combined-cap check below. The
    // reads forward+reverse-scan internally (F-12), so a glitched scan
    // yields u64::MAX — rejected here and tripped by the saturating cap.
    let local_offchain_a = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let local_offchain_b = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    if local_offchain_a != local_offchain_b || local_offchain_a == u64::MAX {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let local_offchain = local_offchain_a;

    let last_userop_a = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let last_userop_b = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    if last_userop_a != last_userop_b || last_userop_a == u64::MAX {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let last_userop_snapshot = last_userop_a;

    // MEDIUM-2 (audit counter-replay 20260611): enforce the *combined*
    // SPHINCS+ few-time budget on-device. Off-chain EIP-1271 sigs are
    // never counted on-chain (isValidSignature is view-only), and a
    // UserOp this firmware signs but the companion withholds / lets revert
    // never bumps on-chain `slotUses` — so the chain alone cannot bound
    // total slot-key usage. `userop_sigs` is the durable tally of Type-2
    // sigs THIS firmware has produced for the slot; together with
    // `local_offchain` it is the device's view of total slot-key
    // signatures. Refuse before signing if emitting one more would push
    // the combined total past MAX_SLOT_USES. Fail-closed: a glitched read
    // returns u64::MAX, which saturates and trips the gate.
    let userop_sigs_a = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    crate::fi::wait_random();
    let userop_sigs_b = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    if userop_sigs_a != userop_sigs_b {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let userop_sigs = userop_sigs_a;

    // The synced `last_userop` floor can be ahead of the materialised local
    // counter after recovery / CMD_OFFCHAIN_SYNC.  The promotion below becomes
    // durable before this signature is released, so the cap decision must use
    // that same effective value.  Checking bare `local_offchain` here used to
    // admit one Type-2 signature after a high sync even when
    // `userop_sigs + max(local,last)` was already exhausted.
    let effective_offchain =
        crate::aa::offchain_gate::effective_offchain_count(local_offchain, last_userop_snapshot);
    if !crate::aa::offchain_gate::userop_cap_ok(effective_offchain, userop_sigs) {
        ui::show_status("Slot exhausted", "rotate slot");
        return NscStatus::OffchainCapExceeded as u32;
    }
    // F-10 belt-and-braces: independently recompute BOTH the floor-fold and
    // cap after a randomised delay. `black_box` prevents LLVM from CSE-folding
    // this into the first decision, so a single glitch cannot substitute the
    // stale-low local count in both windows.
    crate::fi::wait_random();
    let effective_offchain_recheck = crate::aa::offchain_gate::effective_offchain_count(
        core::hint::black_box(local_offchain),
        core::hint::black_box(last_userop_snapshot),
    );
    if effective_offchain_recheck != core::hint::black_box(effective_offchain)
        || !crate::aa::offchain_gate::userop_cap_ok(
            effective_offchain_recheck,
            core::hint::black_box(userop_sigs),
        )
    {
        ui::show_status("Slot sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    secure_log!(
        "[S][sign] slot_key={:02x?} local_offchain={} last_userop={} userop_sigs={}",
        slot_flash_key,
        local_offchain,
        last_userop_snapshot,
        userop_sigs
    );
    let new_offchain_count = effective_offchain;
    if new_offchain_count > local_offchain {
        // Best-effort repair. Even if this write fails (e.g. flash
        // exhausted), we continue: `last_userop_count_set` below is
        // tolerant of an unmoved local counter, and the on-chain
        // monotonicity gate is the authoritative check. Surface a
        // diagnostic on the OLED so operators notice the repair.
        if unsafe {
            crate::offchain_state::offchain_count_promote_to(&slot_flash_key, new_offchain_count)
        }
        .is_err()
        {
            ui::show_status("Sign", "offchain repair");
        }
    }
    let t2_exec = match reconstruct_execute_calldata(
        t2_owner_index,
        new_offchain_count,
        &tx_for_display,
        inner_data,
    ) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 11. Type 2 nonce ───────────────────────────────────────────
    // `type2_nonce` was derived before trusted-display rendering so the
    // sequence/lane shown to the user is byte-identical to this signed nonce.

    // ── 12. Slot C10 keygen (cached by (account_index, chain_id, slot_index)) ──
    //
    // Post-Coinbase-port slot keys are chain-specific. With multi-
    // account derivation they're also account-specific (the master
    // entropy varies per `account_index`). A cache miss on any of the
    // three fields triggers a fresh <1 s keygen.
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded non-reentrant dispatcher: the
        // closure runs synchronously inside `peek_state`'s scope and
        // no other handler can race this read.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        match cached {
            Some(c) => {
                c.account_index != account_index
                    || c.chain_id != chain_id
                    || c.slot_index != slot_index
            }
            None => true,
        }
    });

    if need_keygen {
        ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*slot_master_entropy,
                chain_id,
                slot_index,
                |p| ui::show_progress("Slot keygen", p),
            );
        // SAFETY: category 5 — exclusive write to `static mut
        // SLOT_CACHE`. Non-reentrant dispatcher + `HandlerGuard`
        // mean no concurrent reader or SysTick wipe can race this
        // update. Any displaced prior `CachedSlot` drops here; its
        // `ZeroizeOnDrop` wipes the previous SK.
        unsafe {
            *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
                account_index,
                chain_id,
                slot_index,
                key: slot_sk,
            });
        }
        super::state::with_state(|s| {
            s.slot_master_entropy.zeroize();
            crate::fi::zeroize_barrier();
            s.slot_master_entropy = *slot_master_entropy;
            s.slot_master_derived.set_true();
        });
    }

    // Extract the 32-byte slot pubkey halves. Post-port the on-chain
    // verifier takes `bytes32` pkSeed + pkRoot directly from the 64-byte
    // owner bytes, so the old N-mask truncation to 16 bytes is gone.
    // SAFETY: category 5 — read-only borrow of `static mut SLOT_CACHE`.
    // The cache is guaranteed populated above (we either skipped
    // keygen because of a hit, or just wrote a fresh entry).
    // Non-reentrant dispatcher means no concurrent mutator.
    let (slot_pk_seed_32, slot_pk_root_32) = unsafe {
        match &*core::ptr::addr_of!(super::state::SLOT_CACHE) {
            Some(c) => {
                let mut seed = [0u8; 32];
                let mut root = [0u8; 32];
                seed[..16].copy_from_slice(&c.key.pk_seed()[..16]);
                root[..16].copy_from_slice(&c.key.pk_root()[..16]);
                (seed, root)
            }
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        }
    };

    // Slot-N's 64-byte owner bytes (pkSeed || pkRoot) — injected into the
    // Type 1 addOwnerBytes calldata.
    let mut slot_owner_bytes = [0u8; 64];
    slot_owner_bytes[..32].copy_from_slice(&slot_pk_seed_32);
    slot_owner_bytes[32..].copy_from_slice(&slot_pk_root_32);

    // First spatially separate authority check: no bootstrap-key factory
    // signature may start unless the exact deployment context crossed the
    // affirmative trusted-display branch above.
    crate::fi::scrub_sentinel_register();
    if deployment_confirm_receipt.completion_proof(&deployment_context)
        != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sign refused", "deploy consent");
        return NscStatus::InternalError as u32;
    }

    // ── 13. Build Type 1 (optional) + initCode (optional) ──────────
    //
    // We need the bootstrap C10 key in three cases:
    //   * FLAG_INCLUDE_INIT_CODE — to sign the factorySig for slot-0.
    //   * FLAG_REGISTER_SLOT — to sign the addOwnerBytes UserOp.
    // So regen the bootstrap key (<1 s) once and use as needed.
    //
    // Non-secret outputs:
    //   * `init_code_out` / `emit_init_code` — 4280-byte factory call.
    //   * `type1_wrapper_out` / `emit_type1` — 4128-byte SignatureWrapper.
    let mut init_code_out: Zeroizing<[u8; PQ_INIT_CODE_LEN]> =
        Zeroizing::new([0u8; PQ_INIT_CODE_LEN]);
    let mut type1_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    let mut emit_init_code = false;
    let mut emit_type1 = false;
    let mut t1_init_code_digest = SHA256_EMPTY;

    if include_init_code || register_slot {
        ui::show_progress("C10 keygen", 0);
        let (c10_sk, master_pk_seed_32, master_pk_root_32) =
            crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                &*entropy,
                account_index,
                |p| ui::show_progress("C10 keygen", p),
            );

        // Refresh the bootstrap pubkey cache so the address-picker
        // doesn't have to re-keygen this account on the next look-up.
        super::state::with_state(|s| {
            s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
        });

        // ── 13a. Deploy path: build initCode + factorySig ──────────
        if include_init_code {
            ui::show_status("Factory", "signing slot-0");

            // factorySig message: sha256(DOMAIN || chainId(8) ||
            //                             slot0PkSeed(32) || slot0PkRoot(32))
            let mut factory_msg = [0u8; 25 + 8 + 32 + 32];
            factory_msg[..25].copy_from_slice(FACTORY_ADD_SLOT_DOMAIN);
            factory_msg[25..33].copy_from_slice(&chain_id.to_be_bytes());
            factory_msg[33..65].copy_from_slice(&slot_pk_seed_32);
            factory_msg[65..97].copy_from_slice(&slot_pk_root_32);
            let factory_digest = sha256_bytes(&factory_msg);

            let factory_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &factory_digest,
                c10_sign_progress_bootstrap,
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    crate::fi::zeroize_barrier();
                    return NscStatus::CryptoError as u32;
                }
            };
            // Outer FI guard, symmetric with the Type 2 release. The sig
            // is already FI-verified inside `c10_sign_verified_*`; this
            // second pass guards the path between sign and the
            // initCode-buffer copy below. A glitch that corrupts
            // `factory_sig` or `factory_digest` post-sign would fail this
            // gate; without it the firmware would happily embed the
            // corrupted sig into the initCode blob.
            let (fv1, fv2) = {
                let v1 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &factory_digest,
                    &factory_sig,
                );
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &factory_digest,
                    &factory_sig,
                );
                (v1, v2)
            };
            // F16: `black_box` each verdict so LLVM cannot CSE-merge the
            // helper's two closure evaluations into one (the F-1 idiom the
            // single-bool gates here already use). The genuinely CSE-proof
            // redundancy is the two `verify()` calls separated by `wait_random`
            // above; this brings the AND-of-two outer gate up to the same bar.
            if crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(fv1) && core::hint::black_box(fv2)
            }) != crate::fi::OK_SENTINEL
            {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("FactorySig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            // Build the initCode blob. Layout:
            //
            //   factory(20)
            //   || selector(4)
            //   || masterPkSeed(32) || masterPkRoot(32)
            //   || slot0PkSeed(32) || slot0PkRoot(32)
            //   || chainId (left-padded to uint256, 32)
            //   || bytes-offset (0xE0 = 224, 32)
            //   || bytes-length (4008, 32)
            //   || factory_sig (4008 bytes, then padded to 4032)
            let ic = &mut *init_code_out;
            ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
            ic[20..24].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
            ic[24..56].copy_from_slice(&master_pk_seed_32);
            ic[56..88].copy_from_slice(&master_pk_root_32);
            ic[88..120].copy_from_slice(&slot_pk_seed_32);
            ic[120..152].copy_from_slice(&slot_pk_root_32);
            // chainId left-padded
            ic[152 + 24..184].copy_from_slice(&chain_id.to_be_bytes());
            // bytes-offset = 0xE0 (= head-args-len: 5 × 32 = 160; plus 32
            // for own offset slot gives 192 — wait, but offset is measured
            // from the start of the abi-encoded args, AFTER the selector.
            // Args start at ic+24. The 5 fixed slots take 5*32 = 160 bytes.
            // The bytes-offset slot itself is at 160..192. So offset value
            // = 192 (= 0xC0). Actually Solidity measures offset from the
            // *first byte of the abi-encoded args*, not from the offset
            // slot; and the offset points to the start of the length field.
            // For (bytes32,bytes32,bytes32,bytes32,uint64,bytes) the head
            // occupies 6×32 = 192 bytes (each head slot is 32), and the
            // length field starts at byte 192. So offset = 0xc0 = 192.
            let offset_field_start = 24 + 5 * 32;
            ic[offset_field_start + 24..offset_field_start + 32]
                .copy_from_slice(&(6 * 32u64).to_be_bytes());
            let length_field_start = offset_field_start + 32;
            ic[length_field_start + 24..length_field_start + 32]
                .copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
            let data_start = length_field_start + 32;
            ic[data_start..data_start + C10_SIG_LEN].copy_from_slice(&factory_sig);
            // Trailing 4032 - 4008 = 24 bytes of zero padding are already zero.

            debug_assert_eq!(data_start + 4032, PQ_INIT_CODE_LEN);
            emit_init_code = true;
            // initCode digest for the Type 2 sphincs sign.
            t1_init_code_digest = sha256_bytes(ic.as_slice());
        }

        // ── 13b. Rotation path: build addOwnerBytes UserOp + Type 1 sig ──
        if register_slot {
            ui::show_status("Slot register", "signing addOwner");

            // addOwnerBytes(bytes) calldata:
            //   selector(4) || offset(32 = 0x20) || length(32 = 0x40)
            //     || data(64 = slot_N_owner_bytes) — already 32-aligned
            let mut t1_call = [0u8; 4 + 32 + 32 + 64];
            t1_call[..4].copy_from_slice(&PQ_ADD_OWNER_BYTES_SELECTOR);
            t1_call[4 + 28..4 + 32].copy_from_slice(&0x20u32.to_be_bytes());
            t1_call[4 + 32 + 28..4 + 32 + 32].copy_from_slice(&64u32.to_be_bytes());
            t1_call[4 + 64..4 + 64 + 64].copy_from_slice(&slot_owner_bytes);
            let t1_call_digest = sha256_bytes(&t1_call);

            // Sphincs digest for the Type 1 UserOp.
            let t1_params = AaUserOpParamsV06Sha256 {
                sender,
                entry_point: ENTRY_POINT_V06,
                chain_id,
                nonce: U256(nonce),
                init_code_digest: SHA256_EMPTY, // rotation never rides initCode
                call_gas_limit: U256(call_gas_limit),
                verification_gas_limit: U256(verification_gas_limit),
                pre_verification_gas: U256(pre_verification_gas),
                max_fee_per_gas: U256(max_fee_per_gas),
                max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
                paymaster_and_data_digest: SHA256_EMPTY,
            };
            let t1_digest = compute_sphincs_digest_v06(&t1_params, &t1_call_digest);

            let bootstrap_sig = match crate::crypto::c10_sign_verified_with_progress(
                &c10_sk,
                &t1_digest,
                c10_sign_progress_bootstrap,
            ) {
                Ok(s) => s,
                Err(_) => {
                    entropy.zeroize();
                    crate::fi::zeroize_barrier();
                    return NscStatus::CryptoError as u32;
                }
            };
            // Outer FI guard, symmetric with Type 2.
            let (bv1, bv2) = {
                let v1 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &t1_digest,
                    &bootstrap_sig,
                );
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(),
                    c10_sk.pk_root(),
                    &t1_digest,
                    &bootstrap_sig,
                );
                (v1, v2)
            };
            // F16: black_box each verdict (see the factory-sig gate above).
            if crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(bv1) && core::hint::black_box(bv2)
            }) != crate::fi::OK_SENTINEL
            {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("Type1 sig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            super::sig_wrapper::encode_signature_wrapper(
                &mut *type1_wrapper_out,
                0,
                &bootstrap_sig,
            );
            emit_type1 = true;
        }

        drop(c10_sk); // ZeroizeOnDrop.
    }

    // ── 14. Type 2: slot C10 signs the user's UserOp sphincs digest ──
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_init_code_digest = if include_init_code {
        t1_init_code_digest
    } else {
        SHA256_EMPTY
    };
    // Second authority check, now coupled to the concrete post-confirm output:
    // the Type-2 digest must consume SHA-256 of the exact emitted initCode and
    // that blob must carry the factory shown to the user. Disabled mode proves
    // the opposite: no emitted blob and the canonical empty digest.
    crate::fi::scrub_sentinel_register();
    let deployment_receipt_verdict =
        deployment_confirm_receipt.completion_proof(&deployment_context);
    crate::fi::scrub_sentinel_register();
    let deployment_output_verdict = crate::tx::display::deployment_output_binding_proof(
        &deployment_context,
        emit_init_code,
        init_code_out.as_slice(),
        &t2_init_code_digest,
        &SHA256_EMPTY,
    );
    if deployment_receipt_verdict != crate::fi::OK_SENTINEL
        || deployment_output_verdict != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sign refused", "deploy binding");
        return NscStatus::InternalError as u32;
    }
    // The on-wire `paymaster_and_data_hash` is now the SHA-256 of the
    // paymasterAndData bytes (companion sends SHA256_EMPTY when absent).
    // Staying all-sha256 means zero keccak on the sign path.
    let t2_params = AaUserOpParamsV06Sha256 {
        sender,
        entry_point: ENTRY_POINT_V06,
        chain_id,
        nonce: U256(type2_nonce),
        init_code_digest: t2_init_code_digest,
        call_gas_limit: U256(call_gas_limit),
        verification_gas_limit: U256(verification_gas_limit),
        pre_verification_gas: U256(pre_verification_gas),
        max_fee_per_gas: U256(max_fee_per_gas),
        max_priority_fee_per_gas: U256(max_priority_fee_per_gas),
        paymaster_and_data_digest: paymaster_and_data_hash,
    };
    let t2_digest = compute_sphincs_digest_v06(&t2_params, &t2_call_digest);

    ui::show_progress("Slot C10 sign", 0);
    let t2_sig = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded dispatcher; the cache was
        // populated above (or already valid) and no concurrent
        // mutator can swap it under us.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        };
        match crate::crypto::c10_sign_verified_with_progress(
            slot_ref,
            &t2_digest,
            c10_sign_progress_slot,
        ) {
            Ok(s) => s,
            Err(_) => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::CryptoError as u32;
            }
        }
    };

    // Verify-before-release, double-evaluated with FI hardening. A
    // random-length volatile delay separates the two verifies, and
    // `fi::check_true` gates the AND through a hamming-distant
    // sentinel that survives single-bit flips. Defence in depth: the
    // sig was already FI-verified inside
    // `c10_sign_verified_with_progress`; this second pass guards the
    // path between sign and release-to-NS.
    let (v1, v2) = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE` for the FI-hardened verify-before-release.
        // Same single-threaded-dispatcher rationale as the sign block.
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                return NscStatus::InternalError as u32;
            }
        };
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        crate::fi::wait_random();
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &t2_digest, &t2_sig);
        (v1, v2)
    };
    // F16: black_box each verdict (see the factory-sig gate above).
    if crate::fi::check_true_into_sentinel(|| {
        core::hint::black_box(v1) && core::hint::black_box(v2)
    }) != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // Wrap the Type 2 sig: ownerIndex = slot_index + 1 (bootstrap is at 0).
    // `t2_owner_index` was bound at step 10 alongside the calldata.
    let mut type2_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    super::sig_wrapper::encode_signature_wrapper(&mut *type2_wrapper_out, t2_owner_index, &t2_sig);

    // ── 14b. Persist the new last_userop_count and (if Type 1) the
    //         registered-slot flag. Done *after* sig verify so a verify
    //         failure does not bake a phantom count into flash.
    if register_slot {
        if unsafe { crate::offchain_state::offchain_count_register_slot(&slot_flash_key) }.is_err()
        {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            secure_log!(
                "[S][slot-register] offchain_count_register_slot FAIL key={:02x?}",
                slot_flash_key
            );
            ui::show_status("Slot register", "FAIL");
            return NscStatus::InternalError as u32;
        }
    }
    if unsafe { crate::offchain_state::last_userop_count_set(&slot_flash_key, new_offchain_count) }
        .is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!(
            "[S][sig-commit] last_userop_count_set FAIL key={:02x?} count={}",
            slot_flash_key,
            new_offchain_count
        );
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }
    // MEDIUM-2: durably tally this Type-2 slot-key signature so the
    // combined-cap gate (§10) accounts for it on the next call. Bumped
    // after sig verify (so a verify failure bakes no phantom count) and
    // before the response is written (so a bump failure refuses the
    // response rather than releasing an uncounted sig). `userop_sigs` was
    // read at §10 and the cap gate proved `userop_sigs < MAX_SLOT_USES`,
    // so `+ 1` cannot overflow.
    if unsafe { crate::offchain_state::userop_sigs_bump(&slot_flash_key, userop_sigs + 1) }.is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!(
            "[S][sig-commit] userop_sigs_bump FAIL key={:02x?} count={}",
            slot_flash_key,
            userop_sigs + 1
        );
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 15. Assemble output bundle ─────────────────────────────────
    //
    // Layout:
    //   [new_offchain_count(8 BE)] -- the value just baked into the
    //                                signed inner-tx calldata, surfaced
    //                                here so the companion does not
    //                                have to ABI-decode `executeWith
    //                                OffchainCount(...)` to find it.
    //   [init_code_len(4 BE)][init_code(0 or 4280)]
    //   [type1_len(4 BE)][type1_wrapper(0 or 4128)]
    //   [type2_len(4 BE)][type2_wrapper(4128)]
    //
    // FI deref-site re-validation (finding F5). The top-of-handler write gate
    // (§2) and these volatile writes are spatially distant, so a single skip of
    // that gate's reject branch would admit an `out_ptr` into secure SRAM
    // straight to the writes below. Re-validate the FULL MAX_SIGN_RESPONSE_LEN
    // write extent now, double-evaluated through the Hamming-distant sentinel,
    // so reaching the write REQUIRES a second passing validation in this branch
    // — two coordinated faults instead of one. A legit sign already passed the
    // identical §2 check, so this never false-rejects.
    let out_extent_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if out_extent_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }
    let mut write_pos: usize = 0;
    write_be_u64(out_ptr, &mut write_pos, new_offchain_count);
    let init_code_len = if emit_init_code { PQ_INIT_CODE_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, init_code_len as u32);
    if emit_init_code {
        for i in 0..PQ_INIT_CODE_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), init_code_out[i]);
        }
        write_pos += PQ_INIT_CODE_LEN;
    }

    let type1_len = if emit_type1 { SIG_WRAPPER_LEN } else { 0 };
    write_be_u32(out_ptr, &mut write_pos, type1_len as u32);
    if emit_type1 {
        for i in 0..SIG_WRAPPER_LEN {
            core::ptr::write_volatile(out_ptr.add(write_pos + i), type1_wrapper_out[i]);
        }
        write_pos += SIG_WRAPPER_LEN;
    }

    write_be_u32(out_ptr, &mut write_pos, SIG_WRAPPER_LEN as u32);
    for i in 0..SIG_WRAPPER_LEN {
        core::ptr::write_volatile(out_ptr.add(write_pos + i), type2_wrapper_out[i]);
    }
    write_pos += SIG_WRAPPER_LEN;

    debug_assert!(write_pos <= MAX_SIGN_RESPONSE_LEN);
    debug_assert_eq!(
        write_pos - (8 + 4 + init_code_len + 4 + type1_len + 4),
        SIG_WRAPPER_LEN
    );
    let _ = write_pos;

    // ── 16. Zeroise transients ─────────────────────────────────────
    entropy.zeroize();
    crate::fi::zeroize_barrier();
    type1_wrapper_out.zeroize();
    type2_wrapper_out.zeroize();
    init_code_out.zeroize();
    // L-2: wipe the TOCTOU snapshot on exit too. The payload itself is
    // not secret (the NS side sourced it) but it contains user metadata
    // (names, EIP-712 readable text, recipients) that we don't want
    // leaving in BSS until the next sign overwrites it.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if px_route {
        crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Signed);
    } else {
        ui::show_status("Signed", "");
    }
    #[cfg(not(all(feature = "ui-px", feature = "ui-lcd")))]
    ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// Volatile write of a big-endian u32 to `out_ptr + *write_pos`, advancing the cursor.
///
/// # Safety
/// Category 2 — NS pointer deref. Caller must have already validated
/// `[out_ptr, out_ptr + MAX_SIGN_RESPONSE_LEN)` via
/// `validate_ns_write_ptr` AND must ensure `*write_pos + 4 <=
/// MAX_SIGN_RESPONSE_LEN`. The volatile store keeps NS observers from
/// seeing a torn word.
unsafe fn write_be_u32(out_ptr: *mut u8, write_pos: &mut usize, v: u32) {
    let be = v.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 4;
}

/// Volatile write of a big-endian u64 to `out_ptr + *write_pos`, advancing the cursor.
///
/// # Safety
/// Category 2 — NS pointer deref. Caller must have validated
/// `[out_ptr, out_ptr + MAX_SIGN_RESPONSE_LEN)` via
/// `validate_ns_write_ptr` AND ensured `*write_pos + 8 <=
/// MAX_SIGN_RESPONSE_LEN`.
unsafe fn write_be_u64(out_ptr: *mut u8, write_pos: &mut usize, v: u64) {
    let be = v.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 8;
}

/// Increment the 64-bit sequence portion of an EntryPoint v0.6 nonce
/// (192-bit key | 64-bit seq, stored big-endian in bytes[24..32]).
fn add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    debug_assert!(false, "nonce seq overflow slipped past the step-4b guard");
}

fn c10_sign_progress_bootstrap(percent: u8) {
    crate::ui::show_progress("C10 sign", percent);
}

fn c10_sign_progress_slot(percent: u8) {
    crate::ui::show_progress("Slot C10 sign", percent);
}

/// Decode a 32-byte BE u256 as `u128`, saturating at `u128::MAX`.
fn u128_saturating_from_u256(bytes: &[u8; 32]) -> u128 {
    for &b in &bytes[0..16] {
        if b != 0 {
            return u128::MAX;
        }
    }
    let mut buf = [0u8; 16];
    buf.copy_from_slice(&bytes[16..32]);
    u128::from_be_bytes(buf)
}

/// Route a Safe sign confirmation through the pixel UI when `ui-px` is on.
/// `None` means "use the page dialog" (non-Safe route, or the feature is
/// off); `Some(Err(reason))` is a refusal, never a fall-back.
#[cfg(feature = "ui-px")]
fn px_route_confirm(
    scratch: &mut [u8],
    pages: &crate::tx::display::Pages,
    chain_id: u64,
    safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    cow: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    resolver: &crate::names::NameResolver<'_>,
    facts: &crate::tx::display::TrailerFacts<'_>,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    if safe_v1.is_none() && safe_exec.is_none() {
        return None;
    }
    Some(super::px_confirm_safe(scratch, pages, chain_id, safe_v1, safe_exec, cow, erc20, resolver, facts))
}

#[cfg(not(feature = "ui-px"))]
#[inline(always)]
fn px_route_confirm(
    _scratch: &mut [u8],
    _pages: &crate::tx::display::Pages,
    _chain_id: u64,
    _safe_v1: Option<&crate::tx::eip712::safe::VerifiedSafeV1<'_>>,
    _safe_exec: Option<&crate::tx::eip712::safe::VerifiedSafeExec<'_>>,
    _cow: Option<&crate::tx::eip712::cowswap::VerifiedCowswapV3>,
    _erc20: Option<&crate::erc20::bundle::Erc20Metadata<'_>>,
    _resolver: &crate::names::NameResolver<'_>,
    _facts: &crate::tx::display::TrailerFacts<'_>,
) -> Option<Result<(crate::ui::confirm::ConfirmResult, u32), &'static str>> {
    None
}
