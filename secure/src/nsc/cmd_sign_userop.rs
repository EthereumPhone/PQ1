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
    NscStatus, ACCOUNT_INDEX_MASK, ACCOUNT_INDEX_SHIFT, APPROVE_HASH_CALLDATA_LEN,
    APPROVE_HASH_SELECTOR, C10_SIG_LEN, ERC7730_MAX_TRAILER_LEN,
    EXEC_TRANSACTION_MIN_CALLDATA_LEN, EXEC_TRANSACTION_SELECTOR, FLAG_INCLUDE_INIT_CODE,
    FLAG_REGISTER_SLOT, GPV2_SETTLEMENT_ADDRESS, MAX_SIGN_RESPONSE_LEN, MAX_TX_LEN,
    PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SAFE_V1_PAYLOAD_MAX, SET_PRE_SIGNATURE_SELECTOR,
    SIGN_USEROP_HEADER_LEN, SIG_WRAPPER_LEN, SLOT_INDEX_MASK, ZK_CLEAR_SIGN_FIXED_LEN,
    ZK_V3_FIXED_LEN, ZK_VK_BUNDLE_MAX_LEN,
};
use zeroize::{Zeroize, Zeroizing};

/// Domain tag the firmware signs when authorising slot-0 on a new chain.
/// MUST match `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata, MAX_ERC20_BUNDLE_LEN};
use crate::names::{verify_name_bundle, NameResolver, MAX_NAME_BUNDLES, MAX_NAME_BUNDLE_LEN};
use crate::selectors::{
    parse_self_attest_bundle, verify_selector_bundle, SelectorMeta, MAX_SELECTOR_BUNDLE_LEN,
    MAX_SELF_ATTEST_BUNDLE_LEN,
};
use crate::tx::display::pick_sign_pages;
use crate::tx::eip1559::{Eip1559Tx, U256};
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
    + 2 + ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN
    + 2 + ZK_V3_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN
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
    use crate::ui::confirm::{confirm, ConfirmResult};

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
    if !validate_ns_read_ptr(args.arg0, total_len) {
        ui::show_status("Sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN) {
        ui::show_status("Sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // M1 fix: wipe any leftover payload from the PREVIOUS sign before
    // we fill it with this request.
    static mut SNAP_BUF: [u8; SNAP_LEN] = [0u8; SNAP_LEN];
    {
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    let snap = &mut SNAP_BUF[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

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
    let include_init_code = (flags & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & FLAG_REGISTER_SLOT) != 0;
    let account_index = (flags & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT;
    let slot_index = flags & SLOT_INDEX_MASK;

    #[cfg(all(feature = "e2e-test", feature = "ui-oled"))]
    {
        static mut E2E_CALL_NO: u8 = 0;
        // SAFETY: category 5 — `E2E_CALL_NO` is a `static mut` debug-
        // only counter compiled in only under `e2e-test` + `ui-oled`.
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
    let mut sender = [0u8; 20];
    sender.copy_from_slice(&snap[12..32]);
    let mut entry_point = [0u8; 20];
    entry_point.copy_from_slice(&snap[32..52]);
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
    let data_len = u16::from_be_bytes([snap[328], snap[329]]) as usize;

    if data_len > MAX_TX_LEN || SIGN_USEROP_HEADER_LEN + data_len > total_len {
        ui::show_status("Sign", "bad data_len");
        return NscStatus::InvalidPointer as u32;
    }

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
    let include_init_code_r = (flags_recheck & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot_r = (flags_recheck & FLAG_REGISTER_SLOT) != 0;
    let slot_index_r = flags_recheck & SLOT_INDEX_MASK;
    if include_init_code_r != include_init_code
        || register_slot_r != register_slot
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

    let inner_data: &[u8] =
        &snap[SIGN_USEROP_HEADER_LEN..SIGN_USEROP_HEADER_LEN + data_len];

    // ── 5. Parse optional trailers ─────────────────────────────────
    //
    // Three independently-optional length-prefixed trailers (ERC-20
    // bundle, v1 ZK clear-sign, v3 CoW EIP-712), followed by the
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

    let zk_v1 = match super::trailer::read_optional_u16_prefixed(
        snap,
        cursor,
        total_len,
        ZK_CLEAR_SIGN_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN,
        "bad zk bundle",
    ) {
        Ok(t) => t,
        Err(s) => return s,
    };
    cursor = zk_v1.next_cursor;

    // v3 CoW EIP-712 trailer: proof(384) || canonical(204) ||
    // readable(128) || VK bundle. Companion sends the 716-byte fixed
    // prefix; the NS gateway's `maybe_inject_vk_bundle_v3` appends
    // the bundle. Absent is legal for non-CoW tx — the CoW
    // downgrade-mitigation gate below enforces presence when needed.
    //
    // Inlined instead of `trailer::read_optional_u16_prefixed` so the
    // OLED distinguishes the two failure modes (oversized declared
    // length vs. declared length overflowing the payload) — makes
    // companion-vs-NS-router layout disagreements trivial to triage.
    let zk_v3 = if cursor + 2 > total_len {
        super::trailer::Trailer {
            start: cursor,
            len: 0,
            next_cursor: cursor,
        }
    } else {
        let declared = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        let payload_start = cursor + 2;
        if declared > ZK_V3_FIXED_LEN + ZK_VK_BUNDLE_MAX_LEN {
            // Dump four values across the 4-line OLED:
            //   line 1: "Sign v3 len>cap"
            //   line 2: "d=XXXX (data_len)"
            //   line 3: "e=XXXX z=XXXX   "   (erc20 + v1 zk declared len)
            //   line 4: "v3=XXXX        "
            // Expected happy values for a CoW swap on Base:
            //   d=00a4 (164), e=0000, z=0000, v3=0790 (or 02cc bare).
            const HEX: &[u8] = b"0123456789abcdef";
            let d = data_len as u16;
            let e = erc20.len as u16;
            let z = zk_v1.len as u16;
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
            line3[7] = b'z';
            line3[8] = b'=';
            line3[9] = HEX[((z >> 12) & 0xF) as usize];
            line3[10] = HEX[((z >> 8) & 0xF) as usize];
            line3[11] = HEX[((z >> 4) & 0xF) as usize];
            line3[12] = HEX[(z & 0xF) as usize];

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
    cursor = zk_v3.next_cursor;

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
    // Wire layout: `[u16 BE len][payload]`, payload is exactly the
    // bundle format consumed by `pqsigner_erc7730::bundle::verify_erc7730_bundle`:
    //   ir_len(2 BE) || ir || leaf_index(4 BE) || proof_depth(4 BE) || proof
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

    // ERC-7730 is an enhancement layer: a wrong / malformed / mis-bound
    // trailer MUST degrade gracefully to blind-sign instead of aborting
    // the userop, per `docs/companion-erc7730-implementation-guide.md`
    // §1: "If it ships a wrong / malformed / mis-bound trailer, the
    // firmware refuses the descriptor and falls back to blind-sign with
    // a brief status-line banner. Clear signing is never required — it
    // is an enhancement layer the companion is free to skip per-tx."
    //
    // The banner is shown via `ui::show_status` so the user can see why
    // clear-signing didn't engage; the subsequent confirmation pages
    // then render the blind-sign ladder normally.
    let erc7730_verified: Option<crate::tx::erc7730::VerifiedDescriptor<'_>> =
        if erc7730_trailer.len > 0 {
            let bytes = &snap[erc7730_trailer.start
                ..erc7730_trailer.start + erc7730_trailer.len];
            match crate::tx::erc7730::verify_erc7730_bundle(
                bytes,
                &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
            ) {
                Ok(v) => {
                    // FI-hardened binding cross-check (Phase 5 item 6).
                    // Compute the verdict once, then double-evaluate via
                    // `check_true_into_sentinel` with `wait_random` between.
                    // A single-fault glitch that skips the gate also has to
                    // race a Hamming-distant sentinel compare. Mirrors the
                    // verify-before-release pattern in
                    // `crypto::c10_sign_verified_with_progress`.
                    let bind_ok = crate::tx::erc7730::cross_check_contract(
                        &v.ir,
                        chain_id,
                        &to_address,
                    )
                    .is_ok();
                    crate::fi::wait_random();
                    if crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_ok))
                        != crate::fi::OK_SENTINEL
                    {
                        ui::show_status("Sign", "7730 binding fail");
                        None
                    } else {
                        #[cfg(feature = "debug-log")]
                        {
                            let c = &v.ir.contract;
                            secure_log!(
                                "[ERC-7730] matched: chain={} contract=0x{:02x}{:02x}{:02x}{:02x}..{:02x}{:02x}{:02x}{:02x} ir_len={}",
                                v.ir.chain_id,
                                c[0], c[1], c[2], c[3],
                                c[16], c[17], c[18], c[19],
                                v.ir.raw.len(),
                            );
                        }
                        Some(v)
                    }
                }
                Err(_e) => {
                    ui::show_status("Sign", "7730 bundle fail");
                    None
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

    // ── 6. Build display-time Eip1559Tx shim ───────────────────────
    let display_nonce = u64::from_be_bytes([
        nonce[24], nonce[25], nonce[26], nonce[27],
        nonce[28], nonce[29], nonce[30], nonce[31],
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
    };

    // ── 7. Verify optional trailers ────────────────────────────────

    // 7a. ERC-20 bundle — Merkle-verified token metadata, cross-checked
    // against the tx's chain_id + recipient address.
    let verified_meta: Option<Erc20Metadata<'_>> = if erc20.len > 0 {
        let bundle_slice = &snap[erc20.start..erc20.start + erc20.len];
        match verify_erc20_bundle(bundle_slice) {
            Some(meta) => {
                let contract_match = match tx_for_display.to {
                    Some(addr) => addr == meta.contract,
                    None => false,
                };
                if meta.chain_id == chain_id && contract_match {
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

    // 7b. v1 ZK clear-sign — circuit-attested (calldata, readable)
    // pair + VK bundle Merkle-committed to VK_DB_ROOT. See
    // `zk::verify_and_bind_trailer_v1` for the full trust chain.
    let zk_v1_verified = if zk_v1.len > 0 {
        crate::zk::verify_and_bind_trailer_v1(
            &snap[zk_v1.start..zk_v1.start + zk_v1.len],
            inner_data,
            chain_id,
            &to_address,
        )
    } else {
        None
    };

    // 7c. v3 CoW EIP-712 — 5-step pipeline (Groth16 + H_root pin →
    // sentinel + chain → length → shape → cross-check). Returns
    // `None` on any failure; no partial-success fallback. See
    // `tx::eip712::cowswap::verify_and_bind_trailer` for specifics.
    let zk_v3_verified = if zk_v3.len > 0 {
        crate::tx::eip712::cowswap::verify_and_bind_trailer(
            &snap[zk_v3.start..zk_v3.start + zk_v3.len],
            inner_data,
            chain_id,
            &sender,
        )
    } else {
        None
    };

    // 7c-bis. `safe_v1` Safe-multisig `approveHash` cross-check —
    // 8-step all-native pipeline (length → selector → calldata len →
    // chain pin → safe-address pin → operation gate → data_hash bind
    // → safeTxHash bind). No Groth16; the approveHash digest is in the
    // calldata itself, so the firmware natively recomputes both
    // keccak chains and byte-compares.
    let safe_v1_verified = if safe_v1.len > 0 {
        crate::tx::eip712::safe::verify_and_bind_trailer(
            &snap[safe_v1.start..safe_v1.start + safe_v1.len],
            inner_data,
            chain_id,
            &to_address,
        )
    } else {
        None
    };

    // 7c-ter. Safe-multisig `execTransaction(...)` decode — no trailer
    // needed; the SafeTx fields are encoded directly into the function
    // arguments, so the firmware decodes them straight out of
    // `inner_data` once the selector matches. Companion of the
    // approveHash path above for the case where the wallet is the
    // EOA-equivalent actually triggering execution (carrying co-signers'
    // approvals in the `signatures` argument).
    let safe_exec_verified = if inner_data.len() >= 4
        && inner_data[..4] == EXEC_TRANSACTION_SELECTOR
    {
        crate::tx::eip712::safe::verify_and_bind_exec(inner_data, chain_id, &to_address)
    } else {
        None
    };

    // 7c-ter. Selector → text-signature bundle.
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
        let bundle_slice = &snap
            [self_attest_trailer.start..self_attest_trailer.start + self_attest_trailer.len];
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
    if cow_selector && cow_target && zk_v3_verified.is_none() {
        ui::show_status("CoW sign", "v3 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Symmetric Safe `approveHash` gate. If the inner calldata claims
    // to be `approveHash(bytes32)`, a `safe_v1` trailer is mandatory.
    // Without this gate a hostile NS could strip the trailer and
    // coerce the user into blind-signing the bytes32 hash with no
    // visibility into what SafeTx it commits to.
    let safe_selector = inner_data.len() >= 4 && inner_data[..4] == APPROVE_HASH_SELECTOR;
    let safe_calldata_len = inner_data.len() == APPROVE_HASH_CALLDATA_LEN;
    if safe_selector && safe_calldata_len && safe_v1_verified.is_none() {
        ui::show_status("Safe sign", "safe_v1 required");
        return NscStatus::InvalidPointer as u32;
    }

    // Symmetric Safe `execTransaction` gate. The selector + minimum-
    // length signature is unique enough that any NS attempt to feed
    // execTransaction calldata SHOULD be honoured by the Safe-exec
    // renderer; a parse failure means the calldata is malformed or
    // requests DelegateCall. Either way the firmware refuses rather
    // than falling through to a generic blind-sign view, which would
    // confuse the user about the actual on-chain behaviour ("this
    // looks like a Safe call, why is it asking me to blind-sign?").
    let safe_exec_selector =
        inner_data.len() >= 4 && inner_data[..4] == EXEC_TRANSACTION_SELECTOR;
    let safe_exec_enough_len = inner_data.len() >= EXEC_TRANSACTION_MIN_CALLDATA_LEN;
    if safe_exec_selector && safe_exec_enough_len && safe_exec_verified.is_none() {
        ui::show_status("Safe sign", "exec parse fail");
        return NscStatus::InvalidPointer as u32;
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
    // The priority ladder (v3 → v1 → value/ERC-20/blind-sign) lives in
    // `display::pick_sign_pages`. Ordering is load-bearing: v3 beats
    // v1 so a CoW setPreSig that satisfied both circuits renders the
    // 8-page order, not the weaker string. The gate above made this
    // the only legal outcome for CoW setPreSig already.
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
        let rotate_pages = crate::tx::display::build_slot_rotation_pages(slot_index);
        match confirm(rotate_pages.as_slice()) {
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
    }
    let mut pages = pick_sign_pages(
        &tx_for_display,
        inner_data,
        zk_v3_verified.as_ref(),
        zk_v1_verified.as_ref(),
        safe_v1_verified.as_ref(),
        safe_exec_verified.as_ref(),
        erc7730_verified.as_ref(),
        verified_meta.as_ref(),
        selector_verified.as_ref(),
        &resolver,
    );
    // ERC-8213 fingerprint — show the calldata digest as the last
    // page so a user can cross-check against `cast` / `viem`. Always
    // appended (cap is 22 pages; longest renderer ≤ 14 pages, well
    // within budget). If the buffer is full (shouldn't happen with
    // current renderers but the bound is enforced), the fingerprint
    // is silently skipped — off-device verification still works.
    let calldata_fingerprint =
        pqsigner_tx_core::erc8213::calldata_digest(inner_data);
    let _ = crate::tx::display::erc8213::append_fingerprint_page(
        &mut pages,
        crate::tx::display::erc8213::Kind::CalldataDigest(calldata_fingerprint),
    );
    match confirm(pages.as_slice()) {
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
    let local_offchain =
        unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    let last_userop_snapshot =
        unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    secure_log!(
        "[S][sign] slot_key={:02x?} local_offchain={} last_userop={}",
        slot_flash_key, local_offchain, last_userop_snapshot
    );
    let new_offchain_count = local_offchain.max(last_userop_snapshot);
    if new_offchain_count > local_offchain {
        // Best-effort repair. Even if this write fails (e.g. flash
        // exhausted), we continue: `last_userop_count_set` below is
        // tolerant of an unmoved local counter, and the on-chain
        // monotonicity gate is the authoritative check. Surface a
        // diagnostic on the OLED so operators notice the repair.
        if unsafe {
            crate::offchain_state::offchain_count_promote_to(
                &slot_flash_key,
                new_offchain_count,
            )
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
    // When REGISTER_SLOT is set, the Type 1 UserOp consumes the supplied
    // base nonce and Type 2 uses base+1. In the other two modes Type 2
    // uses the supplied base directly.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

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
                    c10_sk.pk_seed(), c10_sk.pk_root(), &factory_digest, &factory_sig);
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(), c10_sk.pk_root(), &factory_digest, &factory_sig);
                (v1, v2)
            };
            if crate::fi::check_true_into_sentinel(|| fv1 && fv2) != crate::fi::OK_SENTINEL {
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
                entry_point,
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
                    c10_sk.pk_seed(), c10_sk.pk_root(), &t1_digest, &bootstrap_sig);
                crate::fi::wait_random();
                let v2 = sphincs_c10::verify(
                    c10_sk.pk_seed(), c10_sk.pk_root(), &t1_digest, &bootstrap_sig);
                (v1, v2)
            };
            if crate::fi::check_true_into_sentinel(|| bv1 && bv2) != crate::fi::OK_SENTINEL {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("Type1 sig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            super::sig_wrapper::encode_signature_wrapper(&mut *type1_wrapper_out, 0, &bootstrap_sig);
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
    // The on-wire `paymaster_and_data_hash` is now the SHA-256 of the
    // paymasterAndData bytes (companion sends SHA256_EMPTY when absent).
    // Staying all-sha256 means zero keccak on the sign path.
    let t2_params = AaUserOpParamsV06Sha256 {
        sender,
        entry_point,
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
    if crate::fi::check_true_into_sentinel(|| v1 && v2) != crate::fi::OK_SENTINEL {
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
        if unsafe { crate::offchain_state::offchain_count_register_slot(&slot_flash_key) }
            .is_err()
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
    if unsafe {
        crate::offchain_state::last_userop_count_set(&slot_flash_key, new_offchain_count)
    }
    .is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        secure_log!(
            "[S][sig-commit] last_userop_count_set FAIL key={:02x?} count={}",
            slot_flash_key, new_offchain_count
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
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
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
