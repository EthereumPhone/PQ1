//! CMD_SIGN_USEROP_BATCH — atomic multi-call SPHINCS+C10 sign.
//!
//! ## Trust contract
//!
//! Same flag handling, same bootstrap/slot key derivation, same FI
//! verify-before-release pattern as the single-tx
//! [`super::cmd_sign_userop`]. The only differences are:
//!
//!   * The wire payload carries N `(to, value, data)` blocks instead of
//!     a single one.
//!   * The trusted UI confirms each inner tx independently (banner +
//!     per-tx pages + long-right) so clear-signing is preserved per
//!     member, then a final "Sign N txs?" gate authorises the whole
//!     batch.
//!   * The Type 2 callData is `executeBatchWithOffchainCount(...)`
//!     covering all N inner txs instead of
//!     `executeWithOffchainCount(...)`.
//!
//! ## Trailer parity with single-tx (wire v2)
//!
//! The payload terminates in a TLV-tagged trailer list (see
//! [`super::batch_trailers`]). Every clear-signing kind the single-tx
//! handler accepts is also accepted here, routed per inner-tx:
//!
//!   * Live kinds 1 and 3..=7 (ERC-20, native CoW order, Safe v1,
//!     selector curated, selector self-attest, ERC-7730) bind via `tx_idx` to a specific
//!     inner-tx and feed `pick_sign_pages` for that tx.
//!   * Frozen compatibility kind 2 is rejected for every payload length.
//!   * Kind 8 (address-name bundles) is batch-wide (`tx_idx == 0xff`),
//!     accumulating into a single `NameResolver` shared across renders.
//!
//! The same per-tx **downgrade-mitigation gates** as single-tx fire
//! before `pick_sign_pages` for each inner-tx: if an inner calldata
//! claims `setPreSignature` on GPv2 settlement, the matching native CoW order
//! trailer is mandatory; if it claims `approveHash(bytes32)`, the
//! matching Safe v1 trailer is mandatory. Refusal aborts the whole
//! batch with `InvalidPointer`.
//!
//! Wire-version cutover: payloads with `wire_version != 2` are refused.
//! Companions check device protocol version via `INS_GET_DEVICE_INFO`
//! before sending.
//!
//! Output bundle is byte-identical to `CMD_SIGN_USEROP`'s. The
//! companion submits the resulting UserOp to EntryPoint v0.6 the same
//! way it submits any other; only the inner `callData` differs.

use sphincs_tz_shared::{
    NscStatus, C10_SIG_LEN, GPV2_SETTLEMENT_ADDRESS, MAX_BATCH_TXS, MAX_SIGN_RESPONSE_LEN,
    MAX_TX_LEN, PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SET_PRE_SIGNATURE_SELECTOR, SIGN_USEROP_BATCH_HEADER_LEN,
    SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN, SIGN_USEROP_BATCH_TX_PREFIX_LEN,
    SIGN_USEROP_BATCH_WIRE_VERSION, SIG_WRAPPER_LEN, TRAILER_KIND_COW_ORDER, TRAILER_KIND_ERC20,
    TRAILER_KIND_ERC7730, TRAILER_KIND_NAME, TRAILER_KIND_SAFE_V1, TRAILER_KIND_SEL_CURATED,
    TRAILER_KIND_SEL_SELFATTEST,
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
    batch_member_commitment, batch_tuple_commitment_from_members, compute_sphincs_digest_v06,
    execute_batch_tuple_commitment_from_calldata, reconstruct_execute_batch_calldata_into,
    sha256_bytes, AaUserOpParamsV06Sha256, BatchInnerTx, ExecuteBatchCallData, ENTRY_POINT_V06,
    MAX_EXECUTE_BATCH_CALLDATA_LEN, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata};
use crate::names::{verify_name_bundle, NameResolver};
use crate::selectors::{parse_self_attest_bundle, verify_selector_bundle, SelectorMeta};
use crate::tx::display::batch::{build_final_summary_pages, wrap_pages_with_batch_banner};
use crate::tx::display::pick_sign_pages_with_erc7730_evidence;
use crate::tx::eip1559::{Eip1559Tx, UserOpDisplayFields, U256};
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::safe::VerifiedSafeV1;
use crate::tx::erc7730::VerifiedProofSet;
use crate::ui;

use super::batch_trailers::parse_all as parse_batch_trailers;

/// Snapshot buffer sized for the worst-case batch payload (header +
/// MAX_BATCH_TXS × (per-tx prefix + MAX_TX_LEN data)).
const SNAP_LEN: usize = SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN;

/// One parsed inner tx, pointing into the TOCTOU snapshot.
struct ParsedTx {
    to: [u8; 20],
    value: [u8; 32],
    /// Byte offset of the `data` payload within the snapshot.
    data_off: usize,
    data_len: usize,
}

/// Per-inner-tx routed trailer slots. Each field carries the result of
/// a successful verifier on a trailer whose wire `tx_idx` matched this
/// inner tx's index. Empty fields reach `pick_sign_pages`; genuinely unknown
/// tuples may use lower-priority value/ERC-20/typed/blind renderers, while a
/// firmware-known ERC-7730 tuple with no verified descriptor hard-refuses.
///
/// Lifetime `'a` ties to the secure-side TOCTOU snapshot — every
/// borrowed verifier output (ERC-20 metadata, Safe canonical, ERC-7730
/// IR, selector text-sig) lives inside `snap[..]` for the whole
/// `pick_sign_pages` call window. The native CoW verifier returns an owned
/// fixed-size buffer, hence no `'a` on that variant.
struct RoutedTrailers<'a> {
    erc20: Option<Erc20Metadata<'a>>,
    cow_order: Option<VerifiedCowswapV3>,
    safe_v1: Option<VerifiedSafeV1<'a>>,
    erc7730: Option<VerifiedProofSet<'a>>,
    selector: Option<SelectorMeta<'a>>,
}

impl<'a> RoutedTrailers<'a> {
    /// All slots `None`. Used as the `get_or_insert_with` default while
    /// dispatching parsed trailer records into the per-tx array.
    fn empty() -> Self {
        Self {
            erc20: None,
            cow_order: None,
            safe_v1: None,
            erc7730: None,
            selector: None,
        }
    }
}

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. Same
/// invariants as `cmd_sign_userop::run`: NS pointer derefs only
/// after `validate_ns_{read,write}_ptr`, `static mut` driver state
/// (`SE`, `SLOT_CACHE`, `SNAP_BUF`) accessed under the non-reentrant
/// dispatcher + `HandlerGuard`.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    use crate::ui::confirm::{confirm_checked, ConfirmResult};

    // Same handler-busy guard as the single-tx path: prevents SysTick
    // from zeroing `master_secret` while we're holding stack-local
    // copies derived from it.
    let _busy = super::HandlerGuard::enter();

    ui::show_status("Batch sign", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if super::state::peek_state(|s| s.pin_verified.check_sentinel()) != crate::fi::OK_SENTINEL {
        ui::show_status("Batch sign", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ──────────────────────────────
    let payload_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_USEROP_BATCH_HEADER_LEN + SIGN_USEROP_BATCH_TX_PREFIX_LEN
        || total_len > SNAP_LEN
    {
        ui::show_status("Batch sign", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    // HIGH-1 (audit fault-injection 20260611): sentinel-gate the NS-pointer
    // checks so a stuck/corrupted validation result cannot become an accepted
    // pointer. The spatially separate deref-site write-extent gate in §14
    // closes the remaining single-skip path before the first output write.
    crate::fi::scrub_sentinel_register();
    let read_ptr_ok =
        crate::fi::check_true_into_sentinel(|| validate_ns_read_ptr(args.arg0, total_len));
    if read_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Batch sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();
    let write_ptr_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if write_ptr_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Batch sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    //
    // Shared with the sibling sign handlers via `super::SIGN_SNAP_BUF`
    // (one buffer for all three; safe under the non-reentrant dispatcher —
    // see the buffer's doc comment). `total_len` was already gated `>
    // SNAP_LEN` above, and the const assert pins `SNAP_LEN` ≤ the shared
    // buffer, so the slice can never overrun.
    const _: () = assert!(SNAP_LEN <= super::SIGN_SNAP_BUF_LEN);
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    // The pixel UI (`ui-px`) overlays its screen transcript on the shared
    // buffer's tail past THIS request's snapshot (the batch maximum fills the
    // whole buffer, so a request too large to leave room for the transcript
    // is refused on the pixel route — `px_screens_view` → "px scratch").
    let (snap_full, px_scratch) =
        (&mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF)).split_at_mut(total_len);
    #[cfg(not(feature = "ui-px"))]
    let _ = &px_scratch;
    let snap = &mut snap_full[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(payload_ptr.add(i));
    }

    // EntryPoint v0.6 is a frozen wallet/factory domain. The companion field
    // is only an assertion: two independent fail-closed sentinel gates pin it
    // to the firmware constant before any other request field is parsed, and
    // every T1/T2 digest below consumes the constant directly. Thus a skipped
    // reject cannot make hostile wire bytes signing authority, while the
    // second gate still detects a single skip.
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
        ui::show_status("Batch refused", "wrong EntryPoint");
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
        ui::show_status("Batch refused", "wrong EntryPoint");
        return NscStatus::InvalidPointer as u32;
    }
    crate::fi::scrub_sentinel_register();

    // ── 4. Parse fixed header ───────────────────────────────────────
    let chain_id = u64::from_be_bytes([
        snap[0], snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7],
    ]);

    // F-11 hardening (mirroring single-tx `cmd_sign_userop.rs:166-172`):
    // parse `flags` from the snapshot twice with a randomised gap, halt
    // on mismatch. The snapshot lives in S-world SRAM (no NS races), so
    // a divergence between the two reads is necessarily a glitch on the
    // register/load path.
    let flags_a = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    crate::fi::wait_random();
    let flags_b = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_a != flags_b {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let flags = flags_a;
    // Preserve the redundant reads above and independent recheck below, but
    // route bitfield extraction through the same Kani-proven total kernel as
    // the single-UserOp handler.
    let (include_init_code, register_slot, account_index, slot_index) =
        crate::aa::userop::decode_flags(flags);

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

    // Wire-version byte at offset 276 (v2 cutover: see
    // `SIGN_USEROP_BATCH_WIRE_VERSION` doc). Refusing any other value
    // means a stale companion never gets silently mis-parsed.
    let wire_version = snap[276];
    if wire_version != SIGN_USEROP_BATCH_WIRE_VERSION {
        ui::show_status("Batch sign", "bad wire_version");
        return NscStatus::InvalidPointer as u32;
    }
    let batch_count = snap[277] as usize;

    if batch_count == 0 || batch_count > MAX_BATCH_TXS {
        ui::show_status("Batch sign", "bad batch_count");
        return NscStatus::InvalidPointer as u32;
    }

    // F-11 belt-and-braces: re-derive flags + sanity gates from the
    // snapshot (mirroring single-tx `cmd_sign_userop.rs:261-288`). A
    // single-shot fault on the derived values has to land twice — once
    // before each gate — to bypass.
    crate::fi::wait_random();
    let flags_recheck = u32::from_be_bytes([snap[8], snap[9], snap[10], snap[11]]);
    if flags_recheck != flags {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let (include_init_code_r, register_slot_r, account_index_r, slot_index_r) =
        crate::aa::userop::decode_flags(flags_recheck);
    if include_init_code_r != include_init_code
        || register_slot_r != register_slot
        || account_index_r != account_index
        || slot_index_r != slot_index
    {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }

    // Same flag-combination invariants as the single-tx path.
    if include_init_code && register_slot {
        ui::show_status("Batch sign", "incompatible flags");
        return NscStatus::InvalidPointer as u32;
    }
    if include_init_code && slot_index != 0 {
        ui::show_status("Batch sign", "init_code needs slot0");
        return NscStatus::InvalidPointer as u32;
    }
    if register_slot && slot_index == 0 {
        ui::show_status("Batch sign", "register needs slot>=1");
        return NscStatus::InvalidPointer as u32;
    }
    if register_slot && nonce[24..32] == [0xFFu8; 8] {
        ui::show_status("Nonce seq", "overflow");
        return NscStatus::InvalidPointer as u32;
    }
    // Derive the exact batch UserOp nonce before any transaction/final
    // confirmation. REGISTER_SLOT consumes the supplied base nonce with the
    // Type-1 rotation, so the signed Type-2 batch is base+1 in the same lane.
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

    // ── 5. Parse N inner-tx blocks ──────────────────────────────────
    let mut parsed: [Option<ParsedTx>; MAX_BATCH_TXS] = [const { None }; MAX_BATCH_TXS];
    let mut cursor = SIGN_USEROP_BATCH_HEADER_LEN;
    for i in 0..batch_count {
        if cursor + SIGN_USEROP_BATCH_TX_PREFIX_LEN > total_len {
            ui::show_status("Batch sign", "truncated tx");
            return NscStatus::InvalidPointer as u32;
        }
        let mut to = [0u8; 20];
        to.copy_from_slice(&snap[cursor..cursor + 20]);
        cursor += 20;
        let mut value = [0u8; 32];
        value.copy_from_slice(&snap[cursor..cursor + 32]);
        cursor += 32;
        let data_len = u16::from_be_bytes([snap[cursor], snap[cursor + 1]]) as usize;
        cursor += 2;
        if data_len > MAX_TX_LEN || cursor + data_len > total_len {
            ui::show_status("Batch sign", "bad data_len");
            return NscStatus::InvalidPointer as u32;
        }
        let data_off = cursor;
        cursor += data_len;
        parsed[i] = Some(ParsedTx {
            to,
            value,
            data_off,
            data_len,
        });
    }
    // ── 5b. Parse TLV-tagged trailer list (wire v2) ────────────────
    //
    // Every clear-signing kind the single-tx path accepts is also
    // accepted here, routed to inner txs by `tx_idx`. See
    // [`super::batch_trailers`] for the wire format and parse-time
    // refusal table. Trailing-bytes check is enforced inside
    // `parse_batch_trailers` (must consume to `total_len` exactly).
    let parsed_trailers = match parse_batch_trailers(snap, cursor, total_len, batch_count) {
        Ok(p) => p,
        Err(s) => return s,
    };

    // Bind the untrusted wire sender to this mnemonic/account's deterministic
    // CREATE2 address before any trailer verifier or trusted-display page can
    // consume it. Only the derived address is used below, so a fault that
    // skips the rejection cannot make the device sign for another wallet.
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

    // ── 5c. Verify + route trailers per inner-tx ──────────────────
    //
    // For every parsed record, run the kind-appropriate verifier with
    // the same FI-hardened envelope the single-tx path uses
    // (`let ok = verify(...).is_some(); wait_random(); sentinel`).
    // Successful verifications land in `routed[tx_idx].<field>`;
    // verifier failures leave the routed slot empty. For generic metadata
    // that can still degrade safely; ERC-7730 is different: the independently
    // pinned known-call filter inside `pick_sign_pages` hard-refuses a registry-declared
    // tuple whose descriptor slot is empty. CoW v3 and Safe v1 have their own
    // explicit downgrade-mitigation gates later in this loop.
    //
    // Mutual exclusion (curated XOR self-attest per tx_idx) was already
    // enforced at parse time inside `parse_batch_trailers`.
    let mut routed: [Option<RoutedTrailers<'_>>; MAX_BATCH_TXS] = [const { None }; MAX_BATCH_TXS];
    let mut resolver = NameResolver::new();

    for rec_opt in &parsed_trailers.records[..parsed_trailers.count] {
        let rec = match rec_opt.as_ref() {
            Some(r) => r,
            None => continue,
        };
        let bytes: &[u8] = &snap[rec.start..rec.start + rec.len];

        match rec.kind {
            TRAILER_KIND_ERC20 => {
                let meta_opt = verify_erc20_bundle(bytes);
                let ok = meta_opt.is_some();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    continue;
                }
                let meta = meta_opt.unwrap();
                // Store only the Merkle- and chain-verified metadata here.
                // Target attribution is deliberately deferred until render
                // time, after every Safe trailer for this member has either
                // produced a verified context or failed closed. Scanning raw
                // SAFE_V1 bytes here used to let an invalid companion trailer
                // grant metadata authority to an unrelated direct ERC-7730
                // call (RT-ERC20-01).
                if meta.chain_id == chain_id {
                    routed[rec.tx_idx as usize]
                        .get_or_insert_with(RoutedTrailers::empty)
                        .erc20 = Some(meta);
                }
            }
            TRAILER_KIND_COW_ORDER => {
                // Deferred to pass 2 (§5d below). The CoW binding
                // target depends on the Safe context for the same
                // tx_idx — and the matching `safe_v1` record may sit
                // LATER in the companion-supplied record order — so
                // COW_ORDER verification runs only after every other kind
                // has routed. Parse-time validation (kind / tx_idx /
                // length caps / dedup) already happened in
                // `parse_batch_trailers`, so skipping here is safe.
            }
            TRAILER_KIND_SAFE_V1 => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let v_opt = crate::tx::eip712::safe::verify_and_bind_trailer(
                    bytes, inner_data, chain_id, &ptx.to,
                );
                let ok = v_opt.is_some();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    continue;
                }
                routed[rec.tx_idx as usize]
                    .get_or_insert_with(RoutedTrailers::empty)
                    .safe_v1 = v_opt;
            }
            TRAILER_KIND_SEL_CURATED => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let meta_opt = verify_selector_bundle(bytes);
                let ok = meta_opt.is_some();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    continue;
                }
                let meta = meta_opt.unwrap();
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    routed[rec.tx_idx as usize]
                        .get_or_insert_with(RoutedTrailers::empty)
                        .selector = Some(meta);
                }
            }
            TRAILER_KIND_SEL_SELFATTEST => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let meta_opt = parse_self_attest_bundle(bytes);
                let ok = meta_opt.is_some();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    continue;
                }
                let meta = meta_opt.unwrap();
                if inner_data.len() >= 4 && meta.selector == inner_data[..4] {
                    routed[rec.tx_idx as usize]
                        .get_or_insert_with(RoutedTrailers::empty)
                        .selector = Some(meta);
                }
            }
            TRAILER_KIND_ERC7730 => {
                let v_res = crate::tx::erc7730::verify_erc7730_proof_set(
                    bytes,
                    &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
                );
                let ok = v_res.is_ok();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    ui::show_status("Batch sign", "7730 bundle fail");
                    return NscStatus::InvalidPointer as u32;
                }
                let v = v_res.unwrap();
                // Full context/nested binding is deliberately deferred until
                // this member's trusted `Eip1559Tx` exists in the display
                // loop. Until then this rooted set is only a candidate in the
                // secure TOCTOU snapshot, not display authority.
                routed[rec.tx_idx as usize]
                    .get_or_insert_with(RoutedTrailers::empty)
                    .erc7730 = Some(v);
            }
            TRAILER_KIND_NAME => {
                // Batch-wide; tx_idx already validated as 0xff at parse time.
                // Failed bundles silently dropped (address renders as 40-hex,
                // always safe). Capacity is enforced by `NameResolver::push`
                // (it silently no-ops past MAX_NAME_BUNDLES — already
                // capped at parse time by `parse_batch_trailers`).
                if let Some(meta) = verify_name_bundle(bytes) {
                    resolver.push(meta);
                }
            }
            _ => {
                // `parse_batch_trailers` already refused kind == 0 || kind > 8,
                // so reaching here is structurally impossible. Defence in depth:
                // refuse anyway.
                ui::show_status("Batch sign", "kind unreachable");
                return NscStatus::InternalError as u32;
            }
        }
    }

    // ── 5d. Pass 2: verify the deferred COW_ORDER (CoW v3) records ──────
    //
    // Runs after every other kind so the Safe context for the same
    // tx_idx — wherever it sat in the companion's record order — is
    // already in `routed`. Mirrors the single-tx handler's ordering
    // (Safe verifies before the CoW verify) and uses the same
    // `safe::cow_binding` resolver: a Safe-wrapped presign binds the
    // trailer to the SafeTx's inner raw_data with uid.owner == the
    // Safe; everything else binds to the tx's inner calldata with
    // uid.owner == sender.
    for rec_opt in &parsed_trailers.records[..parsed_trailers.count] {
        let rec = match rec_opt.as_ref() {
            Some(r) => r,
            None => continue,
        };
        if rec.kind != TRAILER_KIND_COW_ORDER {
            continue;
        }
        let bytes: &[u8] = &snap[rec.start..rec.start + rec.len];
        let idx = rec.tx_idx as usize;
        let ptx = parsed[idx].as_ref().unwrap();
        let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
        // Exec context via a cheap pure ABI decode (no keccak). The render
        // loop recomputes the same decode later;
        // doubling it for the one CoW-wrapped tx beats threading a
        // MAX_BATCH_TXS-sized context array through the handler.
        let mut safe_exec_claim = crate::tx::eip712::safe::ExecClaimReceipt::fail_closed();
        let mut safe_exec_claim_cfi = crate::fi::CfiCounter::new();
        // SAFETY: caller-owned initialized receipt; a skipped proof call must
        // leave the volatile fail state materialized.
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
        let mut safe_exec_ctx: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
        let mut safe_exec_ctx_check: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> = None;
        let mut safe_exec_verify_cfi_a = crate::fi::CfiCounter::new();
        let mut safe_exec_verify_cfi_b = crate::fi::CfiCounter::new();
        // SAFETY: distinct initialized caller-owned outputs. Skipped verifier
        // calls leave `None` and their CFI counters short.
        unsafe {
            core::ptr::write_volatile(&mut safe_exec_ctx, None);
            core::ptr::write_volatile(&mut safe_exec_ctx_check, None);
        }
        crate::tx::eip712::safe::verify_and_bind_exec_into(
            inner_data,
            chain_id,
            &ptx.to,
            &mut safe_exec_ctx,
            &mut safe_exec_verify_cfi_a,
        );
        crate::fi::wait_random();
        crate::tx::eip712::safe::verify_and_bind_exec_into(
            inner_data,
            chain_id,
            &ptx.to,
            &mut safe_exec_ctx_check,
            &mut safe_exec_verify_cfi_b,
        );
        // Do not let a malformed Safe claim get reinterpreted as a direct CoW
        // route merely because this pass resolves a CoW trailer first. Two
        // spatially separate checks make a single skipped reject insufficient.
        crate::fi::scrub_sentinel_register();
        let safe_claim_cfi_verdict_a = safe_exec_claim_cfi
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_verify_a_cfi_verdict_a = safe_exec_verify_cfi_a
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_verify_b_cfi_verdict_a = safe_exec_verify_cfi_b
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_resolution_verdict_a = crate::tx::eip712::safe::exec_claim_resolution_proof(
            &safe_exec_claim,
            safe_exec_ctx.as_ref(),
            safe_exec_ctx_check.as_ref(),
        );
        if safe_claim_cfi_verdict_a != crate::fi::OK_SENTINEL
            || safe_verify_a_cfi_verdict_a != crate::fi::OK_SENTINEL
            || safe_verify_b_cfi_verdict_a != crate::fi::OK_SENTINEL
            || safe_resolution_verdict_a != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "exec parse fail");
            return NscStatus::InvalidPointer as u32;
        }
        crate::fi::scrub_sentinel_register();
        crate::fi::wait_random();
        let safe_claim_cfi_verdict_b = safe_exec_claim_cfi
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_verify_a_cfi_verdict_b = safe_exec_verify_cfi_a
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_verify_b_cfi_verdict_b = safe_exec_verify_cfi_b
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_VERIFY_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let safe_resolution_verdict_b = crate::tx::eip712::safe::exec_claim_resolution_proof(
            &safe_exec_claim,
            safe_exec_ctx.as_ref(),
            safe_exec_ctx_check.as_ref(),
        );
        if safe_claim_cfi_verdict_b != crate::fi::OK_SENTINEL
            || safe_verify_a_cfi_verdict_b != crate::fi::OK_SENTINEL
            || safe_verify_b_cfi_verdict_b != crate::fi::OK_SENTINEL
            || safe_resolution_verdict_b != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "exec parse fail");
            return NscStatus::InvalidPointer as u32;
        }
        crate::fi::scrub_sentinel_register();
        let cow_bind = crate::tx::eip712::safe::resolve_cow_binding(
            inner_data,
            &sender,
            routed[idx].as_ref().and_then(|r| r.safe_v1.as_ref()),
            safe_exec_ctx.as_ref(),
        );
        let v_opt = crate::tx::eip712::cowswap::verify_and_bind_trailer(
            bytes,
            cow_bind.calldata,
            chain_id,
            &cow_bind.owner,
        );
        let ok = v_opt.is_some();
        crate::fi::wait_random();
        if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
            != crate::fi::OK_SENTINEL
        {
            continue;
        }
        routed[idx]
            .get_or_insert_with(RoutedTrailers::empty)
            .cow_order = v_opt;
    }

    // ── 6. Per-tx clear-signing confirm ─────────────────────────────
    //
    // Slot rotation is its own affirmative-consent step ahead of the
    // per-tx loop: when `FLAG_REGISTER_SLOT` is set the firmware also
    // emits a Type 1 `addOwnerBytes` UserOp that consumes one of the
    // wallet's `MAX_BOOTSTRAP_USES` budget items on chain. The cap
    // applies to the whole batch (one Type 1 per sign call), so we
    // gate it once before any inner-tx render.
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
            ui::show_status("Batch sign", "signer unshown");
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
            ui::show_status("Batch sign", "signer unshown");
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
            ui::show_status("Batch sign", "lane unshown");
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
            ui::show_status("Batch sign", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        // Bind the three signed gas limits (F10) — mirrors cmd_sign_userop.rs.
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
            ui::show_status("Batch sign", "gas unshown");
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
            ui::show_status("Batch sign", "gas unshown");
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
            ui::show_status("Batch sign", "gas conflict");
            return NscStatus::InternalError as u32;
        }
        // Pixel trusted UI (`ui-px`): the rotation consent, as in the single
        // handler (`px_confirm_rotation`).
        #[cfg(feature = "ui-px")]
        let px = {
            let zero32 = [0u8; 32];
            let display_tx = Eip1559Tx::default();
            let facts = crate::tx::display::TrailerFacts {
                tx: &display_tx,
                legacy_fee_required: false,
                paymaster_and_data_hash: &paymaster_and_data_hash,
                account_index,
                sender: &sender,
                target: &sender,
                nonce: &nonce,
                call_gas: &call_gas_limit,
                verification_gas: &verification_gas_limit,
                pre_verification_gas: &pre_verification_gas,
                fingerprint: crate::tx::display::erc8213::Kind::CalldataDigest(zero32),
                deployment: None,
                set: crate::tx::display::TrailerSet::Rotation,
                fingerprint2: None,
                offchain: None,
            };
            Some(super::px_confirm_rotation(&mut *px_scratch, &rotate_pages, chain_id, slot_index, &facts))
        };
        #[cfg(not(feature = "ui-px"))]
        let px: Option<Result<(ConfirmResult, u32), &'static str>> = None;
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        let px_route = px.is_some();
        let (cr, cr_verdict) = match px {
            Some(Ok(r)) => r,
            Some(Err(reason)) => {
                ui::show_status("Sign refused", reason);
                return NscStatus::InternalError as u32;
            }
            None => confirm_checked(rotate_pages.as_slice()),
        };
        match cr {
            ConfirmResult::Confirmed => {
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
        // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail closed.
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
    }

    // For each member: render the same pages the single-tx path would render
    // from its routed trailers. A genuinely unknown tuple may use the basic
    // value/ERC-20/typed/blind ladder; a firmware-known ERC-7730 tuple without
    // its verified routed proof is refused inside `pick_sign_pages`.
    // wrap with a "BATCH SIGN | Tx i of N" banner, and require an
    // affirmative long-right confirm. Cancel anywhere → abort the
    // entire signing operation; idle wipe → zero secrets.
    //
    // Display-time fields (gas, nonce) come from the outer UserOp; per
    // member we vary only `(to, value, data_len, signing_hash)`.
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

    // `resolver` and `routed` were populated above from the TLV
    // trailer list. Resolver is batch-wide (every render call shares
    // it); `routed[i]` carries the per-tx verified slots.

    // Ordered, fixed-frame tuple commitments recorded only after each member's
    // affirmative UI sentinel. Unlike the historical data-only digest, each
    // member binds its index, target, value and ERC-8213 calldata digest.
    let mut confirmed_member_commitments = [[0u8; 32]; MAX_BATCH_TXS];
    let mut member_confirm_receipt = crate::tx::display::batch::BatchMemberConfirmReceipt::new();
    member_confirm_receipt.fail_initialize();

    for i in 0..batch_count {
        let ptx = parsed[i].as_ref().unwrap();
        let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];

        let tx_for_display = Eip1559Tx {
            chain_id,
            nonce: display_nonce,
            max_priority_fee_per_gas: display_max_prio,
            max_fee_per_gas: display_max_fee,
            gas_limit: display_gas_limit,
            to: Some(ptx.to),
            value: U256(ptx.value),
            data_len: ptx.data_len,
            access_list_count: 0,
            signing_hash: [0u8; 32],
            userop_fields: Some(UserOpDisplayFields {
                // Bind every member display to the nonce of the Type-2 batch
                // being authorized.  In REGISTER_SLOT mode the base nonce is
                // consumed by Type 1 and the batch signs at base+1.
                nonce: U256(type2_nonce),
                call_gas_limit: U256(call_gas_limit),
                verification_gas_limit: U256(verification_gas_limit),
                pre_verification_gas: U256(pre_verification_gas),
            }),
        };

        // ── Per-tx downgrade-mitigation gates ──────────────────────
        //
        // Mirroring single-tx `cmd_sign_userop.rs:789-806`. If an inner
        // calldata claims `setPreSignature` on the GPv2 settlement
        // contract, the matching native CoW order trailer is mandatory — without
        // it the user would otherwise confirm the weaker static "Pre-
        // sign CowSwap order" string and end up signing an orderUid
        // they never saw the contents of. Same logic for Safe
        // `approveHash`: without the safe_v1 trailer a hostile NS
        // could coerce blind-signing a bytes32 with no SafeTx
        // visibility.
        let cow_selector = inner_data.len() >= 4 && &inner_data[..4] == SET_PRE_SIGNATURE_SELECTOR;
        let cow_target = ptx.to == GPV2_SETTLEMENT_ADDRESS;
        if cow_selector
            && cow_target
            && routed[i]
                .as_ref()
                .and_then(|r| r.cow_order.as_ref())
                .is_none()
        {
            ui::show_status("CoW sign", "v3 required (batch)");
            return NscStatus::InvalidPointer as u32;
        }
        // Keyed on the SELECTOR ALONE — the batch twin of the single-tx
        // approveHash gate. `Safe.approveHash(bytes32)` ignores trailing
        // calldata on-chain, so an exact `len == 36` test was bypassable
        // with one padding byte → generic blind-sign of an invisible SafeTx
        // pre-approval (audit 2026-06-28). `is_approve_hash_claim` is the
        // SAME shared predicate the single-tx handler uses, so the two
        // cannot drift.
        if crate::tx::eip712::safe::is_approve_hash_claim(inner_data)
            && routed[i]
                .as_ref()
                .and_then(|r| r.safe_v1.as_ref())
                .is_none()
        {
            ui::show_status("Safe sign", "safe_v1 required (batch)");
            return NscStatus::InvalidPointer as u32;
        }

        // Routed-trailer pass-through: every per-tx slot the single-tx
        // handler passes is mirrored here from `routed[i]`. Empty slots for
        // genuinely unknown tuples may reach lower-priority renderers; an
        // empty ERC-7730 slot for a firmware-known tuple is refused by the
        // dispatcher's membership gate.
        let r = routed[i].as_ref();
        // Safe `execTransaction` decode is purely a function of
        // `inner_data` (no trailer needed), so we run it per inner-tx
        // inline rather than threading a new routed-trailer slot
        // through. Selector + DelegateCall gate matches the single-tx
        // handler's behaviour in `cmd_sign_userop`.
        let mut safe_exec_claim = crate::tx::eip712::safe::ExecClaimReceipt::fail_closed();
        let mut safe_exec_claim_cfi = crate::fi::CfiCounter::new();
        // SAFETY: caller-owned initialized receipt; a skipped proof call must
        // leave the volatile fail state materialized.
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
        let mut safe_exec_verified_check: Option<crate::tx::eip712::safe::VerifiedSafeExec<'_>> =
            None;
        let mut safe_exec_verify_cfi_a = crate::fi::CfiCounter::new();
        let mut safe_exec_verify_cfi_b = crate::fi::CfiCounter::new();
        // SAFETY: distinct initialized caller-owned outputs. Skipped verifier
        // calls leave `None` and their CFI counters short.
        unsafe {
            core::ptr::write_volatile(&mut safe_exec_verified, None);
            core::ptr::write_volatile(&mut safe_exec_verified_check, None);
        }
        crate::tx::eip712::safe::verify_and_bind_exec_into(
            inner_data,
            chain_id,
            &ptx.to,
            &mut safe_exec_verified,
            &mut safe_exec_verify_cfi_a,
        );
        crate::fi::wait_random();
        crate::tx::eip712::safe::verify_and_bind_exec_into(
            inner_data,
            chain_id,
            &ptx.to,
            &mut safe_exec_verified_check,
            &mut safe_exec_verify_cfi_b,
        );

        // Selector ownership is independent of ABI length. Resolve the proved
        // class against the strict decoder twice before ERC-20, ERC-7730,
        // selector-name, typed-call, or generic blind routing.
        crate::fi::scrub_sentinel_register();
        let safe_claim_cfi_verdict_a = safe_exec_claim_cfi
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
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
            ui::show_status("Batch sign", "exec parse fail");
            return NscStatus::InvalidPointer as u32;
        }
        crate::fi::scrub_sentinel_register();
        crate::fi::wait_random();
        let safe_claim_cfi_verdict_b = safe_exec_claim_cfi
            .check_into_sentinel(crate::tx::eip712::safe::EXEC_CLAIM_CFI_EXPECTED);
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
            ui::show_status("Batch sign", "exec parse fail");
            return NscStatus::InvalidPointer as u32;
        }
        crate::fi::scrub_sentinel_register();

        // `r.erc20` is Merkle- and chain-verified. The display dispatcher
        // grants it only against signed facts of the selected surface:
        // outer target, verified descriptor tokenPath, or verified Safe
        // direct/pinned-MultiSend target. Invalid raw Safe trailers never
        // participate, while legitimate direct ERC-7730 protocol calls keep
        // their friendly metadata.
        let chain_verified_erc20 = r.and_then(|r| r.erc20.as_ref());

        // MultiSend gate — same shared decision as the single-tx
        // handler (`multisend_sign_gate`): a verified Safe context
        // whose inner call claims an allowlisted MultiSendCallOnly
        // DELEGATECALL must pass every hard rule and fit the trusted-
        // display page budget, else refuse the whole batch. Reserved
        // pages here: the dispatcher's native-value page when this
        // member carries ETH, the two ERC-8213 fingerprint pages, the batch
        // banner page, mandatory full signer + target pages, worst-case
        // non-zero nonce-lane page, the mandatory UserOp gas-triple page (F10),
        // and the two gas/fee pages the dispatcher splices for the Safe surface
        // (audit 2026-06-19).
        {
            let reserved = usize::from(ptx.value.iter().any(|&b| b != 0))
                + 2
                + 1
                + crate::tx::display::SIGNER_IDENTITY_PAGES
                + crate::tx::display::TARGET_IDENTITY_PAGES
                + crate::tx::display::NONZERO_NONCE_LANE_PAGES
                + crate::tx::display::USEROP_GAS_PAGES
                + 2;
            match crate::tx::display::multisend_sign_gate(
                routed[i].as_ref().and_then(|r| r.safe_v1.as_ref()),
                safe_exec_verified.as_ref(),
                routed[i].as_ref().and_then(|r| r.cow_order.as_ref()),
                reserved,
            ) {
                crate::tx::display::MultisendGate::Reject(reason) => {
                    ui::show_status("Batch sign", reason);
                    return NscStatus::InvalidPointer as u32;
                }
                crate::tx::display::MultisendGate::NotMultiSend
                | crate::tx::display::MultisendGate::Ok => {}
            }
        }

        // Safe-wrapped CoW presign gate — twin of the direct gate
        // above and of the single-tx handler's `cow_bind.via_safe`
        // gate. The predicate is the SAME resolver pass 2 used to pick
        // the v3 binding target, so gate and verify cannot drift: when
        // a verified Safe context's inner call claims setPreSignature
        // on the GPv2 settlement, a verified v3 trailer is mandatory
        // for this tx — no blind-sign fallback.
        let safe_wrapped_cow = crate::tx::eip712::safe::resolve_cow_binding(
            inner_data,
            &sender,
            routed[i].as_ref().and_then(|r| r.safe_v1.as_ref()),
            safe_exec_verified.as_ref(),
        )
        .via_safe;
        if safe_wrapped_cow
            && routed[i]
                .as_ref()
                .and_then(|r| r.cow_order.as_ref())
                .is_none()
        {
            ui::show_status("CoW sign", "v3 required (batch)");
            return NscStatus::InvalidPointer as u32;
        }
        // Direct-path CoW target gate (audit 2026-06-26 — direct-path target
        // unshown), the batch twin of the single-tx gate. A verified DIRECT
        // (non-Safe-wrapped) v3 order renders via `render_cowswap_pages`,
        // which shows the order but NOT this member's call target `ptx.to`;
        // the signed `executeBatchWithOffchainCount(...)` forwards
        // `ptx.to.call{value}(data)`. Unless that target IS the GPv2
        // settlement singleton, refuse the whole atomic batch rather than
        // sign a member whose attacker-chosen destination the CoW screen
        // never showed.
        if !crate::tx::eip712::safe::direct_cow_target_ok(
            routed[i]
                .as_ref()
                .and_then(|r| r.cow_order.as_ref())
                .is_some(),
            safe_wrapped_cow,
            &ptx.to,
        ) {
            ui::show_status("CoW sign", "bad target (batch)");
            return NscStatus::InvalidPointer as u32;
        }

        // Bind this member's complete proof set only after its exact signed
        // display context exists. The pure expectation is followed by two
        // independent whole-payload reparses and nested derivations inside the
        // non-inlined proof helper. Any present invalid evidence refuses the
        // complete batch instead of disappearing into a weaker fallback.
        let (erc7730_verified, erc7730_nested_binding) = if let Some(set) =
            r.and_then(|r| r.erc7730.as_ref())
        {
            let expected_nested = match crate::tx::erc7730::derive_nested_call(
                &tx_for_display,
                inner_data,
                set,
                &sender,
            ) {
                Ok(binding) => binding,
                Err(_) => {
                    ui::show_status("Batch sign", "7730 binding fail");
                    return NscStatus::InvalidPointer as u32;
                }
            };

            let mut bind_verdict_slot = 0u32;
            // SAFETY: unique local; volatile FAIL survives LTO if the proof
            // call is fault-skipped.
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
                ui::show_status("Batch sign", "7730 binding fail");
                return NscStatus::InternalError as u32;
            }

            crate::fi::wait_random();
            core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
            // SAFETY: same live local, independently re-read after the gap.
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
                ui::show_status("Batch sign", "7730 binding fail");
                return NscStatus::InternalError as u32;
            }

            (Some(set), expected_nested)
        } else {
            (None, None)
        };

        let legacy_fee_pages_required = crate::tx::display::legacy_fee_pages_required(
            r.and_then(|r| r.cow_order.as_ref()).is_some(),
            r.and_then(|r| r.safe_v1.as_ref()).is_some(),
            safe_exec_verified.is_some(),
        );
        let mut dispatch_page_proofs = crate::tx::display::DispatchPageProofs::new();
        dispatch_page_proofs.fail_initialize();
        let inner_pages = match pick_sign_pages_with_erc7730_evidence(
            &tx_for_display,
            inner_data,
            &sender,
            r.and_then(|r| r.cow_order.as_ref()),
            r.and_then(|r| r.safe_v1.as_ref()),
            safe_exec_verified.as_ref(),
            erc7730_verified,
            erc7730_nested_binding.as_ref(),
            chain_verified_erc20,
            r.and_then(|r| r.selector.as_ref()),
            &resolver,
            &mut dispatch_page_proofs,
        ) {
            Ok(p) => p,
            // Fail closed for any mandatory render failure: native-value/gas
            // budget, Safe accounting, a verified ERC-7730 descriptor that
            // cannot render exactly, or a firmware-known call whose proof was
            // omitted / malformed / mis-bound. Never downgrade these cases.
            Err(()) => {
                ui::show_status("Batch sign", "render refused");
                return NscStatus::InternalError as u32;
            }
        };
        // Fail closed if the per-tx renderer ate the banner budget (F5):
        // signing without the "BATCH SIGN | Tx i of N" anchor would release a
        // Type-2 sig over a member the user couldn't place in the batch.
        let mut pages = crate::tx::display::Pages::empty_with_len(0);
        let mut banner_cfi = crate::fi::CfiCounter::new();
        if wrap_pages_with_batch_banner(&inner_pages, i, batch_count, &mut pages, &mut banner_cfi)
            .is_err()
        {
            ui::show_status("Batch sign", "banner unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let banner_cfi_verdict =
            banner_cfi.check_into_sentinel(crate::tx::display::batch::BATCH_BANNER_CFI_EXPECTED);
        // F-15.r1: a skipped second sentinel-returning call must not inherit
        // the CFI check's OK value from the AAPCS return register.
        crate::fi::scrub_sentinel_register();
        let banner_copy_verdict = crate::tx::display::batch::batch_banner_copy_proof(
            &inner_pages,
            &pages,
            i,
            batch_count,
        );
        if banner_cfi_verdict != crate::fi::OK_SENTINEL
            || banner_copy_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "banner incomplete");
            return NscStatus::InternalError as u32;
        }
        if dispatch_page_proofs.shift_indices(1).is_err() {
            ui::show_status("Batch sign", "proof index overflow");
            return NscStatus::InternalError as u32;
        }
        // The batch banner anchors the member position. The signer is appended
        // after the complete wrapped renderer transcript and identifies the
        // already-bound derived sender, never the companion wire field.
        let signer_pages_before = pages.len;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_from_page(
            &mut pages,
            account_index,
            &sender,
            &mut signer_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let signer_cfi_verdict =
            signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let signer_page_verdict = crate::tx::display::from_page_proof(
            &pages,
            signer_pages_before,
            account_index,
            &sender,
        );
        if signer_cfi_verdict != crate::fi::OK_SENTINEL
            || signer_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        // Each member gets its own exact outer target page. A final batch
        // summary does not repeat targets because every member was already
        // individually confirmed above.
        let target_pages_before = pages.len;
        let mut target_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_target_page(&mut pages, &ptx.to, &mut target_cfi).is_err() {
            ui::show_status("Batch sign", "target unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let target_cfi_verdict =
            target_cfi.check_into_sentinel(crate::tx::display::TARGET_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let target_page_verdict =
            crate::tx::display::target_page_proof(&pages, target_pages_before, &ptx.to);
        if target_cfi_verdict != crate::fi::OK_SENTINEL
            || target_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "target unshown");
            return NscStatus::InternalError as u32;
        }

        let nonce_lane_pages_before = pages.len;
        let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_nonce_lane_page(
            &mut pages,
            &type2_nonce,
            &mut nonce_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let nonce_lane_cfi_verdict =
            nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let nonce_lane_page_verdict = crate::tx::display::nonce_lane_page_proof(
            &pages,
            nonce_lane_pages_before,
            &type2_nonce,
        );
        if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        // Bind the three signed gas limits (F10) — mirrors cmd_sign_userop.rs.
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
            ui::show_status("Batch sign", "gas unshown");
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
            ui::show_status("Batch sign", "gas unshown");
            return NscStatus::InternalError as u32;
        }

        // Per-tx ERC-8213 fingerprint. The user sees one fingerprint
        // per inner call; a separate batch-final fingerprint binds
        // the whole bundle below.
        let inner_digest = pqsigner_tx_core::erc8213::calldata_digest(inner_data);
        let fingerprint_pages_before = pages.len;
        let fingerprint_kind = crate::tx::display::erc8213::Kind::CalldataDigest(inner_digest);
        let mut fingerprint_cfi = crate::fi::CfiCounter::new();
        // Fail closed if the fingerprint page can't be appended (F5): the
        // digest ties the displayed intent to the signed calldata; dropping
        // it silently and signing anyway breaks that binding.
        if crate::tx::display::erc8213::append_fingerprint_page(
            &mut pages,
            fingerprint_kind,
            &mut fingerprint_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "digest unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let fingerprint_cfi_verdict = fingerprint_cfi
            .check_into_sentinel(crate::tx::display::erc8213::FINGERPRINT_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let fingerprint_page_verdict = crate::tx::display::erc8213::fingerprint_page_proof(
            &pages,
            fingerprint_pages_before,
            fingerprint_kind,
        );
        if fingerprint_cfi_verdict != crate::fi::OK_SENTINEL
            || fingerprint_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "digest incomplete");
            return NscStatus::InternalError as u32;
        }
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
            ui::show_status("Batch sign", "gas conflict");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let mut dispatch_final_verdict_slot = 0u32;
        // SAFETY: unique live local. Volatile FAIL initialization ensures a
        // skipped final-proof call cannot authorize this batch member.
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
        // SAFETY: the slot remains live and has no concurrent writer.
        let dispatch_final_verdict_a =
            unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
        crate::fi::scrub_sentinel_register();
        let dispatch_final_gate_a = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(dispatch_final_verdict_a == crate::fi::OK_SENTINEL)
        });
        crate::fi::scrub_sentinel_register();
        if dispatch_final_gate_a != crate::fi::OK_SENTINEL {
            ui::show_status("Batch sign", "value/fee conflict");
            return NscStatus::InternalError as u32;
        }
        crate::fi::wait_random();
        core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
        // SAFETY: second independent volatile read after a randomized gap.
        let dispatch_final_verdict_b =
            unsafe { core::ptr::read_volatile(&dispatch_final_verdict_slot) };
        crate::fi::scrub_sentinel_register();
        let dispatch_final_gate_b = crate::fi::check_true_into_sentinel(|| {
            core::hint::black_box(dispatch_final_verdict_b == crate::fi::OK_SENTINEL)
        });
        crate::fi::scrub_sentinel_register();
        if dispatch_final_gate_b != crate::fi::OK_SENTINEL {
            ui::show_status("Batch sign", "value/fee conflict");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        if crate::tx::display::erc8213::fingerprint_final_set_proof(
            &pages,
            fingerprint_pages_before,
            fingerprint_kind,
        ) != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "digest changed");
            return NscStatus::InternalError as u32;
        }
        // Pixel trusted UI (`ui-px`): the member's own route body (the same
        // precedence as the single handler: Safe, direct CoW, ERC-7730, the
        // single-UserOp ladder) with the batch position right after its
        // hero, and the member trailers, bound to the proven `pages`.
        #[cfg(feature = "ui-px")]
        let px = {
            use crate::tx::display::px_lift::Body;
            let safe_v1 = r.and_then(|r| r.safe_v1.as_ref());
            let cow = r.and_then(|r| r.cow_order.as_ref());
            let facts = crate::tx::display::TrailerFacts {
                tx: &tx_for_display,
                legacy_fee_required: legacy_fee_pages_required,
                paymaster_and_data_hash: &paymaster_and_data_hash,
                account_index,
                sender: &sender,
                target: &ptx.to,
                nonce: &type2_nonce,
                call_gas: &call_gas_limit,
                verification_gas: &verification_gas_limit,
                pre_verification_gas: &pre_verification_gas,
                fingerprint: fingerprint_kind,
                deployment: None,
                set: crate::tx::display::TrailerSet::BatchMember,
                fingerprint2: None,
                offchain: None,
            };
            let inner = if safe_v1.is_some() || safe_exec_verified.is_some() {
                Body::Safe {
                    safe_v1,
                    safe_exec: safe_exec_verified.as_ref(),
                    cow,
                    erc20: crate::tx::display::safe_route_meta(
                        chain_id,
                        safe_v1,
                        safe_exec_verified.as_ref(),
                        chain_verified_erc20,
                    ),
                    resolver: &resolver,
                }
            } else if let Some(v3) = cow {
                Body::Cow { v3 }
            } else if erc7730_verified.is_some() {
                let tail = crate::tx::display::expected_trailer_count(&facts);
                Body::Erc7730 {
                    pages: &pages,
                    start: 1,
                    body_len: pages.len.saturating_sub(1 + tail),
                    chain_id,
                    family: crate::tx::display::erc7730_screens::family(
                        crate::tx::display::erc7730_screens::Surface::Contract,
                        &ptx.to,
                    ),
                }
            } else {
                Body::UserOp(crate::tx::display::userop_screens::UserOpInputs {
                    tx: &tx_for_display,
                    inner_data,
                    erc20: chain_verified_erc20,
                    selector: r.and_then(|r| r.selector.as_ref()),
                    resolver: &resolver,
                })
            };
            let inputs = crate::tx::display::px_lift::ContentInputs {
                body: Body::BatchMember {
                    index: i,
                    total: batch_count,
                    inner: &inner,
                },
                trailers: &facts,
            };
            Some(super::px_confirm(&mut *px_scratch, &pages, &inputs))
        };
        #[cfg(not(feature = "ui-px"))]
        let px: Option<Result<(ConfirmResult, u32), &'static str>> = None;
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        let px_route = px.is_some();
        let (cr, cr_verdict) = match px {
            Some(Ok(r)) => r,
            Some(Err(reason)) => {
                ui::show_status("Sign refused", reason);
                return NscStatus::InternalError as u32;
            }
            None => confirm_checked(pages.as_slice()),
        };
        match cr {
            ConfirmResult::Confirmed => {
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
        // Between members the pixel route says where the batch stands —
        // CONFIRMED, never SIGNED: nothing is signed before the final ask.
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        if px_route && i + 1 < batch_count {
            crate::ui::px::lcd::set_film_look(
                pqsigner_ui_px::Look::plain(pqsigner_ui_px::Icon::Eth),
                crate::tx::display::batch_screens::member_confirmed_caption(i, batch_count),
                b"BATCH DECLINED",
            );
            crate::ui::px::lcd::show_ending(pqsigner_ui_px::scene::Ending::Signed);
        }
        // FI belt (UI1 / work-todo #12c): per-tx affirmative-sentinel gate. A
        // belt trip aborts the WHOLE batch (return), never falls to the next tx.
        if cr_verdict != crate::fi::OK_SENTINEL {
            super::zeroize_sensitive_state();
            return NscStatus::UserRejected as u32;
        }
        // Only the affirmative sentinel may advance the ordered member
        // transcript. The independently recomputed tuple commitment and
        // receipt gate below detect a skipped update or early loop exit.
        let Some(member_commitment) =
            batch_member_commitment(i, &ptx.to, &ptx.value, &inner_digest)
        else {
            ui::show_status("Batch sign", "commit failed");
            return NscStatus::InternalError as u32;
        };
        confirmed_member_commitments[i] = member_commitment;
        if member_confirm_receipt.record_confirmed(i).is_err() {
            ui::show_status("Batch sign", "confirm sequence");
            return NscStatus::InternalError as u32;
        }
    }

    // Deployment is authorized once at the whole-batch boundary. Its receipt
    // binds the exact public mode/factory context and remains fail-initialized
    // until the final summary confirmation succeeds.
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
    // Whether the pixel UI owned the final ask (and so plays the signing film
    // and the ending).
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    let mut px_owns_ending = false;

    // ── 6b. Final summary confirm + batch-final fingerprint ────────
    //
    // Prove that the loop reached every freshly pinned member and that its
    // running tuple commitment equals an independent second pass over every
    // parsed member's index, target, value and calldata digest. A skipped
    // loop-back branch yields a short receipt and subset commitment; neither
    // can reach the final whole-batch confirmation.
    // SAFETY: the validated snapshot contains byte 277 for the handler's
    // lifetime and is immutable after acquisition.
    let pinned_batch_count_a = unsafe { core::ptr::read_volatile(snap.as_ptr().add(277)) };
    crate::fi::wait_random();
    let pinned_batch_count_b = unsafe { core::ptr::read_volatile(snap.as_ptr().add(277)) };
    let pinned_count_ok = pinned_batch_count_a as usize == batch_count
        && pinned_batch_count_b as usize == batch_count
        && pinned_batch_count_a == pinned_batch_count_b
        && batch_count != 0
        && batch_count <= MAX_BATCH_TXS;
    crate::fi::scrub_sentinel_register();
    let pinned_count_verdict =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(pinned_count_ok));
    crate::fi::scrub_sentinel_register();
    let member_confirm_verdict = member_confirm_receipt.completion_proof(batch_count);

    let Some(running_batch_final) =
        batch_tuple_commitment_from_members(&confirmed_member_commitments[..batch_count])
    else {
        ui::show_status("Batch sign", "commit failed");
        return NscStatus::InternalError as u32;
    };
    let mut recomputed_members = [[0u8; 32]; MAX_BATCH_TXS];
    for member_index in 0..batch_count {
        let ptx = parsed[member_index].as_ref().unwrap();
        let inner_data = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
        let inner_digest = pqsigner_tx_core::erc8213::calldata_digest(inner_data);
        let Some(member_commitment) =
            batch_member_commitment(member_index, &ptx.to, &ptx.value, &inner_digest)
        else {
            ui::show_status("Batch sign", "commit failed");
            return NscStatus::InternalError as u32;
        };
        recomputed_members[member_index] = member_commitment;
    }
    let Some(recomputed_batch_final) =
        batch_tuple_commitment_from_members(&recomputed_members[..batch_count])
    else {
        ui::show_status("Batch sign", "commit failed");
        return NscStatus::InternalError as u32;
    };
    let batch_tuple_matches = running_batch_final
        .ct_eq(&recomputed_batch_final)
        .unwrap_u8()
        == 1;
    crate::fi::scrub_sentinel_register();
    let batch_tuple_verdict =
        crate::fi::check_true_into_sentinel(|| core::hint::black_box(batch_tuple_matches));
    if pinned_count_verdict != crate::fi::OK_SENTINEL
        || member_confirm_verdict != crate::fi::OK_SENTINEL
        || batch_tuple_verdict != crate::fi::OK_SENTINEL
    {
        ui::show_status("Batch sign", "members incomplete");
        return NscStatus::InternalError as u32;
    }
    let batch_final = recomputed_batch_final;
    {
        let mut final_pages = build_final_summary_pages(batch_count);
        // Paymaster WYSIWYS gate (audit 2026-06-27). `paymaster_and_data_hash`
        // is folded into the signed sphincs digest (§"Type 2" below), so the
        // batch signature commits to whatever paymaster the companion chose,
        // yet no renderer surfaces it. It is a single UserOp-level field
        // (one paymaster for the whole batch), so it is shown ONCE here on the
        // final-summary pages rather than once per inner tx. FI-hardened
        // (sentinel skip-on-empty) and fails CLOSED — refuse the whole atomic
        // batch rather than sign a sponsor the user never saw.
        let paymaster_pages_before = final_pages.len;
        let mut paymaster_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_paymaster_page(
            &mut final_pages,
            &paymaster_and_data_hash,
            &mut paymaster_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "paymaster unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let paymaster_cfi_verdict =
            paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let paymaster_page_verdict = crate::tx::display::paymaster_page_proof(
            &final_pages,
            paymaster_pages_before,
            &paymaster_and_data_hash,
        );
        if paymaster_cfi_verdict != crate::fi::OK_SENTINEL
            || paymaster_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "paymaster unshown");
            return NscStatus::InternalError as u32;
        }
        // Repeat signer identity on the final whole-batch authorization, so
        // no confirmation screen is account-ambiguous even if the user jumps
        // directly to the last gate after reviewing the members.
        let signer_pages_before = final_pages.len;
        let mut signer_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_from_page(
            &mut final_pages,
            account_index,
            &sender,
            &mut signer_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let signer_cfi_verdict =
            signer_cfi.check_into_sentinel(crate::tx::display::SIGNER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let signer_page_verdict = crate::tx::display::from_page_proof(
            &final_pages,
            signer_pages_before,
            account_index,
            &sender,
        );
        if signer_cfi_verdict != crate::fi::OK_SENTINEL
            || signer_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "signer unshown");
            return NscStatus::InternalError as u32;
        }
        let nonce_lane_pages_before = final_pages.len;
        let mut nonce_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_nonce_lane_page(
            &mut final_pages,
            &type2_nonce,
            &mut nonce_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let nonce_lane_cfi_verdict =
            nonce_lane_cfi.check_into_sentinel(crate::tx::display::NONCE_LANE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let nonce_lane_page_verdict = crate::tx::display::nonce_lane_page_proof(
            &final_pages,
            nonce_lane_pages_before,
            &type2_nonce,
        );
        if nonce_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || nonce_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "lane unshown");
            return NscStatus::InternalError as u32;
        }
        // Bind the three signed gas limits (F10) — mirrors cmd_sign_userop.rs.
        let gas_lane_pages_before = final_pages.len;
        let mut gas_lane_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_userop_gas_page(
            &mut final_pages,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
            &mut gas_lane_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_page_verdict = crate::tx::display::userop_gas_page_proof(
            &final_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "gas unshown");
            return NscStatus::InternalError as u32;
        }
        // Fail closed if the batch-final fingerprint can't be appended (F5):
        // it binds the complete ordered `(index,target,value,data-digest)`
        // member set and count to the single sig the user is about to authorise.
        let fingerprint_pages_before = final_pages.len;
        let fingerprint_kind = crate::tx::display::erc8213::Kind::Raw32(batch_final);
        let mut fingerprint_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::erc8213::append_fingerprint_page(
            &mut final_pages,
            fingerprint_kind,
            &mut fingerprint_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "digest unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let fingerprint_cfi_verdict = fingerprint_cfi
            .check_into_sentinel(crate::tx::display::erc8213::FINGERPRINT_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let fingerprint_page_verdict = crate::tx::display::erc8213::fingerprint_page_proof(
            &final_pages,
            fingerprint_pages_before,
            fingerprint_kind,
        );
        if fingerprint_cfi_verdict != crate::fi::OK_SENTINEL
            || fingerprint_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "digest incomplete");
            return NscStatus::InternalError as u32;
        }
        // The final whole-batch gate owns the deployment mode. Append an exact
        // cancellable factory page here (not once per member), with an exact
        // completed-skip proof for ordinary already-deployed UserOps.
        let deployment_pages_before = final_pages.len;
        let mut deployment_page_cfi = crate::fi::CfiCounter::new();
        if crate::tx::display::enforce_deployment_page(
            &mut final_pages,
            &deployment_context,
            &mut deployment_page_cfi,
        )
        .is_err()
        {
            ui::show_status("Batch sign", "deploy unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let deployment_cfi_verdict = deployment_page_cfi
            .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let deployment_page_verdict = crate::tx::display::deployment_page_proof(
            &final_pages,
            deployment_pages_before,
            &deployment_context,
        );
        if deployment_cfi_verdict != crate::fi::OK_SENTINEL
            || deployment_page_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "deploy unshown");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_cfi_verdict =
            gas_lane_cfi.check_into_sentinel(crate::tx::display::USEROP_GAS_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let gas_lane_final_verdict = crate::tx::display::userop_gas_final_set_proof(
            &final_pages,
            gas_lane_pages_before,
            &call_gas_limit,
            &verification_gas_limit,
            &pre_verification_gas,
        );
        if gas_lane_final_cfi_verdict != crate::fi::OK_SENTINEL
            || gas_lane_final_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "gas conflict");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let paymaster_final_cfi_verdict =
            paymaster_cfi.check_into_sentinel(crate::tx::display::PAYMASTER_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let paymaster_final_verdict = crate::tx::display::paymaster_final_set_proof(
            &final_pages,
            paymaster_pages_before,
            &paymaster_and_data_hash,
        );
        if paymaster_final_cfi_verdict != crate::fi::OK_SENTINEL
            || paymaster_final_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "paymaster changed");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        if crate::tx::display::erc8213::fingerprint_final_set_proof(
            &final_pages,
            fingerprint_pages_before,
            fingerprint_kind,
        ) != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "digest changed");
            return NscStatus::InternalError as u32;
        }
        crate::fi::scrub_sentinel_register();
        let deployment_final_cfi_verdict = deployment_page_cfi
            .check_into_sentinel(crate::tx::display::DEPLOYMENT_PAGE_CFI_EXPECTED);
        crate::fi::scrub_sentinel_register();
        let deployment_final_verdict = crate::tx::display::deployment_final_set_proof(
            &final_pages,
            deployment_pages_before,
            &deployment_context,
        );
        if deployment_final_cfi_verdict != crate::fi::OK_SENTINEL
            || deployment_final_verdict != crate::fi::OK_SENTINEL
        {
            ui::show_status("Batch sign", "deploy changed");
            return NscStatus::InternalError as u32;
        }
        // Pixel trusted UI (`ui-px`): the whole-batch ask and the batch-wide
        // trailers (paymaster, signer, lane, gas, batch-final fingerprint,
        // deployment).
        #[cfg(feature = "ui-px")]
        let px = {
            let display_tx = Eip1559Tx::default();
            let facts = crate::tx::display::TrailerFacts {
                tx: &display_tx,
                legacy_fee_required: false,
                paymaster_and_data_hash: &paymaster_and_data_hash,
                account_index,
                sender: &sender,
                target: &sender,
                nonce: &type2_nonce,
                call_gas: &call_gas_limit,
                verification_gas: &verification_gas_limit,
                pre_verification_gas: &pre_verification_gas,
                fingerprint: fingerprint_kind,
                deployment: Some(&deployment_context),
                set: crate::tx::display::TrailerSet::BatchFinal,
                fingerprint2: None,
                offchain: None,
            };
            let inputs = crate::tx::display::px_lift::ContentInputs {
                body: crate::tx::display::px_lift::Body::BatchSummary { total: batch_count },
                trailers: &facts,
            };
            Some(super::px_confirm(&mut *px_scratch, &final_pages, &inputs))
        };
        #[cfg(not(feature = "ui-px"))]
        let px: Option<Result<(ConfirmResult, u32), &'static str>> = None;
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        let px_route = px.is_some();
        let (cr, cr_verdict) = match px {
            Some(Ok(r)) => r,
            Some(Err(reason)) => {
                ui::show_status("Sign refused", reason);
                return NscStatus::InternalError as u32;
            }
            None => confirm_checked(final_pages.as_slice()),
        };
        match cr {
            ConfirmResult::Confirmed => {
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
        #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
        {
            px_owns_ending = px_route;
        }
        // FI belt (UI1 / work-todo #12c): affirmative-sentinel gate; fail closed.
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
    }

    // ── 7. Reconstruct entropy + derive slot master ─────────────────
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

    // ── 8. Build Type 2 callData: executeBatchWithOffchainCount(...) ─
    let t2_owner_index = (slot_index as u64) + 1;
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);

    // Same offchain count promotion logic as the single-tx path: keep
    // `local_offchain_count` at least at the on-chain high-water mark
    // so a stale local view does not cause a verify-then-revert cycle.
    // F-10 hardening (audit 2026-06-18 — match the off-chain gate's bar,
    // cmd_sign_offchain.rs §6): double-read each counter with a randomised
    // delay between and refuse on disagreement / u64::MAX (the glitched-
    // scan sentinel from the F-12 forward+reverse read), so a single
    // stuck-at fault cannot smuggle a faulted count into the combined cap.
    let local_offchain_a = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let local_offchain_b = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    if local_offchain_a != local_offchain_b || local_offchain_a == u64::MAX {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let local_offchain = local_offchain_a;

    let last_userop_a = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    crate::fi::wait_random();
    let last_userop_b = unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    if last_userop_a != last_userop_b || last_userop_a == u64::MAX {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let last_userop_snapshot = last_userop_a;

    // MEDIUM-2 (audit counter-replay 20260611): same combined-cap gate as
    // the single-tx path. A batch produces exactly ONE Type-2 slot-key
    // signature (covering all inner txs), so it consumes one unit of the
    // few-time budget. Refuse before signing if the combined total
    // (durable UserOp tally + off-chain count) would exceed MAX_SLOT_USES.
    let userop_sigs_a = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    crate::fi::wait_random();
    let userop_sigs_b = unsafe { crate::offchain_state::userop_sigs_read(&slot_flash_key) };
    if userop_sigs_a != userop_sigs_b {
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let userop_sigs = userop_sigs_a;

    // A recovery sync may put `last_userop_snapshot` ahead of the local
    // counter. The promotion below is part of the state this signature will
    // commit, so cap-gate the repaired/effective count rather than the stale
    // local value (sync→batch sibling of the single-Type-2 regression).
    let effective_offchain =
        crate::aa::offchain_gate::effective_offchain_count(local_offchain, last_userop_snapshot);
    if !crate::aa::offchain_gate::userop_cap_ok(effective_offchain, userop_sigs) {
        ui::show_status("Slot exhausted", "rotate slot");
        return NscStatus::OffchainCapExceeded as u32;
    }
    // F-10 belt-and-braces: independently recompute the floor-fold and cap;
    // black_box keeps LLVM from collapsing the second FI window into the first.
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
        ui::show_status("Batch sign", "fi tampered");
        return NscStatus::InternalError as u32;
    }
    let new_offchain_count = effective_offchain;
    if new_offchain_count > local_offchain {
        if unsafe {
            crate::offchain_state::offchain_count_promote_to(&slot_flash_key, new_offchain_count)
        }
        .is_err()
        {
            ui::show_status("Batch sign", "offchain repair");
        }
    }

    // Borrow the parsed inner-tx data slices for the encoder — these
    // point into `snap`, which lives until end of handler.
    let mut batch_view: [BatchInnerTx<'_>; MAX_BATCH_TXS] = [BatchInnerTx {
        to: [0u8; 20],
        value: [0u8; 32],
        data: &[],
    }; MAX_BATCH_TXS];
    for i in 0..batch_count {
        let p = parsed[i].as_ref().unwrap();
        batch_view[i] = BatchInnerTx {
            to: p.to,
            value: p.value,
            data: &snap[p.data_off..p.data_off + p.data_len],
        };
    }
    // In-place fill of a single caller-owned buffer. Building the 18 KB
    // `ExecuteBatchCallData` here and passing `&mut` to the reconstructor
    // (rather than letting it return one by value) keeps exactly one such
    // buffer on this already-deep sign stack — the return-by-value form
    // left a second transient copy live that overflowed into BSS.
    let mut t2_exec = ExecuteBatchCallData {
        buf: [0u8; MAX_EXECUTE_BATCH_CALLDATA_LEN],
        len: 0,
    };
    if reconstruct_execute_batch_calldata_into(
        &mut t2_exec,
        t2_owner_index,
        new_offchain_count,
        &batch_view[..batch_count],
    )
    .is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Batch sign", "calldata too long");
        return NscStatus::CryptoError as u32;
    }

    // Independently parse the exact live bytes that will feed the Type-2 call
    // digest. This closes the post-confirmation construction seam: a fault in
    // the tuple copy or ABI encoder cannot change target/value/data/count/order
    // while preserving the final fingerprint the user confirmed.
    let mut encoded_tuple_verdict = crate::fi::FAIL_SENTINEL;
    // SAFETY: unique live local; volatile fail-initialization makes a skipped
    // parser/comparison call non-authoritative.
    unsafe {
        core::ptr::write_volatile(&mut encoded_tuple_verdict, crate::fi::FAIL_SENTINEL);
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    if let Some(encoded_tuple_commitment) = execute_batch_tuple_commitment_from_calldata(
        t2_exec.as_slice(),
        t2_owner_index,
        new_offchain_count,
        batch_count,
    ) {
        let exact = encoded_tuple_commitment.ct_eq(&batch_final).unwrap_u8() == 1;
        crate::fi::scrub_sentinel_register();
        let verdict = crate::fi::check_true_into_sentinel(|| core::hint::black_box(exact));
        // SAFETY: unique live local and no concurrent access.
        unsafe { core::ptr::write_volatile(&mut encoded_tuple_verdict, verdict) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    // SAFETY: live local, sampled independently around a randomized gap.
    let encoded_tuple_verdict_a = unsafe { core::ptr::read_volatile(&encoded_tuple_verdict) };
    if encoded_tuple_verdict_a != crate::fi::OK_SENTINEL {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Batch sign", "tuple mismatch");
        return NscStatus::InternalError as u32;
    }
    crate::fi::wait_random();
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
    let encoded_tuple_verdict_b = unsafe { core::ptr::read_volatile(&encoded_tuple_verdict) };
    if encoded_tuple_verdict_b != crate::fi::OK_SENTINEL {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Batch sign", "tuple mismatch");
        return NscStatus::InternalError as u32;
    }

    // ── 9. Type 2 nonce ─────────────────────────────────────────────
    // `type2_nonce` was derived before trusted-display rendering so every
    // member/final confirmation is bound to this exact signed batch nonce.

    // ── 10. Slot C10 keygen (cached) ────────────────────────────────
    let need_keygen = super::state::peek_state(|_| {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE` under the single-threaded gateway. Mirrors
        // `cmd_sign_userop`.
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
        // SLOT_CACHE` under the non-reentrant dispatcher +
        // `HandlerGuard`. Displaced prior `CachedSlot` drops here
        // (ZeroizeOnDrop wipes the previous SK).
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

    // SAFETY: category 5 — read-only borrow of `static mut
    // SLOT_CACHE`. Cache populated above; single-threaded dispatcher
    // means no concurrent mutator.
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

    let mut slot_owner_bytes = [0u8; 64];
    slot_owner_bytes[..32].copy_from_slice(&slot_pk_seed_32);
    slot_owner_bytes[32..].copy_from_slice(&slot_pk_root_32);

    // First spatially separate authority check: the bootstrap factory-sign
    // path cannot begin unless the whole-batch deployment page was confirmed.
    crate::fi::scrub_sentinel_register();
    if deployment_confirm_receipt.completion_proof(&deployment_context)
        != crate::fi::OK_SENTINEL
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Batch sign", "deploy consent");
        return NscStatus::InternalError as u32;
    }

    // ── 11. Build Type 1 (optional) + initCode (optional) ───────────
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
        super::state::with_state(|s| {
            s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
        });

        // ── 11a. Deploy path ───────────────────────────────────────
        if include_init_code {
            ui::show_status("Factory", "signing slot-0");

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
            // Outer FI guard, symmetric with Type 2.
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
            // F16: black_box each verdict so LLVM cannot CSE-merge the helper's
            // two closure evaluations (the F-1 idiom the single-bool gates here
            // already use); the two `verify()` calls split by `wait_random` are
            // the CSE-proof redundancy, this matches their bar.
            if crate::fi::check_true_into_sentinel(|| {
                core::hint::black_box(fv1) && core::hint::black_box(fv2)
            }) != crate::fi::OK_SENTINEL
            {
                entropy.zeroize();
                crate::fi::zeroize_barrier();
                ui::show_status("FactorySig", "verify FAIL");
                return NscStatus::CryptoError as u32;
            }

            let ic = &mut *init_code_out;
            ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
            ic[20..24].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
            ic[24..56].copy_from_slice(&master_pk_seed_32);
            ic[56..88].copy_from_slice(&master_pk_root_32);
            ic[88..120].copy_from_slice(&slot_pk_seed_32);
            ic[120..152].copy_from_slice(&slot_pk_root_32);
            ic[152 + 24..184].copy_from_slice(&chain_id.to_be_bytes());
            let offset_field_start = 24 + 5 * 32;
            ic[offset_field_start + 24..offset_field_start + 32]
                .copy_from_slice(&(6 * 32u64).to_be_bytes());
            let length_field_start = offset_field_start + 32;
            ic[length_field_start + 24..length_field_start + 32]
                .copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
            let data_start = length_field_start + 32;
            ic[data_start..data_start + C10_SIG_LEN].copy_from_slice(&factory_sig);

            debug_assert_eq!(data_start + 4032, PQ_INIT_CODE_LEN);
            emit_init_code = true;
            t1_init_code_digest = sha256_bytes(ic.as_slice());
        }

        // ── 11b. Rotation path ─────────────────────────────────────
        if register_slot {
            ui::show_status("Slot register", "signing addOwner");

            let mut t1_call = [0u8; 4 + 32 + 32 + 64];
            t1_call[..4].copy_from_slice(&PQ_ADD_OWNER_BYTES_SELECTOR);
            t1_call[4 + 28..4 + 32].copy_from_slice(&0x20u32.to_be_bytes());
            t1_call[4 + 32 + 28..4 + 32 + 32].copy_from_slice(&64u32.to_be_bytes());
            t1_call[4 + 64..4 + 64 + 64].copy_from_slice(&slot_owner_bytes);
            let t1_call_digest = sha256_bytes(&t1_call);

            let t1_params = AaUserOpParamsV06Sha256 {
                sender,
                entry_point: ENTRY_POINT_V06,
                chain_id,
                nonce: U256(nonce),
                init_code_digest: SHA256_EMPTY,
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

        drop(c10_sk);
    }

    // ── 12. Type 2: slot C10 signs the batch UserOp sphincs digest ──
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_init_code_digest = if include_init_code {
        t1_init_code_digest
    } else {
        SHA256_EMPTY
    };
    // Reprove the affirmative receipt and couple it to the concrete emitted
    // initCode immediately before Type-2 digest construction. The enabled
    // path verifies the exact shown factory and byte digest; disabled mode
    // proves no blob was materialized and uses SHA256_EMPTY.
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
        ui::show_status("Batch sign", "deploy binding");
        return NscStatus::InternalError as u32;
    }
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

    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if px_owns_ending {
        crate::ui::px::lcd::film_start();
    } else {
        ui::show_progress("Slot C10 sign", 0);
    }
    #[cfg(not(all(feature = "ui-px", feature = "ui-lcd")))]
    ui::show_progress("Slot C10 sign", 0);
    let t2_sig = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE`. Single-threaded dispatcher; cache populated
        // above.
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

    // Verify-before-release, double-evaluated with FI hardening — same
    // pattern as the single-tx path. `fi::check_true` gates the AND
    // through a hamming-distant sentinel.
    let (v1, v2) = {
        // SAFETY: category 5 — read-only borrow of `static mut
        // SLOT_CACHE` for the FI-hardened verify-before-release.
        // Same rationale as the sign block above.
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

    let mut type2_wrapper_out: Zeroizing<[u8; SIG_WRAPPER_LEN]> =
        Zeroizing::new([0u8; SIG_WRAPPER_LEN]);
    super::sig_wrapper::encode_signature_wrapper(&mut *type2_wrapper_out, t2_owner_index, &t2_sig);

    // ── 13. Persist the new offchain count + slot-registered flag ──
    if register_slot {
        if unsafe { crate::offchain_state::offchain_count_register_slot(&slot_flash_key) }.is_err()
        {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            ui::show_status("Slot register", "FAIL");
            return NscStatus::InternalError as u32;
        }
    }
    if unsafe { crate::offchain_state::last_userop_count_set(&slot_flash_key, new_offchain_count) }
        .is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }
    // MEDIUM-2: durably tally this batch's single Type-2 slot-key
    // signature (same accounting unit as the single-tx path). After sig
    // verify, before the response write, fail-closed.
    if unsafe { crate::offchain_state::userop_sigs_bump(&slot_flash_key, userop_sigs + 1) }.is_err()
    {
        entropy.zeroize();
        crate::fi::zeroize_barrier();
        ui::show_status("Sig commit", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 14. Assemble output bundle ──────────────────────────────────
    //
    // Same layout as `CMD_SIGN_USEROP`'s response so the companion's
    // parser is reused as-is.
    //
    // FI deref-site re-validation (Partner-A PA-01 / finding F5). The
    // top-of-handler gate is spatially distant from these writes; skipping its
    // reject branch must not admit an attacker-chosen secure-SRAM address.
    // Validate the full possible response extent again immediately before the
    // first dereference, matching the single and off-chain handlers.
    crate::fi::scrub_sentinel_register();
    let out_extent_ok = crate::fi::check_true_into_sentinel(|| {
        validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN)
    });
    if out_extent_ok != crate::fi::OK_SENTINEL {
        ui::show_status("Batch sign", "bad out");
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
    let _ = write_pos;

    // ── 15. Zeroise transients ──────────────────────────────────────
    entropy.zeroize();
    crate::fi::zeroize_barrier();
    type1_wrapper_out.zeroize();
    type2_wrapper_out.zeroize();
    init_code_out.zeroize();
    // L-2: wipe the TOCTOU snapshot on exit. Mirror of cmd_sign_userop.
    {
        let buf = &mut *core::ptr::addr_of_mut!(super::SIGN_SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
    // The pixel route lands the signing film (`BATCH SIGNED`).
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if px_owns_ending {
        crate::ui::px::lcd::film_resolve(pqsigner_ui_px::scene::Ending::Signed);
        ui::show_status("PQSigner OS", "Ready");
        return NscStatus::Ok as u32;
    }
    ui::show_status("Batch signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    ui::show_status("PQSigner OS", "Ready");

    NscStatus::Ok as u32
}

/// # Safety
/// Category 2 — NS pointer deref. Caller must have validated
/// `[out_ptr, out_ptr + MAX_SIGN_RESPONSE_LEN)` via
/// `validate_ns_write_ptr` AND ensured `*write_pos + 4 <=
/// MAX_SIGN_RESPONSE_LEN`. Volatile keeps NS observers from
/// seeing a torn word.
unsafe fn write_be_u32(out_ptr: *mut u8, write_pos: &mut usize, v: u32) {
    let be = v.to_be_bytes();
    for i in 0..4 {
        core::ptr::write_volatile(out_ptr.add(*write_pos + i), be[i]);
    }
    *write_pos += 4;
}

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

fn add_one_to_be_u256(v: &mut [u8; 32]) {
    for i in (24..32).rev() {
        let (sum, carry) = v[i].overflowing_add(1);
        v[i] = sum;
        if !carry {
            return;
        }
    }
    debug_assert!(false, "nonce seq overflow slipped past the step-4 guard");
}

fn c10_sign_progress_bootstrap(percent: u8) {
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if crate::ui::px::lcd::film_live() {
        crate::ui::px::lcd::film_tick(percent);
        return;
    }
    crate::ui::show_progress("C10 sign", percent);
}

fn c10_sign_progress_slot(percent: u8) {
    #[cfg(all(feature = "ui-px", feature = "ui-lcd"))]
    if crate::ui::px::lcd::film_live() {
        crate::ui::px::lcd::film_tick(percent);
        return;
    }
    crate::ui::show_progress("Slot C10 sign", percent);
}

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
