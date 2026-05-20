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
//!   * Kinds 1..=7 (ERC-20, ZK v1, ZK v3, Safe v1, selector curated,
//!     selector self-attest, ERC-7730) bind via `tx_idx` to a specific
//!     inner-tx and feed `pick_sign_pages` for that tx.
//!   * Kind 8 (address-name bundles) is batch-wide (`tx_idx == 0xff`),
//!     accumulating into a single `NameResolver` shared across renders.
//!
//! The same per-tx **downgrade-mitigation gates** as single-tx fire
//! before `pick_sign_pages` for each inner-tx: if an inner calldata
//! claims `setPreSignature` on GPv2 settlement, the matching ZK v3
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
    NscStatus, ACCOUNT_INDEX_MASK, ACCOUNT_INDEX_SHIFT, APPROVE_HASH_CALLDATA_LEN,
    APPROVE_HASH_SELECTOR, C10_SIG_LEN, FLAG_INCLUDE_INIT_CODE, FLAG_REGISTER_SLOT,
    GPV2_SETTLEMENT_ADDRESS, MAX_BATCH_TXS, MAX_SIGN_RESPONSE_LEN, MAX_TX_LEN,
    PQ_ADD_OWNER_BYTES_SELECTOR, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY, SET_PRE_SIGNATURE_SELECTOR, SIGN_USEROP_BATCH_HEADER_LEN,
    SIGN_USEROP_BATCH_MAX_PAYLOAD_LEN, SIGN_USEROP_BATCH_TX_PREFIX_LEN,
    SIGN_USEROP_BATCH_WIRE_VERSION, SIG_WRAPPER_LEN, SLOT_INDEX_MASK, TRAILER_KIND_ERC20,
    TRAILER_KIND_ERC7730, TRAILER_KIND_NAME, TRAILER_KIND_SAFE_V1, TRAILER_KIND_SEL_CURATED,
    TRAILER_KIND_SEL_SELFATTEST, TRAILER_KIND_ZK_V1, TRAILER_KIND_ZK_V3,
};
use zeroize::{Zeroize, Zeroizing};

/// Domain tag the firmware signs when authorising slot-0 on a new chain.
/// MUST match `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;
use crate::aa::userop::{
    compute_sphincs_digest_v06, reconstruct_execute_batch_calldata, sha256_bytes,
    AaUserOpParamsV06Sha256, BatchInnerTx, SHA256_EMPTY,
};
use crate::erc20::bundle::{verify_erc20_bundle, Erc20Metadata};
use crate::names::{verify_name_bundle, NameResolver};
use crate::selectors::{parse_self_attest_bundle, verify_selector_bundle, SelectorMeta};
use crate::tx::display::batch::{build_final_summary_pages, wrap_pages_with_batch_banner};
use crate::tx::display::pick_sign_pages;
use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::eip712::cowswap::VerifiedCowswapV3;
use crate::tx::eip712::safe::VerifiedSafeV1;
use crate::tx::erc7730::VerifiedDescriptor;
use crate::ui;
use crate::zk::VerifiedClearSignV1;

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
/// inner tx's index. Empty fields fall through `pick_sign_pages` to the
/// lower-priority renderers (value transfer / ERC-20 shape / blind-sign).
///
/// Lifetime `'a` ties to the secure-side TOCTOU snapshot — every
/// borrowed verifier output (ERC-20 metadata, Safe canonical, ERC-7730
/// IR, selector text-sig) lives inside `snap[..]` for the whole
/// `pick_sign_pages` call window. ZK v1 / v3 verifiers return owned
/// fixed-size buffers, hence no `'a` on those variants.
struct RoutedTrailers<'a> {
    erc20: Option<Erc20Metadata<'a>>,
    zk_v1: Option<VerifiedClearSignV1>,
    zk_v3: Option<VerifiedCowswapV3>,
    safe_v1: Option<VerifiedSafeV1<'a>>,
    erc7730: Option<VerifiedDescriptor<'a>>,
    selector: Option<SelectorMeta<'a>>,
}

impl<'a> RoutedTrailers<'a> {
    /// All slots `None`. Used as the `get_or_insert_with` default while
    /// dispatching parsed trailer records into the per-tx array.
    fn empty() -> Self {
        Self {
            erc20: None,
            zk_v1: None,
            zk_v3: None,
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
    use crate::ui::confirm::{confirm, ConfirmResult};

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
    if !validate_ns_read_ptr(args.arg0, total_len) {
        ui::show_status("Batch sign", "bad ptr");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, MAX_SIGN_RESPONSE_LEN) {
        ui::show_status("Batch sign", "bad out");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
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
    let include_init_code = (flags & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & FLAG_REGISTER_SLOT) != 0;
    let account_index = (flags & ACCOUNT_INDEX_MASK) >> ACCOUNT_INDEX_SHIFT;
    let slot_index = flags & SLOT_INDEX_MASK;

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
    let include_init_code_r = (flags_recheck & FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot_r = (flags_recheck & FLAG_REGISTER_SLOT) != 0;
    let slot_index_r = flags_recheck & SLOT_INDEX_MASK;
    if include_init_code_r != include_init_code
        || register_slot_r != register_slot
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

    // ── 5c. Verify + route trailers per inner-tx ──────────────────
    //
    // For every parsed record, run the kind-appropriate verifier with
    // the same FI-hardened envelope the single-tx path uses
    // (`let ok = verify(...).is_some(); wait_random(); sentinel`).
    // Successful verifications land in `routed[tx_idx].<field>`;
    // verifier failures drop silently (parity with single-tx — clear-
    // signing is an enhancement layer that degrades gracefully). The
    // CoW v3 and Safe v1 downgrade-mitigation gates are enforced
    // later in the per-tx render loop, before `pick_sign_pages` runs.
    //
    // Mutual exclusion (curated XOR self-attest per tx_idx) was already
    // enforced at parse time inside `parse_batch_trailers`.
    let mut routed: [Option<RoutedTrailers<'_>>; MAX_BATCH_TXS] =
        [const { None }; MAX_BATCH_TXS];
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
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                // Cross-check (chain_id, contract) against the routed tx.
                if meta.chain_id == chain_id && meta.contract == ptx.to {
                    routed[rec.tx_idx as usize]
                        .get_or_insert_with(RoutedTrailers::empty)
                        .erc20 = Some(meta);
                }
            }
            TRAILER_KIND_ZK_V1 => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let v_opt = crate::zk::verify_and_bind_trailer_v1(
                    bytes,
                    inner_data,
                    chain_id,
                    &ptx.to,
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
                    .zk_v1 = v_opt;
            }
            TRAILER_KIND_ZK_V3 => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let v_opt = crate::tx::eip712::cowswap::verify_and_bind_trailer(
                    bytes,
                    inner_data,
                    chain_id,
                    &sender,
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
                    .zk_v3 = v_opt;
            }
            TRAILER_KIND_SAFE_V1 => {
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let inner_data: &[u8] = &snap[ptx.data_off..ptx.data_off + ptx.data_len];
                let v_opt = crate::tx::eip712::safe::verify_and_bind_trailer(
                    bytes,
                    inner_data,
                    chain_id,
                    &ptx.to,
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
                let v_res = crate::tx::erc7730::verify_erc7730_bundle(
                    bytes,
                    &crate::db_roots::ERC7730_DESCRIPTORS_ROOT,
                );
                let ok = v_res.is_ok();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(ok))
                    != crate::fi::OK_SENTINEL
                {
                    ui::show_status("Batch sign", "7730 bundle fail");
                    continue;
                }
                let v = v_res.unwrap();
                // FI-hardened binding cross-check, mirroring single-tx
                // (`cmd_sign_userop.rs:533-548`). Companion-supplied
                // tx_idx is verified to actually match the IR's
                // contract — a glitch flipping the `.is_ok()` lands on
                // a sentinel mismatch.
                let ptx = parsed[rec.tx_idx as usize].as_ref().unwrap();
                let bind_ok = crate::tx::erc7730::cross_check_contract(
                    &v.ir,
                    chain_id,
                    &ptx.to,
                )
                .is_ok();
                crate::fi::wait_random();
                if crate::fi::check_true_into_sentinel(|| core::hint::black_box(bind_ok))
                    != crate::fi::OK_SENTINEL
                {
                    ui::show_status("Batch sign", "7730 binding fail");
                    continue;
                }
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

    // ── 6. Per-tx clear-signing confirm ─────────────────────────────
    //
    // Slot rotation is its own affirmative-consent step ahead of the
    // per-tx loop: when `FLAG_REGISTER_SLOT` is set the firmware also
    // emits a Type 1 `addOwnerBytes` UserOp that consumes one of the
    // wallet's `MAX_BOOTSTRAP_USES` budget items on chain. The cap
    // applies to the whole batch (one Type 1 per sign call), so we
    // gate it once before any inner-tx render.
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

    // For each member: render the same pages the single-tx path would
    // render (no trailers — basic value/erc20-shape/blind-sign ladder),
    // wrap with a "BATCH SIGN | Tx i of N" banner, and require an
    // affirmative long-right confirm. Cancel anywhere → abort the
    // entire signing operation; idle wipe → zero secrets.
    //
    // Display-time fields (gas, nonce) come from the outer UserOp; per
    // member we vary only `(to, value, data_len, signing_hash)`.
    let display_nonce = u64::from_be_bytes([
        nonce[24], nonce[25], nonce[26], nonce[27], nonce[28], nonce[29], nonce[30], nonce[31],
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

    // Running Keccak256 over the concatenation of per-tx ERC-8213
    // calldata digests. The batch-final fingerprint surfaces the
    // resulting hash so a user can cross-check the *whole bundle*
    // (not just an individual inner call) against an off-device
    // reconstruction (e.g., `cast keccak (concat (per-tx digests))`).
    use sha3::Digest;
    let mut batch_digest = sha3::Keccak256::new();

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
        };

        // ── Per-tx downgrade-mitigation gates ──────────────────────
        //
        // Mirroring single-tx `cmd_sign_userop.rs:789-806`. If an inner
        // calldata claims `setPreSignature` on the GPv2 settlement
        // contract, the matching ZK v3 trailer is mandatory — without
        // it the user would otherwise confirm the weaker static "Pre-
        // sign CowSwap order" string and end up signing an orderUid
        // they never saw the contents of. Same logic for Safe
        // `approveHash`: without the safe_v1 trailer a hostile NS
        // could coerce blind-signing a bytes32 with no SafeTx
        // visibility.
        let cow_selector =
            inner_data.len() >= 4 && &inner_data[..4] == SET_PRE_SIGNATURE_SELECTOR;
        let cow_target = ptx.to == GPV2_SETTLEMENT_ADDRESS;
        if cow_selector
            && cow_target
            && routed[i].as_ref().and_then(|r| r.zk_v3.as_ref()).is_none()
        {
            ui::show_status("CoW sign", "v3 required (batch)");
            return NscStatus::InvalidPointer as u32;
        }
        let safe_selector = inner_data.len() >= 4 && inner_data[..4] == APPROVE_HASH_SELECTOR;
        let safe_calldata_len = inner_data.len() == APPROVE_HASH_CALLDATA_LEN;
        if safe_selector
            && safe_calldata_len
            && routed[i].as_ref().and_then(|r| r.safe_v1.as_ref()).is_none()
        {
            ui::show_status("Safe sign", "safe_v1 required (batch)");
            return NscStatus::InvalidPointer as u32;
        }

        // Routed-trailer pass-through: every per-tx slot the single-tx
        // handler passes is mirrored here from `routed[i]`. Empty
        // slots fall through `pick_sign_pages` to the lower-priority
        // renderers (value-transfer / ERC-20 shape / blind-sign).
        let r = routed[i].as_ref();
        let inner_pages = pick_sign_pages(
            &tx_for_display,
            inner_data,
            r.and_then(|r| r.zk_v3.as_ref()),
            r.and_then(|r| r.zk_v1.as_ref()),
            r.and_then(|r| r.safe_v1.as_ref()),
            r.and_then(|r| r.erc7730.as_ref()),
            r.and_then(|r| r.erc20.as_ref()),
            r.and_then(|r| r.selector.as_ref()),
            &resolver,
        );
        let mut pages = wrap_pages_with_batch_banner(inner_pages, i, batch_count);

        // Per-tx ERC-8213 fingerprint. The user sees one fingerprint
        // per inner call; a separate batch-final fingerprint binds
        // the whole bundle below.
        let inner_digest =
            pqsigner_tx_core::erc8213::calldata_digest(inner_data);
        let _ = crate::tx::display::erc8213::append_fingerprint_page(
            &mut pages,
            crate::tx::display::erc8213::Kind::CalldataDigest(inner_digest),
        );
        batch_digest.update(&inner_digest);

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
    }

    // ── 6b. Final summary confirm + batch-final fingerprint ────────
    //
    // `batch_digest` is `keccak256(concat(per_tx_calldata_digests))`
    // — a single 32-byte value the user can cross-check against
    // a host-side reconstruction over the same bundle.
    let batch_final: [u8; 32] = {
        let mut out = [0u8; 32];
        let h = batch_digest.finalize();
        out.copy_from_slice(&h);
        out
    };
    {
        let mut final_pages = build_final_summary_pages(batch_count);
        let _ = crate::tx::display::erc8213::append_fingerprint_page(
            &mut final_pages,
            crate::tx::display::erc8213::Kind::Raw32(batch_final),
        );
        match confirm(final_pages.as_slice()) {
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
    let local_offchain = unsafe { crate::offchain_state::offchain_count_read(&slot_flash_key) };
    let last_userop_snapshot =
        unsafe { crate::offchain_state::last_userop_count_read(&slot_flash_key) };
    let new_offchain_count = local_offchain.max(last_userop_snapshot);
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
    let t2_exec = match reconstruct_execute_batch_calldata(
        t2_owner_index,
        new_offchain_count,
        &batch_view[..batch_count],
    ) {
        Ok(c) => c,
        Err(_) => {
            entropy.zeroize();
            crate::fi::zeroize_barrier();
            ui::show_status("Batch sign", "calldata too long");
            return NscStatus::CryptoError as u32;
        }
    };

    // ── 9. Type 2 nonce ─────────────────────────────────────────────
    let mut type2_nonce = nonce;
    if register_slot {
        add_one_to_be_u256(&mut type2_nonce);
    }

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
                entry_point,
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

        drop(c10_sk);
    }

    // ── 12. Type 2: slot C10 signs the batch UserOp sphincs digest ──
    let t2_call_digest = sha256_bytes(t2_exec.as_slice());
    let t2_init_code_digest = if include_init_code {
        t1_init_code_digest
    } else {
        SHA256_EMPTY
    };
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
    if crate::fi::check_true_into_sentinel(|| v1 && v2) != crate::fi::OK_SENTINEL {
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

    // ── 14. Assemble output bundle ──────────────────────────────────
    //
    // Same layout as `CMD_SIGN_USEROP`'s response so the companion's
    // parser is reused as-is.
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
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
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
    crate::ui::show_progress("C10 sign", percent);
}

fn c10_sign_progress_slot(percent: u8) {
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
