//! CMD_SIGN_OFFCHAIN — produce a SPHINCS+C10 signature for an EIP-1271
//! (off-chain) signing request.
//!
//! Two modes selected by the `kind` byte at offset 13:
//!
//!   * **`OFFCHAIN_KIND_PERSONAL_SIGN` (1)** — the companion sends the
//!     raw `personal_sign` message bytes. The firmware itself computes
//!     the `personal_sign` prefix hash, wraps it via Solady's nested
//!     EIP-712 (PersonalSign workflow), shows the message text on the
//!     trusted display, and signs the resulting hash. This is the only
//!     mode that gives the user real visibility into what they're
//!     approving.
//!
//!   * **`OFFCHAIN_KIND_RAW32` (0)** — fallback for cases where the
//!     companion only has the final 32-byte hash (e.g. a typed-data
//!     digest from a dapp the firmware can't decode). The firmware
//!     signs the supplied bytes as-is and renders them as hex.
//!
//! Slot-key safety:
//!   * Enforces the bounded-recovery rule
//!     `local_offchain - last_userop < MAX_OFFCHAIN_GAP` so the next
//!     UserOp definitely publishes the count, capping the worst-case
//!     unbacked off-chain sigs at `MAX_OFFCHAIN_GAP`.
//!   * Enforces the per-slot cap `local_offchain + 1 <= MAX_SLOT_USES`
//!     pre-emptively. The on-chain combined cap is the primary defence
//!     (it observes both `slotUses` and `offchainSigCount`); this
//!     in-firmware check is defence-in-depth so a faulted firmware
//!     still cannot produce a sig past the SPHINCS+ usage budget.
//!   * Refuses for slots the firmware has no flash record of —
//!     forces a Type 1 slot registration via CMD_SIGN_USEROP after
//!     a fresh-from-seed restore, so the firmware's view of the
//!     local count is grounded in its own signing history.
//!
//! Security policy:
//!   * Requires `pin_verified`.
//!   * `ownerIndex == 0` (bootstrap) is forbidden — the bootstrap key
//!     signs only Type 1 slot registrations. EIP-1271 sigs are slot-
//!     authorised. The on-chain `_erc1271IsValidSignatureNowCalldata`
//!     enforces the same rule; this is duplicated here so a faulted
//!     firmware does not leak bootstrap budget through the off-chain
//!     path.

use sphincs_tz_shared::{
    NscStatus, MAX_ACCOUNT_INDEX, MAX_OFFCHAIN_GAP, MAX_OFFCHAIN_PERSONAL_SIGN_LEN, MAX_SLOT_USES,
    OFFCHAIN_KIND_PERSONAL_SIGN, OFFCHAIN_KIND_RAW32, SIGNATURE_LEN,
    SIGN_OFFCHAIN_HEADER_LEN, SIGN_OFFCHAIN_INPUT_KIND_OFF, SIGN_OFFCHAIN_INPUT_MAX_LEN,
    SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF, SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF,
    SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, SIGN_OFFCHAIN_OUTPUT_LEN, SIGN_OFFCHAIN_OUTPUT_SIG_OFF,
};
use zeroize::{Zeroize, Zeroizing};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // HIGH-7: keep secrets resident across the slot-keygen window.
    let _busy = super::HandlerGuard::enter();

    crate::ui::show_status("EIP-1271", "validating...");

    // ── 1. Unlock check ─────────────────────────────────────────────
    if !super::state::peek_state(|s| s.pin_verified) {
        crate::ui::show_status("EIP-1271", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let in_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len < SIGN_OFFCHAIN_HEADER_LEN || total_len > SIGN_OFFCHAIN_INPUT_MAX_LEN {
        crate::ui::show_status("EIP-1271", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, total_len) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    static mut SNAP_BUF: [u8; SIGN_OFFCHAIN_INPUT_MAX_LEN] = [0u8; SIGN_OFFCHAIN_INPUT_MAX_LEN];
    {
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }
    let snap_full = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
    let snap = &mut snap_full[..total_len];
    for i in 0..total_len {
        snap[i] = core::ptr::read_volatile(in_ptr.add(i));
    }

    // ── 4. Parse header ─────────────────────────────────────────────
    let account_index = snap[0] as u32;
    let chain_id = u64::from_be_bytes([
        snap[1], snap[2], snap[3], snap[4], snap[5], snap[6], snap[7], snap[8],
    ]);
    let slot_index = u32::from_be_bytes([snap[9], snap[10], snap[11], snap[12]]);
    let kind = snap[SIGN_OFFCHAIN_INPUT_KIND_OFF];
    let payload_len = u16::from_be_bytes([
        snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF],
        snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_LEN_OFF + 1],
    ]) as usize;

    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }
    if SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF + payload_len != total_len {
        crate::ui::show_status("EIP-1271", "bad payload_len");
        return NscStatus::InvalidPointer as u32;
    }

    // Per-kind payload constraints. Bound checks first so kind-specific
    // hash construction never sees out-of-range data.
    match kind {
        OFFCHAIN_KIND_RAW32 => {
            if payload_len != 32 {
                crate::ui::show_status("EIP-1271", "raw32 needs 32 B");
                return NscStatus::InvalidPointer as u32;
            }
        }
        OFFCHAIN_KIND_PERSONAL_SIGN => {
            if payload_len > MAX_OFFCHAIN_PERSONAL_SIGN_LEN {
                crate::ui::show_status("EIP-1271", "msg too long");
                return NscStatus::InvalidPointer as u32;
            }
        }
        _ => {
            crate::ui::show_status("EIP-1271", "bad kind");
            return NscStatus::InvalidPointer as u32;
        }
    }

    let payload = &snap[SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF..SIGN_OFFCHAIN_INPUT_PAYLOAD_OFF + payload_len];

    // ── 5. Slot key + registration probe ────────────────────────────
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);
    if !crate::offchain_state::offchain_count_is_registered(&slot_flash_key) {
        crate::ui::show_status("EIP-1271", "slot unregistered");
        return NscStatus::OffchainSlotUnregistered as u32;
    }

    // ── 6. Gap + cap checks (firmware-side defence in depth) ────────
    let last_userop = crate::offchain_state::last_userop_count_read(&slot_flash_key);
    let mut local_offchain = crate::offchain_state::offchain_count_read(&slot_flash_key);
    if last_userop > local_offchain {
        if crate::offchain_state::offchain_count_promote_to(&slot_flash_key, last_userop)
            .is_err()
        {
            crate::ui::show_status("EIP-1271", "repair fail");
            return NscStatus::InternalError as u32;
        }
        local_offchain = last_userop;
    }
    let gap = local_offchain.saturating_sub(last_userop);
    if gap >= MAX_OFFCHAIN_GAP {
        crate::ui::show_status("EIP-1271", "publish first");
        return NscStatus::OffchainGapExceeded as u32;
    }
    let new_count = match local_offchain.checked_add(1) {
        Some(v) => v,
        None => return NscStatus::OffchainCapExceeded as u32,
    };
    if new_count > MAX_SLOT_USES {
        crate::ui::show_status("EIP-1271", "slot exhausted");
        return NscStatus::OffchainCapExceeded as u32;
    }

    // ── 7. Reconstruct entropy + slot master per-account ────────────
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
    let entropy = Zeroizing::new(
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

    // ── 8. PersonalSign hash construction (kind=1) ─────────────────
    //
    // The firmware computes the final replay-safe hash itself from the
    // raw message — that's the whole point of the "show real text"
    // trusted-display contract. It needs the wallet's CREATE2 proxy
    // address, which depends on the bootstrap C10 pubkey for this
    // account. We pull it from `bootstrap_cache` if warm and derive on
    // demand otherwise (<1 s on first hit per session).
    //
    // For kind=0 (raw32) we just sign the 32 bytes verbatim.
    let mut hash_to_sign = [0u8; 32];
    let mut wallet_addr = [0u8; 20];
    match kind {
        OFFCHAIN_KIND_RAW32 => {
            hash_to_sign.copy_from_slice(payload);
        }
        OFFCHAIN_KIND_PERSONAL_SIGN => {
            // Look up bootstrap pubkey; derive on miss.
            let cached =
                super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
            let (master_pk_seed_32, master_pk_root_32) = match cached {
                Some(pair) => pair,
                None => {
                    crate::ui::show_progress("C10 keygen", 0);
                    let (c10_sk, pk_seed_32, pk_root_32) =
                        crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                            &*entropy,
                            account_index,
                            |p| crate::ui::show_progress("C10 keygen", p),
                        );
                    drop(c10_sk); // ZeroizeOnDrop wipes sk_seed.
                    super::state::with_state(|s| {
                        s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
                    });
                    (pk_seed_32, pk_root_32)
                }
            };
            wallet_addr = crate::aa::eip1271::proxy_address(&master_pk_seed_32, &master_pk_root_32);
            hash_to_sign = crate::aa::eip1271::personal_sign_replay_safe_hash(
                chain_id, &wallet_addr, payload,
            );
        }
        _ => return NscStatus::InternalError as u32, // unreachable past §4
    }

    // ── 9. Trusted-display confirmation ─────────────────────────────
    {
        use crate::ui::confirm::{confirm, ConfirmResult};
        let pages = match kind {
            OFFCHAIN_KIND_PERSONAL_SIGN => crate::tx::display::render_eip1271_personal_sign_pages(
                chain_id,
                account_index,
                slot_index,
                &wallet_addr,
                payload,
                new_count,
                last_userop,
                MAX_SLOT_USES,
            ),
            _ => crate::tx::display::render_eip1271_raw32_pages(
                chain_id,
                account_index,
                slot_index,
                &hash_to_sign,
                new_count,
                last_userop,
                MAX_SLOT_USES,
            ),
        };
        match confirm(pages.as_slice()) {
            ConfirmResult::Confirmed => {}
            ConfirmResult::Cancelled => {
                crate::ui::show_status("Cancelled", "");
                return NscStatus::UserRejected as u32;
            }
            ConfirmResult::IdleWipe => {
                super::zeroize_sensitive_state();
                return NscStatus::IdleWipe as u32;
            }
        }
    }

    // ── 10. Slot C10 keygen (shared cache with cmd_sign_userop) ────
    let need_keygen = super::state::peek_state(|_| {
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
        crate::ui::show_progress("Slot keygen", 0);
        let (slot_sk, _slot_pk_seed_32, _slot_pk_root_32) =
            crate::crypto::derive_c10_slot_keypair_with_progress(
                &*slot_master_entropy,
                chain_id,
                slot_index,
                |p| crate::ui::show_progress("Slot keygen", p),
            );
        // SAFETY: single-threaded gateway.
        *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
            account_index,
            chain_id,
            slot_index,
            key: slot_sk,
        });
        super::state::with_state(|s| {
            s.slot_master_entropy.zeroize();
            s.slot_master_entropy = *slot_master_entropy;
            s.slot_master_derived = true;
        });
    }

    // ── 11. C10 sign ────────────────────────────────────────────────
    crate::ui::show_progress("EIP-1271 sign", 0);
    let sig = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => return NscStatus::InternalError as u32,
        };
        match crate::crypto::c10_sign_verified_with_progress(
            slot_ref,
            &hash_to_sign,
            |p| crate::ui::show_progress("EIP-1271 sign", p),
        ) {
            Ok(s) => s,
            Err(_) => return NscStatus::CryptoError as u32,
        }
    };
    debug_assert_eq!(sig.len(), SIGNATURE_LEN);

    // ── 12. FI-hardened verify-before-release ──────────────────────
    let (v1, v2) = {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        let slot_ref = match cached {
            Some(c) => &c.key,
            None => return NscStatus::InternalError as u32,
        };
        let v1 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &hash_to_sign, &sig);
        crate::fi::wait_random();
        let v2 = sphincs_c10::verify(slot_ref.pk_seed(), slot_ref.pk_root(), &hash_to_sign, &sig);
        (v1, v2)
    };
    if crate::fi::check_true_into_sentinel(|| v1 && v2) != crate::fi::OK_SENTINEL {
        crate::ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // ── 13. Bump the durable counter AFTER verify ──────────────────
    if crate::offchain_state::offchain_count_bump(&slot_flash_key, new_count).is_err() {
        crate::ui::show_status("Counter bump", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 14. Write response: [count_be8] [c10_sig] ───────────────────
    let count_be = new_count.to_be_bytes();
    for i in 0..8 {
        core::ptr::write_volatile(
            out_ptr.add(SIGN_OFFCHAIN_OUTPUT_COUNT_OFF + i),
            count_be[i],
        );
    }
    for i in 0..SIGNATURE_LEN {
        core::ptr::write_volatile(out_ptr.add(SIGN_OFFCHAIN_OUTPUT_SIG_OFF + i), sig[i]);
    }

    // L-2: wipe the TOCTOU snapshot on exit.
    {
        let buf = &mut *core::ptr::addr_of_mut!(SNAP_BUF);
        for b in buf.iter_mut() {
            *b = 0;
        }
    }

    crate::timeout::reset_activity();
    crate::ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    crate::ui::show_status("PQSigner OS", "Ready");
    NscStatus::Ok as u32
}
