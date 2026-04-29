//! CMD_SIGN_OFFCHAIN — produce a SPHINCS+C10 signature over an
//! arbitrary 32-byte hash for EIP-1271 (off-chain) verification.
//!
//! The companion is responsible for computing the
//! EIP-712-nested-replay-safe hash (see Solady's
//! `ERC1271._erc1271IsValidSignatureViaNestedEIP712`) before calling
//! this command. The firmware just signs the 32-byte hash; it never
//! interprets it. Because of that, replay protection is enforced
//! solely by the on-chain wallet's domain separator — a sig captured
//! against wallet A on chain X cannot verify against wallet B (same
//! seed, different `account_index`) or against wallet A on chain Y.
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
    NscStatus, MAX_ACCOUNT_INDEX, MAX_OFFCHAIN_GAP, MAX_SLOT_USES, SIGN_OFFCHAIN_INPUT_HASH_OFF,
    SIGN_OFFCHAIN_INPUT_LEN, SIGN_OFFCHAIN_OUTPUT_COUNT_OFF, SIGN_OFFCHAIN_OUTPUT_LEN,
    SIGN_OFFCHAIN_OUTPUT_SIG_OFF, SIGNATURE_LEN,
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

    if total_len != SIGN_OFFCHAIN_INPUT_LEN {
        crate::ui::show_status("EIP-1271", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, SIGN_OFFCHAIN_INPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, SIGN_OFFCHAIN_OUTPUT_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    let mut buf = [0u8; SIGN_OFFCHAIN_INPUT_LEN];
    for i in 0..SIGN_OFFCHAIN_INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = buf[0] as u32;
    let chain_id = u64::from_be_bytes([
        buf[1], buf[2], buf[3], buf[4], buf[5], buf[6], buf[7], buf[8],
    ]);
    let slot_index = u32::from_be_bytes([buf[9], buf[10], buf[11], buf[12]]);
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }
    let mut hash_to_sign = [0u8; 32];
    hash_to_sign.copy_from_slice(&buf[SIGN_OFFCHAIN_INPUT_HASH_OFF..SIGN_OFFCHAIN_INPUT_HASH_OFF + 32]);

    // ── 4. Slot key + registration probe ────────────────────────────
    //
    // After a seed-restore the new firmware has no flash record of
    // any old slot, so the only slots it will sign for are ones
    // registered (via CMD_SIGN_USEROP with FLAG_REGISTER_SLOT) since
    // boot. This bounds `last_userop_count - 0` for those slots and
    // gives the cap calculation a known floor.
    let slot_flash_key =
        crate::offchain_state::slot_key_compute(account_index as u8, chain_id, slot_index);
    if !crate::offchain_state::offchain_count_is_registered(&slot_flash_key) {
        crate::ui::show_status("EIP-1271", "slot unregistered");
        return NscStatus::OffchainSlotUnregistered as u32;
    }

    // ── 5. Gap + cap checks (firmware-side defence in depth) ────────
    //
    // Re-assert the invariant `local_offchain >= last_userop` before
    // consuming an off-chain budget slot. If a flash event has left
    // local_offchain stale, bumping from the lower value would later
    // starve the next Type 2's monotonicity check on-chain (and would
    // wrongly under-count the gap here, allowing more unbacked
    // off-chain sigs than the design permits). Promotion is
    // idempotent if the invariant already holds.
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

    // ── 5b. Trusted-display confirmation ────────────────────────────
    //
    // EIP-1271 sigs are silent-but-binding from the dapp's view, so the
    // user must approve them on the trusted display the same way they
    // approve a UserOp. We surface (chain, account, slot), the full 32
    // bytes of the hash that's about to be signed, and the slot's
    // off-chain budget context. The companion is responsible for
    // deriving the hash via Solady's nested EIP-712 wrap before calling
    // this command — we cannot interpret what the dapp ultimately
    // commits to, but the user can compare these 64 hex chars against
    // whatever the dapp shows.
    {
        use crate::ui::confirm::{confirm, ConfirmResult};
        let pages = crate::tx::display::render_eip1271_pages(
            chain_id,
            account_index,
            slot_index,
            &hash_to_sign,
            new_count,
            last_userop,
            MAX_SLOT_USES,
        );
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

    // ── 6. Reconstruct entropy + slot master per-account ────────────
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

    // ── 7. Slot C10 keygen (shared cache with cmd_sign_userop) ──────
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

    // ── 8. C10 sign (no re-hash — companion already wrapped) ────────
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

    // ── 9. FI-hardened verify-before-release (mirrors cmd_sign_userop) ──
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
    crate::fi::wait_random();
    let ok_sentinel: u32 = if v1 && v2 {
        crate::fi::OK_SENTINEL
    } else {
        crate::fi::FAIL_SENTINEL
    };
    if ok_sentinel != crate::fi::OK_SENTINEL || !v1 || !v2 {
        crate::ui::show_status("Sig verify", "FAIL");
        return NscStatus::CryptoError as u32;
    }

    // ── 10. Bump the durable counter AFTER verify ──────────────────
    if crate::offchain_state::offchain_count_bump(&slot_flash_key, new_count).is_err() {
        crate::ui::show_status("Counter bump", "FAIL");
        return NscStatus::InternalError as u32;
    }

    // ── 11. Write response: [count_be8] [c10_sig] ───────────────────
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

    crate::timeout::reset_activity();
    crate::ui::show_status("Signed", "");
    for _ in 0..3_000_000u32 {
        cortex_m::asm::nop();
    }
    crate::ui::show_status("PQSigner OS", "Ready");
    NscStatus::Ok as u32
}
