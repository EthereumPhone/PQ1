//! CMD_GET_INIT_CODE — emit the 4280-byte ERC-4337 `initCode` for
//! `(account_index, chain_id)` without running the full UserOp sign.
//!
//! This is the pre-compute half of [`cmd_sign_userop`]'s first-deploy
//! path (`FLAG_INCLUDE_INIT_CODE`). The companion uses it to get a
//! cryptographically-valid initCode up-front so
//! `eth_estimateUserOperationGas` can actually simulate a
//! not-yet-deployed wallet — without this, the factory's on-chain
//! SPHINCS+C10 signature check rejects any placeholder the companion
//! could construct locally (AA13), and gas falls back to conservative
//! hard-coded ceilings that frequently overpay or underpay.
//!
//! The signed message is exactly the one the deploy path of
//! `CMD_SIGN_USEROP` already signs:
//!
//! ```text
//!   sha256("pqwallet-factory-add-slot"
//!          || chain_id(8 BE)
//!          || slot0PkSeed(32)
//!          || slot0PkRoot(32))
//! ```
//!
//! Because SPHINCS+C10 is stateless and the message depends only on
//! `(chain_id, slot0_keys)`, the produced `factorySig` is safely
//! reusable — cache-friendly for the companion, and identical byte-for-
//! byte to what the eventual real sign will emit. That means the
//! estimation pass and the real submission both ship the same
//! `initCode`, which keeps the bundler's gas numbers tight.
//!
//! Security policy:
//!   * Requires `pin_verified` (reads SE-resident entropy).
//!   * No OLED confirmation. The user will confirm the actual
//!     transaction later, in `CMD_SIGN_USEROP`. What this command
//!     produces is a deterministic factory authorisation that
//!     carries no value transfer.
//!   * Per-slot keygen hits the same cache (`SLOT_CACHE`) as
//!     `CMD_SIGN_USEROP`, so a later sign on the same
//!     `(account_index, chain_id)` skips the <1 s keygen.
//!   * `c10_sk` is stack-local and dropped before return; ZeroizeOnDrop
//!     wipes the secret key before the function exits.

use sha2::{Digest, Sha256};
use sphincs_tz_shared::{
    NscStatus, C10_SIG_LEN, MAX_ACCOUNT_INDEX, PQ_CREATE_ACCOUNT_SELECTOR, PQ_INIT_CODE_LEN,
    PQ_SMART_WALLET_FACTORY,
};
use zeroize::{Zeroize, Zeroizing};

use super::ptr_validate::{validate_ns_read_ptr, validate_ns_write_ptr};
use super::state::CachedSlot;
use super::GatewayArgs;

/// Must match `cmd_sign_userop::FACTORY_ADD_SLOT_DOMAIN` and the
/// on-chain `PQSmartWalletFactory.FACTORY_ADD_SLOT_DOMAIN`.
const FACTORY_ADD_SLOT_DOMAIN: &[u8] = b"pqwallet-factory-add-slot";

/// Wire layout of the 12-byte input body.
const INPUT_LEN: usize = 12;

#[inline]
fn sha256(bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(bytes);
    h.finalize().into()
}

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    // HIGH-7 guard: the bootstrap + slot C10 keygens keep stack-local
    // copies of the secret keys alive for ~10 s each. Block SysTick's
    // idle-wipe path from zeroing BSS secrets out from under us.
    let _busy = super::HandlerGuard::enter();

    crate::ui::show_status("InitCode", "validating...");

    // ── 1. Unlock check ──────────────────────────────────────────────
    if !super::state::peek_state(|s| s.pin_verified) {
        crate::ui::show_status("InitCode", "not unlocked");
        return NscStatus::NotInitialized as u32;
    }

    // ── 2. Pointer + length validation ───────────────────────────────
    let in_ptr = args.arg0 as *const u8;
    let out_ptr = args.arg1 as *mut u8;
    let total_len = args.arg2 as usize;

    if total_len != INPUT_LEN {
        crate::ui::show_status("InitCode", "bad length");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_read_ptr(args.arg0, INPUT_LEN) {
        crate::ui::show_status("InitCode", "bad in ptr");
        return NscStatus::InvalidPointer as u32;
    }
    if !validate_ns_write_ptr(args.arg1, PQ_INIT_CODE_LEN) {
        crate::ui::show_status("InitCode", "bad out ptr");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 3. TOCTOU snapshot ──────────────────────────────────────────
    let mut buf = [0u8; INPUT_LEN];
    for i in 0..INPUT_LEN {
        buf[i] = core::ptr::read_volatile(in_ptr.add(i));
    }
    let account_index = u32::from_be_bytes([buf[0], buf[1], buf[2], buf[3]]);
    let chain_id = u64::from_be_bytes([
        buf[4], buf[5], buf[6], buf[7], buf[8], buf[9], buf[10], buf[11],
    ]);
    if account_index > MAX_ACCOUNT_INDEX {
        crate::ui::show_status("InitCode", "bad acct");
        return NscStatus::InvalidPointer as u32;
    }

    // ── 4. Reconstruct entropy + derive slot master per-account ───
    //
    // Mirrors `cmd_sign_userop.rs` §9: every call reads the entropy
    // blob out of the SE, decrypts with the session master_secret,
    // and derives the per-account slot master. The C10 keygens
    // below operate on these.
    let master_secret: Zeroizing<[u8; 32]> =
        Zeroizing::new(super::state::peek_state(|s| s.master_secret));
    let mut entropy_blob = Zeroizing::new([0u8; 64]);
    let entropy_blob_len = {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(crate::SE);
        match se.read_entropy_blob(&mut *entropy_blob) {
            Ok(l) => l,
            Err(_) => {
                crate::ui::show_status("InitCode", "SE read fail");
                return NscStatus::InternalError as u32;
            }
        }
    };
    let entropy = Zeroizing::new(
        match crate::crypto::decrypt_entropy_blob(
            &entropy_blob[..entropy_blob_len],
            &*master_secret,
        ) {
            Ok(e) => e,
            Err(_) => {
                crate::ui::show_status("InitCode", "decrypt fail");
                return NscStatus::CryptoError as u32;
            }
        },
    );
    let slot_master_entropy: Zeroizing<[u8; 32]> = Zeroizing::new(
        crate::crypto::slot_master_entropy_from_entropy(&*entropy, account_index),
    );

    // ── 5. Slot-0 C10 keygen (cached by (account_index, chain_id, 0)) ──
    //
    // Same cache as `cmd_sign_userop`: a subsequent sign on the same
    // (account, chain, slot=0) skips this <1 s keygen.
    const SLOT_INDEX: u32 = 0;
    let need_keygen = super::state::peek_state(|_| {
        let cached = unsafe { &*core::ptr::addr_of!(super::state::SLOT_CACHE) };
        match cached {
            Some(c) => {
                c.account_index != account_index
                    || c.chain_id != chain_id
                    || c.slot_index != SLOT_INDEX
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
                SLOT_INDEX,
                |p| crate::ui::show_progress("Slot keygen", p),
            );
        unsafe {
            *core::ptr::addr_of_mut!(super::state::SLOT_CACHE) = Some(CachedSlot {
                account_index,
                chain_id,
                slot_index: SLOT_INDEX,
                key: slot_sk,
            });
        }
        super::state::with_state(|s| {
            s.slot_master_entropy.zeroize();
            s.slot_master_entropy = *slot_master_entropy;
            s.slot_master_derived = true;
        });
    }

    // Extract 32-byte slot-0 pubkey halves from the cache. Mirrors the
    // extraction in `cmd_sign_userop.rs` (N-byte pkSeed/pkRoot copied
    // into the low 16 bytes of a 32-byte zero-init buffer).
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
                crate::ui::show_status("InitCode", "slot cache MIA");
                return NscStatus::InternalError as u32;
            }
        }
    };

    // ── 6. Bootstrap C10 master keygen ───────────────────────────────
    //
    // Needed both to sign `factorySig` and to fill `masterPkSeed` /
    // `masterPkRoot` in the factory call's ABI args.
    crate::ui::show_progress("C10 keygen", 0);
    let (c10_sk, master_pk_seed_32, master_pk_root_32) =
        crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
            &*entropy,
            account_index,
            |p| crate::ui::show_progress("C10 keygen", p),
        );

    // Refresh the bootstrap pubkey cache so a later
    // `CMD_GET_WALLET_ADDRESS` on this account skips its keygen too.
    super::state::with_state(|s| {
        s.bootstrap_cache_insert(account_index, master_pk_seed_32, master_pk_root_32);
    });

    // ── 7. Sign the factory-add-slot message ─────────────────────────
    crate::ui::show_status("Factory", "signing slot-0");
    let mut factory_msg = [0u8; 25 + 8 + 32 + 32];
    factory_msg[..25].copy_from_slice(FACTORY_ADD_SLOT_DOMAIN);
    factory_msg[25..33].copy_from_slice(&chain_id.to_be_bytes());
    factory_msg[33..65].copy_from_slice(&slot_pk_seed_32);
    factory_msg[65..97].copy_from_slice(&slot_pk_root_32);
    let factory_digest = sha256(&factory_msg);

    let factory_sig = match crate::crypto::c10_sign_verified_with_progress(
        &c10_sk,
        &factory_digest,
        |p| crate::ui::show_progress("C10 sign", p),
    ) {
        Ok(s) => s,
        Err(_) => {
            crate::ui::show_status("InitCode", "C10 sign fail");
            return NscStatus::CryptoError as u32;
        }
    };
    // c10_sk drops here → ZeroizeOnDrop wipes sk_seed on the stack.
    drop(c10_sk);

    // ── 8. Assemble the 4280-byte initCode ───────────────────────────
    //
    // Identical layout to `cmd_sign_userop.rs` §13a. Any divergence
    // here would silently corrupt the submitted deploy; keep the two
    // writers in lock-step.
    let mut ic = Zeroizing::new([0u8; PQ_INIT_CODE_LEN]);
    ic[..20].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    ic[20..24].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
    ic[24..56].copy_from_slice(&master_pk_seed_32);
    ic[56..88].copy_from_slice(&master_pk_root_32);
    ic[88..120].copy_from_slice(&slot_pk_seed_32);
    ic[120..152].copy_from_slice(&slot_pk_root_32);
    // chainId left-padded to uint256 at slot 4.
    ic[152 + 24..184].copy_from_slice(&chain_id.to_be_bytes());
    // Dynamic-bytes head: offset = 6 × 32 = 192 (0xC0); length = 4008.
    let offset_field_start = 24 + 5 * 32;
    ic[offset_field_start + 24..offset_field_start + 32]
        .copy_from_slice(&(6 * 32u64).to_be_bytes());
    let length_field_start = offset_field_start + 32;
    ic[length_field_start + 24..length_field_start + 32]
        .copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());
    let data_start = length_field_start + 32;
    ic[data_start..data_start + C10_SIG_LEN].copy_from_slice(&factory_sig);
    debug_assert_eq!(data_start + 4032, PQ_INIT_CODE_LEN);

    // ── 9. Write output to NS via volatile stores ───────────────────
    for i in 0..PQ_INIT_CODE_LEN {
        core::ptr::write_volatile(out_ptr.add(i), ic[i]);
    }

    crate::ui::show_status("PQSigner OS", "Ready");
    NscStatus::Ok as u32
}
