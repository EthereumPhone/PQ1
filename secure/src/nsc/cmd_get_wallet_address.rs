//! CMD_GET_WALLET_ADDRESS — compute the CREATE2-predicted wallet address
//! for a given `account_index` from the firmware-embedded factory +
//! proxy-init-code-hash constants and the bootstrap C10 pubkey.
//!
//! This lets the companion discover the sender address WITHOUT having
//! to do a full sign first just to extract `masterPkSeed` / `masterPkRoot`
//! from an emitted initCode. The numbers baked into the firmware
//! (`PQ_SMART_WALLET_FACTORY`, `PROXY_INIT_CODE_HASH`) are CREATE2-stable
//! across chains, so one formula covers every deploy target.
//!
//! Formula (mirrors `PQSmartWalletFactory.getAddress`):
//!   salt    = sha256(masterPkSeed(32) || masterPkRoot(32))
//!   initHash = PROXY_INIT_CODE_HASH
//!   address = keccak256(0xff || factory || salt || initHash)[12..]
//!
//! Requires an unlocked device. First call for a given `account_index`
//! triggers bootstrap C10 keygen (<1 s on hardware) and caches the
//! resulting pubkey halves in `SecureState::bootstrap_cache` (LRU,
//! capacity `BOOTSTRAP_CACHE_LEN`); subsequent calls reuse the cache
//! and return in <1 ms.
//!
//! `account_index` MUST be in `0..=MAX_ACCOUNT_INDEX` (8 bits). Account
//! 0 reproduces the legacy single-account derivation byte-for-byte so
//! pre-multi-account seeds keep their existing on-chain address.

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sphincs_tz_shared::{
    NscStatus, MAX_ACCOUNT_INDEX, PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH,
};
use zeroize::Zeroizing;

use super::ptr_validate::validate_ns_write_ptr;
use super::GatewayArgs;

/// Output length: a 20-byte Ethereum address.
const ADDR_LEN: usize = 20;

/// # Safety
/// CMSE non-secure-entry handler — dispatcher-invoked. NS pointer
/// deref happens only after `validate_ns_write_ptr`; `static mut SE`
/// access uses the single-threaded dispatcher invariant.
pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let out_ptr = args.arg0 as *mut u8;
    if !validate_ns_write_ptr(args.arg0, ADDR_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // arg1 carries the account_index (0..=255). Anything above the mask
    // is a wire-format error — the companion is supposed to mask before
    // sending. Refuse rather than silently truncating, so a stale
    // companion paying no attention to the new field doesn't quietly
    // alias account 256 onto account 0.
    let account_index = args.arg1;
    if account_index > MAX_ACCOUNT_INDEX {
        return NscStatus::InvalidPointer as u32;
    }

    // ── 1. Ensure bootstrap C10 pubkey for `account_index` is cached ──
    let cached = super::state::with_state(|s| s.bootstrap_cache_lookup(account_index));
    let mut showed_progress = false;
    let (pk_seed, pk_root) = match cached {
        Some(pair) => pair,
        None => {
            showed_progress = true;
            // Cache miss: derive entropy → bootstrap C10 keypair for
            // this specific account_index. Mirrors cmd_sign_userop's
            // §7 + §11 but keeps only the pubkey halves.
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

            crate::ui::show_progress("Wallet addr", 0);
            let (_c10_sk, pk_seed_32, pk_root_32) =
                crate::crypto::derive_c10_master_keypair_from_entropy_with_progress(
                    &*entropy,
                    account_index,
                    |p| crate::ui::show_progress("Wallet addr", p),
                );
            // _c10_sk drops here → ZeroizeOnDrop wipes sk_seed on the stack.

            super::state::with_state(|s| {
                s.bootstrap_cache_insert(account_index, pk_seed_32, pk_root_32);
            });
            (pk_seed_32, pk_root_32)
        }
    };

    // ── 2. CREATE2 formula ─────────────────────────────────────────────
    // salt = sha256(pkSeed(32) || pkRoot(32))
    let mut salt_in = [0u8; 64];
    salt_in[..32].copy_from_slice(&pk_seed);
    salt_in[32..].copy_from_slice(&pk_root);
    let salt: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(salt_in);
        h.finalize().into()
    };

    // preimage = 0xff || factory(20) || salt(32) || PROXY_INIT_CODE_HASH(32)
    let mut pre = [0u8; 1 + 20 + 32 + 32];
    pre[0] = 0xff;
    pre[1..21].copy_from_slice(&PQ_SMART_WALLET_FACTORY);
    pre[21..53].copy_from_slice(&salt);
    pre[53..85].copy_from_slice(&PROXY_INIT_CODE_HASH);
    let digest: [u8; 32] = {
        use sha3::Digest as _;
        let mut h = Keccak256::new();
        h.update(pre);
        h.finalize().into()
    };

    // ── 3. Write low 20 bytes to NS buffer ─────────────────────────────
    for i in 0..ADDR_LEN {
        core::ptr::write_volatile(out_ptr.add(i), digest[12 + i]);
    }

    if showed_progress {
        crate::ui::show_status("PQSigner OS", "Ready");
    }

    NscStatus::Ok as u32
}
