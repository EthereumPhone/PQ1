//! CMD_GET_WALLET_ADDRESS — compute the CREATE2-predicted wallet address
//! from the firmware-embedded factory + proxy-init-code-hash constants
//! and the bootstrap C10 pubkey.
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
//! Requires an unlocked device. First call after unlock triggers
//! bootstrap C10 keygen (~6 s on hardware) and caches the result in
//! `SecureState`; subsequent calls reuse the cache and return in <1 ms.

use sha2::{Digest, Sha256};
use sha3::Keccak256;
use sphincs_tz_shared::{NscStatus, PQ_SMART_WALLET_FACTORY, PROXY_INIT_CODE_HASH};
use zeroize::Zeroizing;

use super::ptr_validate::validate_ns_write_ptr;
use super::GatewayArgs;

/// Output length: a 20-byte Ethereum address.
const ADDR_LEN: usize = 20;

pub(super) unsafe fn run(args: &GatewayArgs) -> u32 {
    if !super::state::peek_state(|s| s.pin_verified) {
        return NscStatus::NotInitialized as u32;
    }

    let out_ptr = args.arg0 as *mut u8;
    if !validate_ns_write_ptr(args.arg0, ADDR_LEN) {
        return NscStatus::InvalidPointer as u32;
    }

    // ── 1. Ensure bootstrap C10 pubkey is cached ──────────────────────
    let already_cached = super::state::peek_state(|s| s.bootstrap_pk_cached);
    if !already_cached {
        // Derive entropy → bootstrap C10 keypair. Mirrors
        // cmd_sign_userop's §7 + §11 but keeps only the pubkey halves.
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
                |p| crate::ui::show_progress("Wallet addr", p),
            );
        // _c10_sk drops here → ZeroizeOnDrop wipes sk_seed on the stack.

        super::state::with_state(|s| {
            s.bootstrap_pk_seed = pk_seed_32;
            s.bootstrap_pk_root = pk_root_32;
            s.bootstrap_pk_cached = true;
        });
    }

    // ── 2. CREATE2 formula ─────────────────────────────────────────────
    let (pk_seed, pk_root) = super::state::peek_state(|s| {
        (s.bootstrap_pk_seed, s.bootstrap_pk_root)
    });

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

    NscStatus::Ok as u32
}
