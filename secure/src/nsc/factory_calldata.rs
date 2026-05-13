//! Build the `PQSmartWalletFactory.createAccount(...)` calldata that
//! both `cmd_get_init_code` (initCode = `factory_addr || calldata`) and
//! `cmd_sign_offchain` (ERC-6492 `factoryCalldata` field for the
//! counterfactual path) need to emit byte-for-byte identically.
//!
//! Centralising the layout here keeps the on-chain ABI invariant in one
//! place — any divergence between the two callers would silently
//! corrupt either the first-deploy initCode or every ERC-6492 wrapped
//! sig the device emits for a non-deployed wallet.
//!
//! Output layout (4260 bytes = `EIP6492_FACTORY_CALLDATA_LEN`):
//!
//! ```text
//!   [   0..   4)  PQ_CREATE_ACCOUNT_SELECTOR
//!   [   4..  36)  masterPkSeed (bytes32)
//!   [  36..  68)  masterPkRoot (bytes32)
//!   [  68.. 100)  slot0PkSeed  (bytes32)
//!   [ 100.. 132)  slot0PkRoot  (bytes32)
//!   [ 132.. 164)  chainId      (uint64 left-padded to uint256)
//!   [ 164.. 196)  bytes offset = 0xC0   (= head size, 6 × 32)
//!   [ 196.. 228)  bytes length = C10_SIG_LEN
//!   [ 228..4260)  factory sig data, zero-padded to next 32-byte boundary
//! ```

use sha2::{Digest, Sha256};
use sphincs_tz_shared::{
    C10_SIG_LEN, EIP6492_FACTORY_CALLDATA_LEN, FACTORY_ADD_SLOT_DOMAIN, NscStatus,
    PQ_CREATE_ACCOUNT_SELECTOR,
};

/// Build the 4260-byte `createAccount(...)` calldata into `out`.
///
/// The caller is responsible for deriving the bootstrap + slot-0 C10
/// key material (this helper does not touch the SE or the slot cache).
/// On success the trailing bytes of `out` past the signature data are
/// zero (ABI tail padding).
pub(super) fn build(
    out: &mut [u8; EIP6492_FACTORY_CALLDATA_LEN],
    chain_id: u64,
    master_c10_sk: &sphincs_c10::SigningKey,
    master_pk_seed_32: &[u8; 32],
    master_pk_root_32: &[u8; 32],
    slot0_pk_seed_32: &[u8; 32],
    slot0_pk_root_32: &[u8; 32],
    progress: fn(u8),
) -> Result<(), NscStatus> {
    out.fill(0);

    out[..4].copy_from_slice(&PQ_CREATE_ACCOUNT_SELECTOR);
    out[4..36].copy_from_slice(master_pk_seed_32);
    out[36..68].copy_from_slice(master_pk_root_32);
    out[68..100].copy_from_slice(slot0_pk_seed_32);
    out[100..132].copy_from_slice(slot0_pk_root_32);

    // chainId — uint64 left-padded to uint256.
    out[132 + 24..164].copy_from_slice(&chain_id.to_be_bytes());

    // Dynamic-bytes head: offset = head_size = 6 × 32 = 0xC0.
    out[164 + 24..196].copy_from_slice(&(6u64 * 32).to_be_bytes());

    // Dynamic-bytes length = C10_SIG_LEN.
    out[196 + 24..228].copy_from_slice(&(C10_SIG_LEN as u64).to_be_bytes());

    // Sign the factory-add-slot digest with the bootstrap C10 key.
    let mut factory_msg = [0u8; 25 + 8 + 32 + 32];
    debug_assert_eq!(FACTORY_ADD_SLOT_DOMAIN.len(), 25);
    factory_msg[..25].copy_from_slice(FACTORY_ADD_SLOT_DOMAIN);
    factory_msg[25..33].copy_from_slice(&chain_id.to_be_bytes());
    factory_msg[33..65].copy_from_slice(slot0_pk_seed_32);
    factory_msg[65..97].copy_from_slice(slot0_pk_root_32);
    let factory_digest: [u8; 32] = {
        let mut h = Sha256::new();
        h.update(factory_msg);
        h.finalize().into()
    };

    let factory_sig =
        crate::crypto::c10_sign_verified_with_progress(master_c10_sk, &factory_digest, progress)
            .map_err(|_| NscStatus::CryptoError)?;

    out[228..228 + C10_SIG_LEN].copy_from_slice(&factory_sig);

    // Sanity: padding from 228 + 4008 = 4236 to 4260 is zero (already from fill(0)).
    debug_assert_eq!(228 + C10_SIG_LEN, 4236);
    debug_assert_eq!(EIP6492_FACTORY_CALLDATA_LEN, 4260);

    Ok(())
}
