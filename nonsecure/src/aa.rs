//! Non-secure-side helpers for ERC-4337 Account Abstraction signing.
//!
//! These helpers do *not* compute the final `userOpHash` — that is the
//! secure world's job (and a hostile NS would otherwise be able to
//! convince the trusted UI to confirm one tx while the device signed
//! another). All this module does is *pack* the AA wrapper parameters
//! and the inner unsigned EIP-1559 envelope into the wire format that
//! `cmd_sign_userop` expects, so application code can hand a single
//! contiguous buffer to [`crate::nsc_api::sign_userop`].
//!
//! See `sphincs_tz_shared::CMD_SIGN_USEROP` for the canonical layout
//! and `secure/src/aa/userop.rs` for the matching parser.

use sphincs_tz_shared::{USEROP_HEADER_LEN, USEROP_PREFIX_LEN};

/// All AA wrapper parameters that the secure world needs to recompute
/// the EntryPoint v0.6 `userOpHash`. Every `u256` is wired in
/// big-endian to match the EVM ABI; pass them through verbatim from
/// whatever the bundler/RPC returned.
#[derive(Clone, Copy)]
pub struct UserOpWrapper<'a> {
    pub sender: &'a [u8; 20],
    pub entry_point: &'a [u8; 20],
    pub chain_id: u64,
    pub nonce: &'a [u8; 32],
    pub call_gas_limit: &'a [u8; 32],
    pub verification_gas_limit: &'a [u8; 32],
    pub pre_verification_gas: &'a [u8; 32],
    pub max_fee_per_gas: &'a [u8; 32],
    pub max_priority_fee_per_gas: &'a [u8; 32],
    /// `keccak256(initCode)`. For an already-deployed wallet this is
    /// `keccak256("")` = `0xc5d246...`.
    pub init_code_hash: &'a [u8; 32],
    /// `keccak256(paymasterAndData)`. For a self-funded UserOp this is
    /// `keccak256("")` too.
    pub paymaster_and_data_hash: &'a [u8; 32],
}

/// keccak256("") — the canonical "empty bytes" hash. The Solidity ABI
/// hashes empty `initCode` / `paymasterAndData` to this value, and the
/// vast majority of UserOps after first deployment use it for both
/// fields.
pub const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// Pack a UserOp wrapper + an inner unsigned EIP-1559 envelope into the
/// wire format expected by `cmd_sign_userop`, *without* an attached
/// ERC-20 metadata bundle.
///
/// Returns the number of bytes written to `out`. Panics if `out` is
/// too small.
pub fn build_userop_payload(
    wrap: &UserOpWrapper<'_>,
    unsigned_tx: &[u8],
    out: &mut [u8],
) -> usize {
    let need = USEROP_PREFIX_LEN + unsigned_tx.len();
    assert!(out.len() >= need, "build_userop_payload: out too small");

    out[0] = 0u8; // has_bundle = false
    write_header(wrap, &mut out[..USEROP_HEADER_LEN]);
    out[USEROP_HEADER_LEN..USEROP_HEADER_LEN + 4]
        .copy_from_slice(&(unsigned_tx.len() as u32).to_le_bytes());
    out[USEROP_PREFIX_LEN..USEROP_PREFIX_LEN + unsigned_tx.len()].copy_from_slice(unsigned_tx);
    need
}

/// Same as [`build_userop_payload`] but with an attached (already
/// looked-up by `crate::erc20_db`) ERC-20 metadata bundle so the
/// trusted UI can decode the inner ERC-20 call.
pub fn build_userop_payload_with_bundle(
    wrap: &UserOpWrapper<'_>,
    unsigned_tx: &[u8],
    bundle: &[u8],
    out: &mut [u8],
) -> usize {
    let need = USEROP_PREFIX_LEN + unsigned_tx.len() + 4 + bundle.len();
    assert!(
        out.len() >= need,
        "build_userop_payload_with_bundle: out too small"
    );

    out[0] = 1u8; // has_bundle = true
    write_header(wrap, &mut out[..USEROP_HEADER_LEN]);
    out[USEROP_HEADER_LEN..USEROP_HEADER_LEN + 4]
        .copy_from_slice(&(unsigned_tx.len() as u32).to_le_bytes());
    let tx_off = USEROP_PREFIX_LEN;
    out[tx_off..tx_off + unsigned_tx.len()].copy_from_slice(unsigned_tx);
    let bl_off = tx_off + unsigned_tx.len();
    out[bl_off..bl_off + 4].copy_from_slice(&(bundle.len() as u32).to_le_bytes());
    out[bl_off + 4..bl_off + 4 + bundle.len()].copy_from_slice(bundle);
    need
}

fn write_header(w: &UserOpWrapper<'_>, out: &mut [u8]) {
    debug_assert_eq!(out.len(), USEROP_HEADER_LEN);
    let mut p = 1usize; // skip has_bundle
    out[p..p + 20].copy_from_slice(w.sender);
    p += 20;
    out[p..p + 20].copy_from_slice(w.entry_point);
    p += 20;
    out[p..p + 8].copy_from_slice(&w.chain_id.to_be_bytes());
    p += 8;
    out[p..p + 32].copy_from_slice(w.nonce);
    p += 32;
    out[p..p + 32].copy_from_slice(w.call_gas_limit);
    p += 32;
    out[p..p + 32].copy_from_slice(w.verification_gas_limit);
    p += 32;
    out[p..p + 32].copy_from_slice(w.pre_verification_gas);
    p += 32;
    out[p..p + 32].copy_from_slice(w.max_fee_per_gas);
    p += 32;
    out[p..p + 32].copy_from_slice(w.max_priority_fee_per_gas);
    p += 32;
    out[p..p + 32].copy_from_slice(w.init_code_hash);
    p += 32;
    out[p..p + 32].copy_from_slice(w.paymaster_and_data_hash);
    p += 32;
    debug_assert_eq!(p, USEROP_HEADER_LEN);
}
