//! ERC-4337 v0.6 `UserOperation` hash construction (FIPS-205-friendly).
//!
//! Reference: <https://eips.ethereum.org/EIPS/eip-4337>
//!
//! `EntryPoint v0.6` defines the user-operation hash as
//!
//! ```text
//!   userOpHash = keccak256(abi.encode(
//!       hashStruct(userOp),
//!       entryPoint,
//!       chainId
//!   ))
//! ```
//!
//! where
//!
//! ```text
//!   hashStruct(userOp) = keccak256(abi.encode(
//!       sender,                                    // address
//!       nonce,                                     // uint256
//!       keccak256(initCode),                       // bytes32
//!       keccak256(callData),                       // bytes32
//!       callGasLimit,                              // uint256
//!       verificationGasLimit,                      // uint256
//!       preVerificationGas,                        // uint256
//!       maxFeePerGas,                              // uint256
//!       maxPriorityFeePerGas,                      // uint256
//!       keccak256(paymasterAndData)                // bytes32
//!   ))
//! ```
//!
//! `abi.encode(...)` of static-only types (no bytes/string/dynamic
//! arrays) is just the concatenation of each element padded to 32
//! bytes, so this whole thing reduces to a fixed 320-byte buffer (10
//! 32-byte slots) hashed twice.
//!
//! All the heavy lifting therefore happens in two helpers:
//!
//!   * [`reconstruct_execute_calldata`] — takes a parsed inner EIP-1559
//!     transaction and rebuilds the canonical
//!     `execute(address,uint256,bytes)` calldata that the smart
//!     account will run when the EntryPoint dispatches it.
//!   * [`compute_user_op_hash`] — takes the AA wrapper parameters plus
//!     `keccak256(callData)` and produces the final `userOpHash`.
//!
//! Both helpers are pure: no SE access, no UI, no signing. They are
//! exercised directly from the e2e harness via the gateway command in
//! `nsc::cmd_sign_userop`.

use crate::tx::eip1559::{Eip1559Tx, U256};
use crate::tx::hash::keccak256;

use sha3::{Digest, Keccak256};

/// Selector for `execute(address,uint256,bytes)` on
/// {PQCoinbaseSmartWallet}. This matches the upstream Coinbase Smart
/// Wallet exactly: it's the first four bytes of
/// `keccak256("execute(address,uint256,bytes)")`. We hardcode it
/// instead of computing it at runtime to keep the hot path
/// allocation-free and to make it easy to grep for from a security
/// review.
pub const EXECUTE_SELECTOR: [u8; 4] = [0xb6, 0x1d, 0x27, 0xf6];

/// Maximum supported reconstructed-callData length.
///
/// EXECUTE selector (4) + abi.encode(address (32), uint256 (32),
/// offset (32), len (32), data padded to next 32-byte boundary).
/// `MAX_TX_LEN` (4096) bounds the inner data, plus rounding gives 4128
/// for the data tail; the static prefix is 4+32+32+32+32 = 132. We
/// round up to a 4 KiB-friendly buffer.
pub const MAX_EXECUTE_CALLDATA_LEN: usize = 4 * 1024 + 256;

/// Stack-friendly buffer for a reconstructed `execute(...)` calldata.
///
/// The buffer is fixed-size (`MAX_EXECUTE_CALLDATA_LEN` bytes) so
/// callers don't need an allocator; the actual valid range is
/// `..len`.
pub struct ExecuteCallData {
    pub buf: [u8; MAX_EXECUTE_CALLDATA_LEN],
    pub len: usize,
}

impl ExecuteCallData {
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum AaError {
    /// Inner tx was a contract-creation (`to == None`); cannot wrap as
    /// `execute(address,uint256,bytes)`.
    ContractCreation,
    /// Inner tx data is larger than the secure-world buffer can hold
    /// after ABI padding.
    CallDataTooLong,
}

/// Build the canonical
/// `execute(address target, uint256 value, bytes data)` calldata for
/// the parsed inner EIP-1559 envelope.
///
/// The returned bytes match what `abi.encodeCall(execute, (target,
/// value, data))` produces in Solidity, byte-for-byte:
///
/// ```text
///   [  0..  4) selector ("b61d27f6")
///   [  4.. 36) target address, left-padded to 32 bytes
///   [ 36.. 68) value (uint256, big-endian)
///   [ 68..100) head offset of `bytes data`, always 0x60
///   [100..132) length of `data` as uint256
///   [132..   ) data, padded with zero bytes to a 32-byte boundary
/// ```
pub fn reconstruct_execute_calldata(
    tx: &Eip1559Tx,
    data: &[u8],
) -> Result<ExecuteCallData, AaError> {
    let target = tx.to.ok_or(AaError::ContractCreation)?;

    // Padded data length, rounded up to a 32-byte word.
    let padded_data_len = data.len().checked_add(31).ok_or(AaError::CallDataTooLong)? & !31usize;
    let total = 4 + 32 + 32 + 32 + 32 + padded_data_len;
    if total > MAX_EXECUTE_CALLDATA_LEN {
        return Err(AaError::CallDataTooLong);
    }

    let mut out = ExecuteCallData {
        buf: [0u8; MAX_EXECUTE_CALLDATA_LEN],
        len: total,
    };

    // selector
    out.buf[0..4].copy_from_slice(&EXECUTE_SELECTOR);
    // target — left-padded to 32 bytes (12 zero bytes + 20 address bytes)
    out.buf[4 + 12..4 + 32].copy_from_slice(&target);
    // value — already big-endian inside U256
    out.buf[4 + 32..4 + 64].copy_from_slice(&tx.value.0);
    // bytes head offset (always 0x60 = 96)
    out.buf[4 + 64 + 31] = 0x60;
    // bytes length
    let len_bytes = (data.len() as u64).to_be_bytes();
    out.buf[4 + 96 + 24..4 + 96 + 32].copy_from_slice(&len_bytes);
    // bytes payload, zero-padded to 32-byte boundary by virtue of the
    // already-zeroed buffer.
    out.buf[4 + 128..4 + 128 + data.len()].copy_from_slice(data);

    Ok(out)
}

/// Parameters carried in `cmd_sign_userop`'s wire payload that the
/// secure world feeds into the userOpHash construction.
///
/// All `U256`s are stored in their on-wire big-endian form so the
/// secure world can splice them straight into the `abi.encode(...)`
/// buffer without re-serialising.
#[derive(Debug)]
pub struct AaUserOpParams {
    pub sender: [u8; 20],
    pub entry_point: [u8; 20],
    pub chain_id: u64,
    pub nonce: U256,
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub init_code_hash: [u8; 32],
    pub paymaster_and_data_hash: [u8; 32],
}

/// Compute the EntryPoint v0.6 `userOpHash` for the given AA params
/// and the keccak256 of the (already reconstructed) callData.
pub fn compute_user_op_hash(params: &AaUserOpParams, call_data_hash: &[u8; 32]) -> [u8; 32] {
    // hashStruct(userOp) — 10 × 32 = 320 bytes total.
    let mut buf = [0u8; 320];

    // sender, left-padded to 32 bytes
    buf[12..32].copy_from_slice(&params.sender);
    // nonce
    buf[32..64].copy_from_slice(&params.nonce.0);
    // keccak256(initCode)
    buf[64..96].copy_from_slice(&params.init_code_hash);
    // keccak256(callData)
    buf[96..128].copy_from_slice(call_data_hash);
    // callGasLimit
    buf[128..160].copy_from_slice(&params.call_gas_limit.0);
    // verificationGasLimit
    buf[160..192].copy_from_slice(&params.verification_gas_limit.0);
    // preVerificationGas
    buf[192..224].copy_from_slice(&params.pre_verification_gas.0);
    // maxFeePerGas
    buf[224..256].copy_from_slice(&params.max_fee_per_gas.0);
    // maxPriorityFeePerGas
    buf[256..288].copy_from_slice(&params.max_priority_fee_per_gas.0);
    // keccak256(paymasterAndData)
    buf[288..320].copy_from_slice(&params.paymaster_and_data_hash);

    let inner = keccak256(&buf);

    // userOpHash = keccak256(abi.encode(inner, entryPoint, chainId))
    let mut outer = [0u8; 96];
    outer[0..32].copy_from_slice(&inner);
    outer[32 + 12..32 + 32].copy_from_slice(&params.entry_point);
    // chainId, left-padded
    outer[64 + 24..64 + 32].copy_from_slice(&params.chain_id.to_be_bytes());

    let mut h = Keccak256::new();
    h.update(&outer);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

#[derive(Debug, PartialEq, Eq)]
pub enum WireParseError {
    Truncated,
}

/// Parse the fixed AA header out of the on-wire `cmd_sign_userop`
/// payload (everything before `tx_len`).
///
/// Mirrors the layout documented in
/// [`sphincs_tz_shared::CMD_SIGN_USEROP`].
pub fn parse_header(buf: &[u8]) -> Result<AaUserOpParams, WireParseError> {
    if buf.len() < sphincs_tz_shared::USEROP_HEADER_LEN {
        return Err(WireParseError::Truncated);
    }
    // Skip the leading `has_bundle` u8 — that's owned by the caller.
    let mut p = 1usize;

    let mut sender = [0u8; 20];
    sender.copy_from_slice(&buf[p..p + 20]);
    p += 20;

    let mut entry_point = [0u8; 20];
    entry_point.copy_from_slice(&buf[p..p + 20]);
    p += 20;

    let mut chain_be = [0u8; 8];
    chain_be.copy_from_slice(&buf[p..p + 8]);
    p += 8;
    let chain_id = u64::from_be_bytes(chain_be);

    let nonce = read_u256(&buf, &mut p);
    let call_gas_limit = read_u256(&buf, &mut p);
    let verification_gas_limit = read_u256(&buf, &mut p);
    let pre_verification_gas = read_u256(&buf, &mut p);
    let max_fee_per_gas = read_u256(&buf, &mut p);
    let max_priority_fee_per_gas = read_u256(&buf, &mut p);

    let mut init_code_hash = [0u8; 32];
    init_code_hash.copy_from_slice(&buf[p..p + 32]);
    p += 32;

    let mut paymaster_and_data_hash = [0u8; 32];
    paymaster_and_data_hash.copy_from_slice(&buf[p..p + 32]);
    p += 32;

    debug_assert_eq!(p, sphincs_tz_shared::USEROP_HEADER_LEN);

    Ok(AaUserOpParams {
        sender,
        entry_point,
        chain_id,
        nonce,
        call_gas_limit,
        verification_gas_limit,
        pre_verification_gas,
        max_fee_per_gas,
        max_priority_fee_per_gas,
        init_code_hash,
        paymaster_and_data_hash,
    })
}

#[inline]
fn read_u256(buf: &[u8], p: &mut usize) -> U256 {
    let mut v = [0u8; 32];
    v.copy_from_slice(&buf[*p..*p + 32]);
    *p += 32;
    U256(v)
}
