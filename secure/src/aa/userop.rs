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
#[cfg_attr(test, derive(Debug))]
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
#[cfg_attr(test, derive(PartialEq))]
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

// ---------------------------------------------------------------------------
// Unit tests — run on the host with `cargo test -p sphincs-tz-secure`
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::eip1559::{Eip1559Tx, U256};

    // -- helpers ----------------------------------------------------------

    /// Deterministic AA params matching the e2e test fixtures.
    fn test_params() -> AaUserOpParams {
        AaUserOpParams {
            sender: [0x42; 20],
            entry_point: [
                0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3,
                0x0c, 0x7c, 0xf5, 0x7e, 0x57, 0x8a, 0x02, 0x6d, 0x27, 0x89,
            ],
            chain_id: 1,
            nonce: u256_from_u64(1),
            call_gas_limit: u256_from_u64(100_000),
            verification_gas_limit: u256_from_u64(200_000),
            pre_verification_gas: u256_from_u64(21_000),
            max_fee_per_gas: u256_from_u64(50_000_000_000),
            max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
            init_code_hash: KECCAK_EMPTY,
            paymaster_and_data_hash: KECCAK_EMPTY,
        }
    }

    /// Simple value-transfer tx: 1 ETH to 0xabcdef...1234, empty data.
    fn test_value_transfer_tx() -> Eip1559Tx {
        let mut value = [0u8; 32];
        // 10^18 = 0x0de0b6b3a7640000
        value[24] = 0x0d;
        value[25] = 0xe0;
        value[26] = 0xb6;
        value[27] = 0xb3;
        value[28] = 0xa7;
        value[29] = 0x64;
        value[30] = 0x00;
        value[31] = 0x00;

        Eip1559Tx {
            chain_id: 1,
            nonce: 0,
            max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
            max_fee_per_gas: u256_from_u64(50_000_000_000),
            gas_limit: 21_000,
            to: Some([
                0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd,
                0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12,
            ]),
            value: U256(value),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
        }
    }

    fn u256_from_u64(v: u64) -> U256 {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&v.to_be_bytes());
        U256(buf)
    }

    /// keccak256("") — used for empty initCode and paymasterAndData.
    const KECCAK_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e,
        0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53,
        0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    /// Encode an AaUserOpParams into the on-wire header format, suitable
    /// for `parse_header()` roundtrip tests.
    fn encode_header(p: &AaUserOpParams) -> Vec<u8> {
        let mut buf = vec![0u8; sphincs_tz_shared::USEROP_HEADER_LEN];
        // [0] has_bundle — 0 for these tests
        buf[0] = 0;
        let mut off = 1;
        buf[off..off + 20].copy_from_slice(&p.sender);
        off += 20;
        buf[off..off + 20].copy_from_slice(&p.entry_point);
        off += 20;
        buf[off..off + 8].copy_from_slice(&p.chain_id.to_be_bytes());
        off += 8;
        for field in &[
            &p.nonce,
            &p.call_gas_limit,
            &p.verification_gas_limit,
            &p.pre_verification_gas,
            &p.max_fee_per_gas,
            &p.max_priority_fee_per_gas,
        ] {
            buf[off..off + 32].copy_from_slice(&field.0);
            off += 32;
        }
        buf[off..off + 32].copy_from_slice(&p.init_code_hash);
        off += 32;
        buf[off..off + 32].copy_from_slice(&p.paymaster_and_data_hash);
        off += 32;
        assert_eq!(off, sphincs_tz_shared::USEROP_HEADER_LEN);
        buf
    }

    // -- reconstruct_execute_calldata tests -------------------------------

    #[test]
    fn test_reconstruct_empty_data() {
        let tx = test_value_transfer_tx();
        let result = reconstruct_execute_calldata(&tx, &[]).unwrap();
        let out = result.as_slice();
        // Total: selector(4) + target(32) + value(32) + offset(32) + len(32) = 132
        assert_eq!(out.len(), 132);
        // Selector
        assert_eq!(&out[0..4], &EXECUTE_SELECTOR);
        // Target left-padded
        assert_eq!(&out[4..16], &[0u8; 12]);
        assert_eq!(&out[16..36], &tx.to.unwrap());
        // Value
        assert_eq!(&out[36..68], &tx.value.0);
        // Offset = 0x60
        assert_eq!(out[99], 0x60);
        // Length = 0
        assert!(out[100..132].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reconstruct_with_data() {
        // 68-byte ERC20 transfer(address, uint256) calldata
        let data = hex::decode(
            "a9059cbb\
             000000000000000000000000742d35cc6634c0532925a3b844bc454e4438f44e\
             000000000000000000000000000000000000000000000000000000003b9aca00"
        ).unwrap();
        assert_eq!(data.len(), 68);

        let mut tx = test_value_transfer_tx();
        tx.to = Some([
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1,
            0x9d, 0x4a, 0x2e, 0x9e, 0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]);
        tx.value = U256::zero();
        tx.data_len = 68;

        let result = reconstruct_execute_calldata(&tx, &data).unwrap();
        let out = result.as_slice();
        // 68 bytes padded to 96 → total = 4 + 32 + 32 + 32 + 32 + 96 = 228
        assert_eq!(out.len(), 228);
        // Data appears at offset 132
        assert_eq!(&out[132..132 + 68], &data);
        // Remaining padding bytes are zero
        assert!(out[132 + 68..228].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reconstruct_32byte_boundary() {
        let tx = test_value_transfer_tx();
        let data = [0xAA; 32];
        let result = reconstruct_execute_calldata(&tx, &data).unwrap();
        // 32 bytes is already on a 32-byte boundary → total = 4 + 4*32 + 32 = 164
        assert_eq!(result.len, 164);
    }

    #[test]
    fn test_reconstruct_33bytes() {
        let tx = test_value_transfer_tx();
        let data = [0xBB; 33];
        let result = reconstruct_execute_calldata(&tx, &data).unwrap();
        // 33 bytes padded to 64 → total = 4 + 4*32 + 64 = 196
        assert_eq!(result.len, 196);
        // Padding bytes after 33 are zero
        assert!(result.buf[132 + 33..132 + 64].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reconstruct_contract_creation() {
        let mut tx = test_value_transfer_tx();
        tx.to = None;
        assert_eq!(
            reconstruct_execute_calldata(&tx, &[]).unwrap_err(),
            AaError::ContractCreation
        );
    }

    #[test]
    fn test_reconstruct_too_long() {
        let tx = test_value_transfer_tx();
        let big = [0u8; MAX_EXECUTE_CALLDATA_LEN];
        assert_eq!(
            reconstruct_execute_calldata(&tx, &big).unwrap_err(),
            AaError::CallDataTooLong
        );
    }

    /// Cross-validate against `cast abi-encode "execute(address,uint256,bytes)"`.
    /// The expected bytes were generated with Foundry's `cast`.
    #[test]
    fn test_reconstruct_cross_validate() {
        let tx = test_value_transfer_tx();
        let result = reconstruct_execute_calldata(&tx, &[]).unwrap();
        let out = result.as_slice();

        // Expected from: cast abi-encode "execute(address,uint256,bytes)" \
        //   0xabcdef1234567890abcdef1234567890abcdef12 1000000000000000000 0x
        // with selector b61d27f6 prepended
        let expected = hex::decode(
            "b61d27f6\
             000000000000000000000000abcdef1234567890abcdef1234567890abcdef12\
             0000000000000000000000000000000000000000000000000de0b6b3a7640000\
             0000000000000000000000000000000000000000000000000000000000000060\
             0000000000000000000000000000000000000000000000000000000000000000"
        ).unwrap();
        assert_eq!(out, expected.as_slice());
    }

    // -- compute_user_op_hash tests ---------------------------------------

    /// Cross-validate against the EntryPoint v0.6 hash computed by
    /// `cast keccak` + `cast abi-encode`. See tools/ for regeneration.
    #[test]
    fn test_hash_known_vector() {
        let params = test_params();
        let call_data_hash = hex::decode(
            "da854735bd0e0dc5ee6409e7d6e496a35a2988be7199131994e06ff812d91c9c"
        ).unwrap();
        let mut cdh = [0u8; 32];
        cdh.copy_from_slice(&call_data_hash);

        let hash = compute_user_op_hash(&params, &cdh);

        let expected = hex::decode(
            "b0ac4b1db1042ca2bd8c1609a6da834b0c0d9d904815cdad2e544ac881ff7579"
        ).unwrap();
        assert_eq!(hash.as_slice(), expected.as_slice());
    }

    #[test]
    fn test_hash_empty_fields() {
        let params = AaUserOpParams {
            sender: [0u8; 20],
            entry_point: [0u8; 20],
            chain_id: 0,
            nonce: U256::zero(),
            call_gas_limit: U256::zero(),
            verification_gas_limit: U256::zero(),
            pre_verification_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            max_priority_fee_per_gas: U256::zero(),
            init_code_hash: KECCAK_EMPTY,
            paymaster_and_data_hash: KECCAK_EMPTY,
        };
        let cdh = [0u8; 32];
        let hash = compute_user_op_hash(&params, &cdh);
        // Must be deterministic and non-zero
        assert_ne!(hash, [0u8; 32]);
        let hash2 = compute_user_op_hash(&params, &cdh);
        assert_eq!(hash, hash2);
    }

    #[test]
    fn test_hash_different_chain_id() {
        let params1 = test_params();
        let mut params5 = test_params();
        params5.chain_id = 5;
        let cdh = [0xAA; 32];
        let h1 = compute_user_op_hash(&params1, &cdh);
        let h5 = compute_user_op_hash(&params5, &cdh);
        assert_ne!(h1, h5);
    }

    #[test]
    fn test_hash_different_sender() {
        let params_a = test_params();
        let mut params_b = test_params();
        params_b.sender = [0x11; 20];
        let cdh = [0xBB; 32];
        let ha = compute_user_op_hash(&params_a, &cdh);
        let hb = compute_user_op_hash(&params_b, &cdh);
        assert_ne!(ha, hb);
    }

    // -- parse_header tests -----------------------------------------------

    #[test]
    fn test_parse_roundtrip() {
        let original = test_params();
        let wire = encode_header(&original);
        let parsed = parse_header(&wire).unwrap();

        assert_eq!(parsed.sender, original.sender);
        assert_eq!(parsed.entry_point, original.entry_point);
        assert_eq!(parsed.chain_id, original.chain_id);
        assert_eq!(parsed.nonce.0, original.nonce.0);
        assert_eq!(parsed.call_gas_limit.0, original.call_gas_limit.0);
        assert_eq!(parsed.verification_gas_limit.0, original.verification_gas_limit.0);
        assert_eq!(parsed.pre_verification_gas.0, original.pre_verification_gas.0);
        assert_eq!(parsed.max_fee_per_gas.0, original.max_fee_per_gas.0);
        assert_eq!(parsed.max_priority_fee_per_gas.0, original.max_priority_fee_per_gas.0);
        assert_eq!(parsed.init_code_hash, original.init_code_hash);
        assert_eq!(parsed.paymaster_and_data_hash, original.paymaster_and_data_hash);
    }

    #[test]
    fn test_parse_truncated() {
        let wire = vec![0u8; sphincs_tz_shared::USEROP_HEADER_LEN - 1];
        assert_eq!(parse_header(&wire), Err(WireParseError::Truncated));
    }

    #[test]
    fn test_parse_exact_length() {
        let wire = encode_header(&test_params());
        assert_eq!(wire.len(), sphincs_tz_shared::USEROP_HEADER_LEN);
        assert!(parse_header(&wire).is_ok());
    }

    #[test]
    fn test_parse_longer_buffer() {
        let mut wire = encode_header(&test_params());
        wire.extend_from_slice(&[0xFF; 64]); // extra garbage
        let parsed = parse_header(&wire).unwrap();
        assert_eq!(parsed.sender, [0x42; 20]);
    }

    #[test]
    fn test_parse_chain_id_endian() {
        let mut params = test_params();
        params.chain_id = 0x0100_0000_0000_0001; // non-trivial BE
        let wire = encode_header(&params);
        let parsed = parse_header(&wire).unwrap();
        assert_eq!(parsed.chain_id, 0x0100_0000_0000_0001);
    }
}
