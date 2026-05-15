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
//! the secure crate's `nsc::cmd_sign_userop`.

use pqsigner_tx_core::eip1559::{Eip1559Tx, U256};
use pqsigner_tx_core::hash::keccak256;

use sha2::{Digest as Sha256Digest, Sha256};
use sha3::Keccak256;

/// SHA-256("") — the empty-bytes hash used for empty `initCode` and
/// `paymasterAndData` inside the SHA-256 sphincs digest.
pub const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
    0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
    0xb8, 0x55,
];

pub use pqsigner_proto::EXECUTE_BATCH_SELECTOR;
pub use pqsigner_proto::EXECUTE_SELECTOR;
pub use pqsigner_proto::MAX_EXECUTE_BATCH_CALLDATA_LEN;
pub use pqsigner_proto::MAX_EXECUTE_CALLDATA_LEN;

/// Solidity ABI word size (one static slot).
const WORD: usize = 32;
/// Function-selector size in bytes (Solidity `bytes4`).
const SELECTOR_LEN: usize = 4;

/// Write `v` into the low 8 bytes of a 32-byte word slot, big-endian,
/// leaving the top 24 bytes untouched (caller must have zeroed them, or
/// must not care). Convenience for the ABI pattern where a `uint`
/// smaller than 256 bits is right-aligned in a word.
#[inline]
fn write_u64_in_word_be(word: &mut [u8], v: u64) {
    debug_assert_eq!(word.len(), WORD);
    word[WORD - 8..WORD].copy_from_slice(&v.to_be_bytes());
}

/// Encode `v` as a 32-byte big-endian uint256 (top 24 bytes zero).
#[inline]
fn u64_to_word_be(v: u64) -> [u8; WORD] {
    let mut buf = [0u8; WORD];
    buf[WORD - 8..].copy_from_slice(&v.to_be_bytes());
    buf
}

/// Read a fixed-size byte array out of `buf` starting at `*p`, advancing
/// `p` past it. Panics on out-of-bounds — callers must have verified the
/// length up front.
#[inline]
fn read_array<const N: usize>(buf: &[u8], p: &mut usize) -> [u8; N] {
    let mut out = [0u8; N];
    out.copy_from_slice(&buf[*p..*p + N]);
    *p += N;
    out
}

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
    #[must_use]
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
/// `executeWithOffchainCount(uint256 ownerIndex, uint256 newOffchainCount,
/// address target, uint256 value, bytes data)` calldata for the parsed
/// inner EIP-1559 envelope plus the firmware-tracked off-chain count.
///
/// The returned bytes match what
/// `abi.encodeCall(executeWithOffchainCount, (ownerIndex, newOffchainCount,
/// target, value, data))` produces in Solidity, byte-for-byte:
///
/// ```text
///   [  0..  4) selector ("14443c57")
///   [  4.. 36) ownerIndex          (uint256, BE)
///   [ 36.. 68) newOffchainCount    (uint256, BE)
///   [ 68..100) target address, left-padded to 32 bytes
///   [100..132) value               (uint256, BE)
///   [132..164) head offset of `bytes data`, always 0xa0
///   [164..196) length of `data` as uint256
///   [196..   ) data, padded with zero bytes to a 32-byte boundary
/// ```
pub fn reconstruct_execute_calldata(
    owner_index: u64,
    new_offchain_count: u64,
    tx: &Eip1559Tx,
    data: &[u8],
) -> Result<ExecuteCallData, AaError> {
    let target = tx.to.ok_or(AaError::ContractCreation)?;

    let padded_data_len = data.len().checked_add(31).ok_or(AaError::CallDataTooLong)? & !31usize;
    // 4 head selector + 5 head words + len word + tail.
    let total = SELECTOR_LEN + 6 * WORD + padded_data_len;
    if total > MAX_EXECUTE_CALLDATA_LEN {
        return Err(AaError::CallDataTooLong);
    }

    let mut out = ExecuteCallData {
        buf: [0u8; MAX_EXECUTE_CALLDATA_LEN],
        len: total,
    };

    // Selector + 5 head words then `bytes` length + data (tail).
    let mut p = 0;
    out.buf[p..p + SELECTOR_LEN].copy_from_slice(&EXECUTE_SELECTOR);
    p += SELECTOR_LEN;
    // ownerIndex (uint256, BE)
    write_u64_in_word_be(&mut out.buf[p..p + WORD], owner_index);
    p += WORD;
    // newOffchainCount (uint256, BE)
    write_u64_in_word_be(&mut out.buf[p..p + WORD], new_offchain_count);
    p += WORD;
    // target (address, left-padded into a 32-byte slot)
    out.buf[p + (WORD - 20)..p + WORD].copy_from_slice(&target);
    p += WORD;
    // value (uint256)
    out.buf[p..p + WORD].copy_from_slice(&tx.value.0);
    p += WORD;
    // Head offset to the `bytes` tail = 5 * 32 = 0xa0.
    out.buf[p + WORD - 1] = 0xa0;
    p += WORD;
    // Tail — bytes length word, then the data padded with zeros (the
    // buffer is already zero-initialised, so no explicit pad write).
    write_u64_in_word_be(&mut out.buf[p..p + WORD], data.len() as u64);
    p += WORD;
    out.buf[p..p + data.len()].copy_from_slice(data);

    Ok(out)
}

// ---------------------------------------------------------------------------
// Batch executeBatchWithOffchainCount calldata reconstruction
// ---------------------------------------------------------------------------

/// One inner transaction in a `executeBatchWithOffchainCount(...)` call.
/// Borrowed view — the firmware never copies the bytes; the caller
/// holds them in the TOCTOU snapshot for the lifetime of this struct.
#[derive(Debug, Clone, Copy)]
pub struct BatchInnerTx<'a> {
    pub to: [u8; 20],
    pub value: [u8; 32], // u256 BE
    pub data: &'a [u8],
}

/// Stack-friendly buffer for a reconstructed
/// `executeBatchWithOffchainCount(...)` calldata.
#[cfg_attr(test, derive(Debug))]
pub struct ExecuteBatchCallData {
    pub buf: [u8; MAX_EXECUTE_BATCH_CALLDATA_LEN],
    pub len: usize,
}

impl ExecuteBatchCallData {
    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

#[derive(Debug, PartialEq, Eq)]
pub enum BatchAaError {
    /// Caller passed an empty inner-tx slice. The on-chain
    /// `executeBatchWithOffchainCount` accepts N == 0 (and runs the
    /// monotonic counter update with no inner calls), but wallet UX
    /// requires every batch to do *something*; refuse here so a hostile
    /// NS cannot trick the user into authorising a zero-tx update via
    /// the batch path.
    EmptyBatch,
    /// Per-tx data field exceeded `MAX_TX_LEN`, or the resulting
    /// reconstructed calldata wouldn't fit in the
    /// `MAX_EXECUTE_BATCH_CALLDATA_LEN` buffer.
    CallDataTooLong,
}

/// Build the canonical
/// `executeBatchWithOffchainCount(uint256 ownerIndex, uint256 newOffchainCount,
/// address[] targets, uint256[] values, bytes[] datas)` calldata from
/// the supplied per-tx slice. Output matches `abi.encodeCall(
/// executeBatchWithOffchainCount, (ownerIndex, newOffchainCount,
/// targets, values, datas))` byte-for-byte.
///
/// ABI layout (after the 4-byte selector):
///
/// ```text
///   head (5 × 32):
///     [  4..  36)  ownerIndex                  uint256
///     [ 36..  68)  newOffchainCount            uint256
///     [ 68..100)   offset_targets              = 0xa0
///     [100..132)   offset_values               = 0xa0 + (32 + N*32)
///     [132..164)   offset_datas                = offset_values + (32 + N*32)
///   targets tail at offset_targets:
///     [+0..+32)         length = N
///     [+32..+32+N*32)   addresses (left-padded to 32 each)
///   values tail at offset_values:
///     [+0..+32)         length = N
///     [+32..+32+N*32)   uint256 values
///   datas tail at offset_datas:
///     [+0..+32)         length = N
///     [+32..+32+N*32)   per-element offsets relative to start of
///                       datas heads (i.e. relative to position 32
///                       within the datas tail, which is the start of
///                       the element-pointer block)
///     For each i:
///       data_i_len           uint256 (32 BE)
///       data_i bytes         padded with zeros to a 32-byte boundary
/// ```
pub fn reconstruct_execute_batch_calldata(
    owner_index: u64,
    new_offchain_count: u64,
    txs: &[BatchInnerTx<'_>],
) -> Result<ExecuteBatchCallData, BatchAaError> {
    if txs.is_empty() {
        return Err(BatchAaError::EmptyBatch);
    }
    let n = txs.len();
    if n > pqsigner_proto::MAX_BATCH_TXS {
        return Err(BatchAaError::CallDataTooLong);
    }

    // Per-tx padded data length and running tail size for `bytes[]`.
    let mut padded_each: [usize; pqsigner_proto::MAX_BATCH_TXS] =
        [0; pqsigner_proto::MAX_BATCH_TXS];
    let mut datas_tail_size: usize = WORD + n * WORD; // length + N inner offsets
    for (i, tx) in txs.iter().enumerate() {
        if tx.data.len() > pqsigner_proto::MAX_TX_LEN {
            return Err(BatchAaError::CallDataTooLong);
        }
        let padded = tx.data.len().checked_add(31).ok_or(BatchAaError::CallDataTooLong)? & !31usize;
        padded_each[i] = padded;
        // Each per-element block: 32 (length) + padded data bytes.
        datas_tail_size = datas_tail_size
            .checked_add(WORD + padded)
            .ok_or(BatchAaError::CallDataTooLong)?;
    }

    // Section sizes within args (after selector).
    let head_len = 5 * WORD; // 160
    let targets_size = WORD + n * WORD;
    let values_size = WORD + n * WORD;
    let total_args = head_len + targets_size + values_size + datas_tail_size;
    let total = SELECTOR_LEN
        .checked_add(total_args)
        .ok_or(BatchAaError::CallDataTooLong)?;
    if total > MAX_EXECUTE_BATCH_CALLDATA_LEN {
        return Err(BatchAaError::CallDataTooLong);
    }

    let mut out = ExecuteBatchCallData {
        buf: [0u8; MAX_EXECUTE_BATCH_CALLDATA_LEN],
        len: total,
    };

    // ── Selector ───────────────────────────────────────────────────
    out.buf[0..SELECTOR_LEN].copy_from_slice(&EXECUTE_BATCH_SELECTOR);

    // ── Head: 5 × 32-byte words ────────────────────────────────────
    //
    //   [0] ownerIndex
    //   [1] newOffchainCount
    //   [2] offset of targets[] tail = head_len
    //   [3] offset of values[]  tail = [2] + targets_size
    //   [4] offset of datas[]   tail = [3] + values_size
    let offset_targets: u64 = head_len as u64;
    let offset_values: u64 = offset_targets + targets_size as u64;
    let offset_datas: u64 = offset_values + values_size as u64;
    let head_words: [u64; 5] = [
        owner_index,
        new_offchain_count,
        offset_targets,
        offset_values,
        offset_datas,
    ];
    for (i, w) in head_words.iter().enumerate() {
        let slot = SELECTOR_LEN + i * WORD;
        write_u64_in_word_be(&mut out.buf[slot..slot + WORD], *w);
    }

    // ── targets[] tail ─────────────────────────────────────────────
    let targets_start = SELECTOR_LEN + head_len;
    write_u64_in_word_be(&mut out.buf[targets_start..targets_start + WORD], n as u64);
    let targets_data = targets_start + WORD;
    for (i, tx) in txs.iter().enumerate() {
        let off = targets_data + i * WORD;
        // Address left-padded into a 32-byte slot.
        out.buf[off + (WORD - 20)..off + WORD].copy_from_slice(&tx.to);
    }

    // ── values[] tail ──────────────────────────────────────────────
    let values_start = targets_start + targets_size;
    write_u64_in_word_be(&mut out.buf[values_start..values_start + WORD], n as u64);
    let values_data = values_start + WORD;
    for (i, tx) in txs.iter().enumerate() {
        let off = values_data + i * WORD;
        out.buf[off..off + WORD].copy_from_slice(&tx.value);
    }

    // ── datas[] tail ───────────────────────────────────────────────
    let datas_start = values_start + values_size;
    write_u64_in_word_be(&mut out.buf[datas_start..datas_start + WORD], n as u64);
    let datas_offsets = datas_start + WORD; // start of N pointers (== "heads" section)
    let datas_payload_base = datas_offsets + n * WORD;
    // Per-element offsets are measured from the start of the heads
    // section (`datas_offsets`), so the first element points just past
    // the N pointer words themselves.
    let mut cursor_within_datas_heads: u64 = (n as u64) * WORD as u64;
    let mut payload_pos = datas_payload_base;
    for (i, tx) in txs.iter().enumerate() {
        let off_slot = datas_offsets + i * WORD;
        write_u64_in_word_be(
            &mut out.buf[off_slot..off_slot + WORD],
            cursor_within_datas_heads,
        );

        // length word + payload bytes (padding stays zero from init).
        write_u64_in_word_be(
            &mut out.buf[payload_pos..payload_pos + WORD],
            tx.data.len() as u64,
        );
        payload_pos += WORD;
        out.buf[payload_pos..payload_pos + tx.data.len()].copy_from_slice(tx.data);
        payload_pos += padded_each[i];

        cursor_within_datas_heads = cursor_within_datas_heads
            .checked_add(WORD as u64 + padded_each[i] as u64)
            .ok_or(BatchAaError::CallDataTooLong)?;
    }
    debug_assert_eq!(payload_pos, total);

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
///
/// This is the hash the EntryPoint itself computes in its
/// `getUserOpHash` view. The on-chain `validateUserOp` path still
/// ignores this value (we sign a SHA-256 sphincs digest instead, for
/// hardware speed), but it is kept here for tooling/tests that need
/// to reproduce what a v0.6 bundler will see on the wire.
#[must_use]
pub fn compute_user_op_hash(params: &AaUserOpParams, call_data_hash: &[u8; 32]) -> [u8; 32] {
    // hashStruct(userOp) — 10 × 32 = 320 bytes total. Each row is one
    // right-aligned ABI word; field order matches `UserOp.hash()` in
    // EntryPoint v0.6.
    let mut buf = [0u8; 10 * WORD];
    let rows: [&[u8]; 10] = [
        &params.sender,
        &params.nonce.0,
        &params.init_code_hash,
        call_data_hash,
        &params.call_gas_limit.0,
        &params.verification_gas_limit.0,
        &params.pre_verification_gas.0,
        &params.max_fee_per_gas.0,
        &params.max_priority_fee_per_gas.0,
        &params.paymaster_and_data_hash,
    ];
    for (i, row) in rows.iter().enumerate() {
        debug_assert!(row.len() <= WORD);
        let slot_end = (i + 1) * WORD;
        buf[slot_end - row.len()..slot_end].copy_from_slice(row);
    }

    let inner = keccak256(&buf);

    // userOpHash = keccak256(abi.encode(inner, entryPoint, chainId))
    //   3 × 32-byte words.
    let mut outer = [0u8; 3 * WORD];
    outer[0..WORD].copy_from_slice(&inner);
    outer[WORD + (WORD - 20)..2 * WORD].copy_from_slice(&params.entry_point);
    write_u64_in_word_be(&mut outer[2 * WORD..3 * WORD], params.chain_id);

    Keccak256::digest(outer).into()
}

#[derive(Debug, PartialEq, Eq)]
pub enum WireParseError {
    Truncated,
}

/// Parse the fixed AA header out of the on-wire `cmd_sign_userop`
/// payload (everything before `tx_len`).
///
/// Mirrors the layout documented on `pqsigner_proto::CMD_SIGN_USEROP`.
pub fn parse_header(buf: &[u8]) -> Result<AaUserOpParams, WireParseError> {
    if buf.len() < pqsigner_proto::USEROP_HEADER_LEN {
        return Err(WireParseError::Truncated);
    }
    // Skip the leading `has_bundle` u8 — that's owned by the caller.
    let mut p = 1usize;

    let sender: [u8; 20] = read_array(buf, &mut p);
    let entry_point: [u8; 20] = read_array(buf, &mut p);
    let chain_id = u64::from_be_bytes(read_array::<8>(buf, &mut p));

    let nonce = U256(read_array(buf, &mut p));
    let call_gas_limit = U256(read_array(buf, &mut p));
    let verification_gas_limit = U256(read_array(buf, &mut p));
    let pre_verification_gas = U256(read_array(buf, &mut p));
    let max_fee_per_gas = U256(read_array(buf, &mut p));
    let max_priority_fee_per_gas = U256(read_array(buf, &mut p));

    let init_code_hash: [u8; 32] = read_array(buf, &mut p);
    let paymaster_and_data_hash: [u8; 32] = read_array(buf, &mut p);

    debug_assert_eq!(p, pqsigner_proto::USEROP_HEADER_LEN);

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

// ---------------------------------------------------------------------------
// EntryPoint v0.6 domain constants
// ---------------------------------------------------------------------------

/// `keccak256("")` — the empty-bytes hash used for `initCode = "0x"` and
/// `paymasterAndData = "0x"` in the v0.6 userOpHash.
pub const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
    0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
    0xa4, 0x70,
];

/// EntryPoint v0.6 canonical singleton address
/// (`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`). Deployed via Nick's
/// method on every major EVM chain.
pub const ENTRY_POINT_V06: [u8; 20] = [
    0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57,
    0x8a, 0x02, 0x6d, 0x27, 0x89,
];

// ---------------------------------------------------------------------------
// SPHINCS+C10 signing digest (SHA-256, hardware-accelerated on STM32U585)
// ---------------------------------------------------------------------------
//
// The keccak-based userOpHash that EntryPoint v0.6 supplies to
// `validateUserOp` is fine for replay protection but expensive to
// compute on our target — STM32U585 has hardware SHA-256 (and SAES) but
// no keccak accelerator, so every keccak call falls back to a portable
// software implementation. To keep the hot path fast we sign over a
// custom SHA-256 digest. `PQSmartWallet.sphincsDigest(userOp)` computes
// the exact same digest on-chain via the SHA-256 precompile (address
// 0x02). Neither side ever calls keccak on the sign path.
//
// Layout (all SHA-256, all big-endian uints), matching the on-chain
// `sphincsDigest(UserOperation06)`:
//
//   sphincsDigest = sha256(
//         sender                          (20 bytes)
//      || nonce                           (32 bytes)
//      || sha256(initCode)                (32 bytes, SHA256_EMPTY when empty)
//      || sha256(callData)                (32 bytes, SHA256_EMPTY when empty)
//      || callGasLimit                    (32 bytes)
//      || verificationGasLimit            (32 bytes)
//      || preVerificationGas              (32 bytes)
//      || maxFeePerGas                    (32 bytes)
//      || maxPriorityFeePerGas            (32 bytes)
//      || sha256(paymasterAndData)        (32 bytes, SHA256_EMPTY when empty)
//      || entryPoint                      (20 bytes)
//      || chainId                         (32 bytes, u256 BE)
//   )
//
// The digest covers every UserOp field that affects transaction
// semantics, plus the entryPoint + chainId domain separators, so replay
// attacks across chains / wallets / UserOps remain impossible.

/// Same shape as `AaUserOpParams` but carrying SHA-256 pre-digests of
/// the variable-length fields instead of keccak ones. Kept as a
/// separate type so the keccak `userOpHash` path cannot be accidentally
/// fed SHA-256 pre-digests.
#[derive(Debug, Clone)]
pub struct AaUserOpParamsV06Sha256 {
    pub sender: [u8; 20],
    pub entry_point: [u8; 20],
    pub chain_id: u64,
    pub nonce: U256,
    pub init_code_digest: [u8; 32],
    pub call_gas_limit: U256,
    pub verification_gas_limit: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee_per_gas: U256,
    pub paymaster_and_data_digest: [u8; 32],
}

/// Compute the firmware-friendly SHA-256 sphincs digest for an
/// EntryPoint v0.6 UserOperation.
///
/// * `init_code_digest` / `paymaster_and_data_digest` are the SHA-256 of
///   the respective bytes fields — use `SHA256_EMPTY` when a field is
///   absent.
/// * `call_data_digest` is the SHA-256 of the reconstructed
///   `execute(...)` / `addOwnerBytes(...)` calldata.
#[must_use]
pub fn compute_sphincs_digest_v06(
    params: &AaUserOpParamsV06Sha256,
    call_data_digest: &[u8; 32],
) -> [u8; 32] {
    Sha256::new()
        .chain_update(params.sender)
        .chain_update(params.nonce.0)
        .chain_update(params.init_code_digest)
        .chain_update(call_data_digest)
        .chain_update(params.call_gas_limit.0)
        .chain_update(params.verification_gas_limit.0)
        .chain_update(params.pre_verification_gas.0)
        .chain_update(params.max_fee_per_gas.0)
        .chain_update(params.max_priority_fee_per_gas.0)
        .chain_update(params.paymaster_and_data_digest)
        .chain_update(params.entry_point)
        // chainId is a Solidity uint256 → 32-byte BE.
        .chain_update(u64_to_word_be(params.chain_id))
        .finalize()
        .into()
}

/// SHA-256 of a byte slice as a convenience wrapper.
#[inline]
#[must_use]
pub fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

// ---------------------------------------------------------------------------
// Unit tests — run on the host with `cargo test -p pqsigner-aa`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use std::vec;

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
            init_code_hash: TEST_KECCAK_EMPTY,
            paymaster_and_data_hash: TEST_KECCAK_EMPTY,
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
    const TEST_KECCAK_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e,
        0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53,
        0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    /// Encode an AaUserOpParams into the on-wire header format, suitable
    /// for `parse_header()` roundtrip tests.
    fn encode_header(p: &AaUserOpParams) -> Vec<u8> {
        let mut buf = vec![0u8; pqsigner_proto::USEROP_HEADER_LEN];
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
        assert_eq!(off, pqsigner_proto::USEROP_HEADER_LEN);
        buf
    }

    // -- reconstruct_execute_calldata tests -------------------------------

    #[test]
    fn test_reconstruct_empty_data() {
        let tx = test_value_transfer_tx();
        let result = reconstruct_execute_calldata(1, 7, &tx, &[]).unwrap();
        let out = result.as_slice();
        // Total: selector(4) + 5 head words(160) + len(32) = 196
        assert_eq!(out.len(), 196);
        assert_eq!(&out[0..4], &EXECUTE_SELECTOR);
        // ownerIndex == 1, BE-padded
        assert_eq!(&out[4..36], &{
            let mut b = [0u8; 32];
            b[31] = 1;
            b
        });
        // newOffchainCount == 7
        assert_eq!(&out[36..68], &{
            let mut b = [0u8; 32];
            b[31] = 7;
            b
        });
        // target left-padded
        assert_eq!(&out[68..80], &[0u8; 12]);
        assert_eq!(&out[80..100], &tx.to.unwrap());
        // value
        assert_eq!(&out[100..132], &tx.value.0);
        // offset = 0xa0 at [132..164], byte 163
        assert_eq!(out[163], 0xa0);
        assert!(out[132..163].iter().all(|&b| b == 0));
        // data length zero
        assert!(out[164..196].iter().all(|&b| b == 0));
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

        let result = reconstruct_execute_calldata(2, 0, &tx, &data).unwrap();
        let out = result.as_slice();
        // 68 bytes padded to 96 → total = 196 + 96 = 292
        assert_eq!(out.len(), 292);
        assert_eq!(&out[196..196 + 68], &data);
        assert!(out[196 + 68..292].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reconstruct_32byte_boundary() {
        let tx = test_value_transfer_tx();
        let data = [0xAA; 32];
        let result = reconstruct_execute_calldata(1, 0, &tx, &data).unwrap();
        // 32 bytes already on boundary → total = 196 + 32 = 228
        assert_eq!(result.len, 228);
    }

    #[test]
    fn test_reconstruct_33bytes() {
        let tx = test_value_transfer_tx();
        let data = [0xBB; 33];
        let result = reconstruct_execute_calldata(1, 0, &tx, &data).unwrap();
        // 33 bytes padded to 64 → total = 196 + 64 = 260
        assert_eq!(result.len, 260);
        assert!(result.buf[196 + 33..196 + 64].iter().all(|&b| b == 0));
    }

    #[test]
    fn test_reconstruct_contract_creation() {
        let mut tx = test_value_transfer_tx();
        tx.to = None;
        assert_eq!(
            reconstruct_execute_calldata(1, 0, &tx, &[]).unwrap_err(),
            AaError::ContractCreation
        );
    }

    #[test]
    fn test_reconstruct_too_long() {
        let tx = test_value_transfer_tx();
        let big = [0u8; MAX_EXECUTE_CALLDATA_LEN];
        assert_eq!(
            reconstruct_execute_calldata(1, 0, &tx, &big).unwrap_err(),
            AaError::CallDataTooLong
        );
    }

    /// Cross-validate against `cast abi-encode
    /// "executeWithOffchainCount(uint256,uint256,address,uint256,bytes)"`.
    #[test]
    fn test_reconstruct_cross_validate() {
        let tx = test_value_transfer_tx();
        let result = reconstruct_execute_calldata(1, 0, &tx, &[]).unwrap();
        let out = result.as_slice();

        // Expected: selector || ownerIndex(1) || newOffchainCount(0)
        //         || target(0xabc...) || value(1e18) || offset(0xa0) || dataLen(0)
        let expected = hex::decode(
            "14443c57\
             0000000000000000000000000000000000000000000000000000000000000001\
             0000000000000000000000000000000000000000000000000000000000000000\
             000000000000000000000000abcdef1234567890abcdef1234567890abcdef12\
             0000000000000000000000000000000000000000000000000de0b6b3a7640000\
             00000000000000000000000000000000000000000000000000000000000000a0\
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
            init_code_hash: TEST_KECCAK_EMPTY,
            paymaster_and_data_hash: TEST_KECCAK_EMPTY,
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
        let wire = vec![0u8; pqsigner_proto::USEROP_HEADER_LEN - 1];
        assert_eq!(parse_header(&wire), Err(WireParseError::Truncated));
    }

    #[test]
    fn test_parse_exact_length() {
        let wire = encode_header(&test_params());
        assert_eq!(wire.len(), pqsigner_proto::USEROP_HEADER_LEN);
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

    // -- v0.6 SHA-256 sphincs digest tests --------------------------------

    /// Parity with Solidity `PQSmartWallet.sphincsDigest(userOp)` for an
    /// all-zero userOp: 12 × 32 = 384 bytes fed to SHA-256, first with
    /// the sender, nonce, two empty-byte hashes, then five 32-byte gas
    /// fields, then the empty paymaster hash, then entryPoint+chainId.
    #[test]
    fn test_compute_sphincs_digest_v06_deterministic() {
        let params = AaUserOpParamsV06Sha256 {
            sender: [0u8; 20],
            entry_point: [0u8; 20],
            chain_id: 0,
            nonce: U256::zero(),
            init_code_digest: SHA256_EMPTY,
            call_gas_limit: U256::zero(),
            verification_gas_limit: U256::zero(),
            pre_verification_gas: U256::zero(),
            max_fee_per_gas: U256::zero(),
            max_priority_fee_per_gas: U256::zero(),
            paymaster_and_data_digest: SHA256_EMPTY,
        };
        let cd = SHA256_EMPTY;
        let h1 = compute_sphincs_digest_v06(&params, &cd);
        let h2 = compute_sphincs_digest_v06(&params, &cd);
        assert_eq!(h1, h2);
        assert_ne!(h1, [0u8; 32]);
    }

    /// Different chain_id → different digest (replay protection).
    #[test]
    fn test_compute_sphincs_digest_v06_chain_separation() {
        let make = |chain_id: u64| AaUserOpParamsV06Sha256 {
            sender: [0x42; 20],
            entry_point: ENTRY_POINT_V06,
            chain_id,
            nonce: u256_from_u64(1),
            init_code_digest: SHA256_EMPTY,
            call_gas_limit: u256_from_u64(100_000),
            verification_gas_limit: u256_from_u64(200_000),
            pre_verification_gas: u256_from_u64(21_000),
            max_fee_per_gas: u256_from_u64(50_000_000_000),
            max_priority_fee_per_gas: u256_from_u64(2_000_000_000),
            paymaster_and_data_digest: SHA256_EMPTY,
        };
        let cd = [0xAB; 32];
        let h1 = compute_sphincs_digest_v06(&make(1), &cd);
        let h8453 = compute_sphincs_digest_v06(&make(8453), &cd);
        assert_ne!(h1, h8453);
    }

    // -- batch executeBatchWithOffchainCount tests ------------------------

    fn u256_from_u128_be(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    fn batch_tx<'a>(to_byte: u8, value: u128, data: &'a [u8]) -> BatchInnerTx<'a> {
        BatchInnerTx {
            to: [to_byte; 20],
            value: u256_from_u128_be(value),
            data,
        }
    }

    /// Empty batch is refused — see `BatchAaError::EmptyBatch`.
    #[test]
    fn test_batch_empty_refused() {
        let r = reconstruct_execute_batch_calldata(1, 0, &[]);
        assert_eq!(r.unwrap_err(), BatchAaError::EmptyBatch);
    }

    /// Single-tx batch produces well-formed calldata. Compare against a
    /// hand-encoded reference: ABI of (1, 7, [0xAA*20], [0], [empty]).
    #[test]
    fn test_batch_n1_empty_data() {
        let txs = [batch_tx(0xAA, 0, &[])];
        let r = reconstruct_execute_batch_calldata(1, 7, &txs).unwrap();
        let out = r.as_slice();

        // Selector
        assert_eq!(&out[0..4], &EXECUTE_BATCH_SELECTOR);
        // ownerIndex = 1
        assert_eq!(out[4 + 31], 1);
        assert!(out[4..4 + 31].iter().all(|&b| b == 0));
        // newOffchainCount = 7
        assert_eq!(out[4 + 32 + 31], 7);
        // offset_targets = 0xa0 (= 160 = 5*32)
        assert_eq!(out[4 + 64 + 31], 0xa0);
        // offset_values = 0xa0 + (32 + 32) = 0xe0
        assert_eq!(out[4 + 96 + 31], 0xe0);
        // offset_datas  = 0xe0 + (32 + 32) = 0x120
        assert_eq!(out[4 + 128 + 30], 0x01);
        assert_eq!(out[4 + 128 + 31], 0x20);

        // targets length = 1
        let targets_off = 4 + 160;
        assert_eq!(out[targets_off + 31], 1);
        // address at targets+32, left-padded
        assert!(out[targets_off + 32..targets_off + 32 + 12].iter().all(|&b| b == 0));
        assert_eq!(&out[targets_off + 32 + 12..targets_off + 32 + 32], &[0xAA; 20]);

        // values length = 1, value = 0
        let values_off = targets_off + 64;
        assert_eq!(out[values_off + 31], 1);
        assert!(out[values_off + 32..values_off + 64].iter().all(|&b| b == 0));

        // datas length = 1, inner offset = 32 (1*32)
        let datas_off = values_off + 64;
        assert_eq!(out[datas_off + 31], 1);
        assert_eq!(out[datas_off + 32 + 31], 32);
        // length word = 0
        assert!(out[datas_off + 64..datas_off + 96].iter().all(|&b| b == 0));

        // Total length = selector + 5 head words + targets + values +
        // datas (32 length + 32 inner offset + 32 inner length + 0 padded)
        let expected = 4 + 5 * 32 + 64 + 64 + 32 + 32 + 32;
        assert_eq!(out.len(), expected);
    }

    /// 2-tx batch with a non-empty body. Verifies the inner-offset
    /// arithmetic in `bytes[]`.
    #[test]
    fn test_batch_n2_with_data() {
        let data0: [u8; 4] = [0x12, 0x34, 0x56, 0x78];
        let data1: [u8; 36] = {
            let mut d = [0u8; 36];
            d[0] = 0xa9;
            d[1] = 0x05;
            d[2] = 0x9c;
            d[3] = 0xbb;
            d[15..36].fill(0xab);
            d
        };
        let txs = [
            batch_tx(0x11, 0xdead_beef, &data0),
            batch_tx(0x22, 0, &data1),
        ];
        let r = reconstruct_execute_batch_calldata(3, 17, &txs).unwrap();
        let out = r.as_slice();
        let n = 2usize;

        // ownerIndex = 3, newOffchainCount = 17
        assert_eq!(out[4 + 31], 3);
        assert_eq!(out[4 + 32 + 31], 17);

        // offset_targets = 0xa0; offset_values = 0xa0 + 32 + N*32 = 0x100;
        // offset_datas = 0x100 + 32 + N*32 = 0x160.
        assert_eq!(out[4 + 64 + 31], 0xa0);
        assert_eq!(out[4 + 96 + 30], 0x01);
        assert_eq!(out[4 + 96 + 31], 0x00);
        assert_eq!(out[4 + 128 + 30], 0x01);
        assert_eq!(out[4 + 128 + 31], 0x60);

        // targets length = 2
        let targets_off = 4 + 160;
        assert_eq!(out[targets_off + 31], 2);
        // tx0 address (left-padded)
        assert_eq!(&out[targets_off + 32 + 12..targets_off + 64], &[0x11; 20]);
        // tx1 address
        assert_eq!(&out[targets_off + 64 + 12..targets_off + 96], &[0x22; 20]);

        // values length = 2, value0 = 0xdeadbeef
        let values_off = targets_off + 32 + n * 32;
        assert_eq!(out[values_off + 31], 2);
        let v0_lo = &out[values_off + 32 + 28..values_off + 64];
        assert_eq!(v0_lo, &[0xde, 0xad, 0xbe, 0xef]);
        // value1 = 0
        assert!(out[values_off + 64..values_off + 96].iter().all(|&b| b == 0));

        // datas length = 2
        let datas_off = values_off + 32 + n * 32;
        assert_eq!(out[datas_off + 31], 2);
        // Inner offset 0 = 64 (= N*32)
        assert_eq!(out[datas_off + 32 + 31], 64);
        // Inner offset 1 = 64 + 32 + padded(4) = 64 + 32 + 32 = 128 = 0x80
        assert_eq!(out[datas_off + 64 + 31], 0x80);

        // tx0 data: length 4 at [datas_off+96..datas_off+128); bytes
        // 0x12345678... at [datas_off+128..); padded 28 zero bytes.
        assert_eq!(out[datas_off + 96 + 31], 4);
        assert_eq!(&out[datas_off + 128..datas_off + 128 + 4], &data0);
        assert!(out[datas_off + 128 + 4..datas_off + 128 + 32]
            .iter()
            .all(|&b| b == 0));

        // tx1 data: length 36, padded to 64 bytes.
        let tx1_len_off = datas_off + 128 + 32;
        assert_eq!(out[tx1_len_off + 31], 36);
        assert_eq!(&out[tx1_len_off + 32..tx1_len_off + 32 + 36], &data1);
        // Trailing 28 padding bytes zero.
        assert!(out[tx1_len_off + 32 + 36..tx1_len_off + 32 + 64]
            .iter()
            .all(|&b| b == 0));

        // Total length sanity check.
        let expected = 4
            + 5 * 32 // head
            + 32 + n * 32 // targets
            + 32 + n * 32 // values
            + 32 + n * 32 + 32 + 32 + 32 + 64; // datas (length + 2 offsets + 2 (length + padded data))
        assert_eq!(out.len(), expected);
    }

    /// Cross-check: encoder output for a 1-tx batch with empty data
    /// matches what `cast abi-encode` produces (verified offline). The
    /// hex below is `cast calldata "executeBatchWithOffchainCount(...)"`
    /// output for ownerIndex=1, count=0, [0xAB*20], [0], [empty].
    #[test]
    fn test_batch_cross_validate_n1() {
        let txs = [batch_tx(0xAB, 0, &[])];
        let r = reconstruct_execute_batch_calldata(1, 0, &txs).unwrap();
        let out = r.as_slice();

        // Reference: built by hand following the ABI spec.
        // [0..4)            7a 38 99 33                       — selector
        // [4..36)           ownerIndex = 1
        // [36..68)          newOffchainCount = 0
        // [68..100)         offset_targets = 0xa0
        // [100..132)        offset_values  = 0xe0
        // [132..164)        offset_datas   = 0x120
        // targets:
        // [164..196)        length = 1
        // [196..228)        addr = 00..00 || 0xAB*20
        // values:
        // [228..260)        length = 1
        // [260..292)        value = 0
        // datas:
        // [292..324)        length = 1
        // [324..356)        inner offset = 0x20
        // [356..388)        data length = 0
        let mut expected = [0u8; 388];
        expected[..4].copy_from_slice(&EXECUTE_BATCH_SELECTOR);
        expected[4 + 31] = 1; // ownerIndex
        // offsets
        expected[4 + 64 + 31] = 0xa0;
        expected[4 + 96 + 31] = 0xe0;
        expected[4 + 128 + 30] = 0x01;
        expected[4 + 128 + 31] = 0x20;
        // targets
        expected[164 + 31] = 1;
        expected[196 + 12..196 + 32].copy_from_slice(&[0xAB; 20]);
        // values
        expected[228 + 31] = 1;
        // datas
        expected[292 + 31] = 1;
        expected[324 + 31] = 0x20;
        // data length already zero.

        assert_eq!(out, &expected[..]);
    }

    /// Per-tx data > MAX_TX_LEN is rejected.
    #[test]
    fn test_batch_per_tx_too_long() {
        let huge = vec![0u8; pqsigner_proto::MAX_TX_LEN + 1];
        let txs = [batch_tx(0x11, 0, &huge)];
        let r = reconstruct_execute_batch_calldata(1, 0, &txs);
        assert_eq!(r.unwrap_err(), BatchAaError::CallDataTooLong);
    }

    /// More than MAX_BATCH_TXS is rejected.
    #[test]
    fn test_batch_count_too_large() {
        // Build a slice with MAX_BATCH_TXS + 1 entries, each empty.
        let dummy: [u8; 0] = [];
        let mut v: Vec<BatchInnerTx<'_>> = Vec::new();
        for _ in 0..pqsigner_proto::MAX_BATCH_TXS + 1 {
            v.push(batch_tx(0x11, 0, &dummy));
        }
        let r = reconstruct_execute_batch_calldata(1, 0, &v);
        assert_eq!(r.unwrap_err(), BatchAaError::CallDataTooLong);
    }
}
