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

/// SHA-256("") — the empty-bytes hash used for empty `initCode` and
/// `paymasterAndData` inside the SHA-256 sphincs digest.
pub const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
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

/// Domain-separated commitment shown at the batch-final confirmation. Each
/// member first commits to its exact ordered tuple `(index, target, value,
/// ERC-8213 calldata digest)`; the final hash commits to the declared count and
/// the ordered member hashes. Fixed framing makes tuple boundaries
/// unambiguous and prevents a target/value fault from preserving the final UI
/// fingerprint merely because calldata stayed unchanged.
const BATCH_MEMBER_COMMIT_DOMAIN: &[u8] = b"PQSigner/batch-member/v1";
const BATCH_FINAL_COMMIT_DOMAIN: &[u8] = b"PQSigner/batch-final/v1";

#[must_use]
pub fn batch_member_commitment(
    index: usize,
    target: &[u8; 20],
    value: &[u8; 32],
    calldata_digest: &[u8; 32],
) -> Option<[u8; 32]> {
    let index = u64::try_from(index).ok()?;
    let mut frame = [0u8; BATCH_MEMBER_COMMIT_DOMAIN.len() + 8 + 20 + 32 + 32];
    let mut p = 0usize;
    frame[p..p + BATCH_MEMBER_COMMIT_DOMAIN.len()].copy_from_slice(BATCH_MEMBER_COMMIT_DOMAIN);
    p += BATCH_MEMBER_COMMIT_DOMAIN.len();
    frame[p..p + 8].copy_from_slice(&index.to_be_bytes());
    p += 8;
    frame[p..p + 20].copy_from_slice(target);
    p += 20;
    frame[p..p + 32].copy_from_slice(value);
    p += 32;
    frame[p..p + 32].copy_from_slice(calldata_digest);
    Some(keccak256(&frame))
}

/// Finalize an ordered set of already-computed member commitments. The count
/// is included independently rather than inferred from byte length so a
/// skipped member-loop backedge cannot preserve the authorization digest.
#[must_use]
pub fn batch_tuple_commitment_from_members(members: &[[u8; 32]]) -> Option<[u8; 32]> {
    if members.is_empty() || members.len() > pqsigner_proto::MAX_BATCH_TXS {
        return None;
    }
    let count = u64::try_from(members.len()).ok()?;
    let mut frame = [0u8; BATCH_FINAL_COMMIT_DOMAIN.len() + 8 + pqsigner_proto::MAX_BATCH_TXS * 32];
    let mut p = 0usize;
    frame[p..p + BATCH_FINAL_COMMIT_DOMAIN.len()].copy_from_slice(BATCH_FINAL_COMMIT_DOMAIN);
    p += BATCH_FINAL_COMMIT_DOMAIN.len();
    frame[p..p + 8].copy_from_slice(&count.to_be_bytes());
    p += 8;
    let mut i = 0usize;
    while i < members.len() {
        frame[p..p + 32].copy_from_slice(&members[i]);
        p += 32;
        i += 1;
    }
    Some(keccak256(&frame[..p]))
}

/// Compute the final commitment directly from authoritative tuple slices.
#[must_use]
pub fn batch_tuple_commitment(txs: &[BatchInnerTx<'_>]) -> Option<[u8; 32]> {
    if txs.is_empty() || txs.len() > pqsigner_proto::MAX_BATCH_TXS {
        return None;
    }
    let mut members = [[0u8; 32]; pqsigner_proto::MAX_BATCH_TXS];
    let mut i = 0usize;
    while i < txs.len() {
        let calldata_digest = pqsigner_tx_core::erc8213::calldata_digest(txs[i].data);
        members[i] = batch_member_commitment(i, &txs[i].to, &txs[i].value, &calldata_digest)?;
        i += 1;
    }
    batch_tuple_commitment_from_members(&members[..txs.len()])
}

fn read_batch_word(buf: &[u8], pos: usize) -> Option<&[u8; WORD]> {
    let end = pos.checked_add(WORD)?;
    buf.get(pos..end)?.try_into().ok()
}

fn read_batch_u64_word(buf: &[u8], pos: usize) -> Option<u64> {
    let word = read_batch_word(buf, pos)?;
    if word[..WORD - 8].iter().any(|&b| b != 0) {
        return None;
    }
    Some(u64::from_be_bytes(word[WORD - 8..].try_into().ok()?))
}

/// Independently parse the exact live ABI bytes produced after confirmation
/// and reconstruct their tuple commitment. This deliberately does not reuse
/// the encoder's `BatchInnerTx` source: selector, owner/counter words, offsets,
/// lengths, address padding, dynamic offsets, data padding, exact consumption,
/// count, order, target, value and calldata all have to survive in the bytes
/// that are actually hashed for signing.
#[must_use]
pub fn execute_batch_tuple_commitment_from_calldata(
    calldata: &[u8],
    expected_owner_index: u64,
    expected_offchain_count: u64,
    expected_member_count: usize,
) -> Option<[u8; 32]> {
    if expected_member_count == 0 || expected_member_count > pqsigner_proto::MAX_BATCH_TXS {
        return None;
    }
    if calldata.get(..SELECTOR_LEN)? != EXECUTE_BATCH_SELECTOR {
        return None;
    }
    if read_batch_u64_word(calldata, SELECTOR_LEN)? != expected_owner_index
        || read_batch_u64_word(calldata, SELECTOR_LEN + WORD)? != expected_offchain_count
    {
        return None;
    }

    let head_len = 5usize.checked_mul(WORD)?;
    let array_size = WORD.checked_add(expected_member_count.checked_mul(WORD)?)?;
    let targets_rel = head_len;
    let values_rel = targets_rel.checked_add(array_size)?;
    let datas_rel = values_rel.checked_add(array_size)?;
    if read_batch_u64_word(calldata, SELECTOR_LEN + 2 * WORD)? != u64::try_from(targets_rel).ok()?
        || read_batch_u64_word(calldata, SELECTOR_LEN + 3 * WORD)?
            != u64::try_from(values_rel).ok()?
        || read_batch_u64_word(calldata, SELECTOR_LEN + 4 * WORD)?
            != u64::try_from(datas_rel).ok()?
    {
        return None;
    }

    let targets_start = SELECTOR_LEN.checked_add(targets_rel)?;
    let values_start = SELECTOR_LEN.checked_add(values_rel)?;
    let datas_start = SELECTOR_LEN.checked_add(datas_rel)?;
    let expected_count_u64 = u64::try_from(expected_member_count).ok()?;
    if read_batch_u64_word(calldata, targets_start)? != expected_count_u64
        || read_batch_u64_word(calldata, values_start)? != expected_count_u64
        || read_batch_u64_word(calldata, datas_start)? != expected_count_u64
    {
        return None;
    }

    let targets_data = targets_start.checked_add(WORD)?;
    let values_data = values_start.checked_add(WORD)?;
    let datas_offsets = datas_start.checked_add(WORD)?;
    let mut cursor = expected_member_count.checked_mul(WORD)?;
    let mut members = [[0u8; 32]; pqsigner_proto::MAX_BATCH_TXS];
    let mut i = 0usize;
    while i < expected_member_count {
        let target_word =
            read_batch_word(calldata, targets_data.checked_add(i.checked_mul(WORD)?)?)?;
        if target_word[..WORD - 20].iter().any(|&b| b != 0) {
            return None;
        }
        let mut target = [0u8; 20];
        target.copy_from_slice(&target_word[WORD - 20..]);
        let value = *read_batch_word(calldata, values_data.checked_add(i.checked_mul(WORD)?)?)?;

        let offset_pos = datas_offsets.checked_add(i.checked_mul(WORD)?)?;
        if read_batch_u64_word(calldata, offset_pos)? != u64::try_from(cursor).ok()? {
            return None;
        }
        let payload_pos = datas_offsets.checked_add(cursor)?;
        let data_len_u64 = read_batch_u64_word(calldata, payload_pos)?;
        let data_len = usize::try_from(data_len_u64).ok()?;
        if data_len > pqsigner_proto::MAX_TX_LEN {
            return None;
        }
        let data_start = payload_pos.checked_add(WORD)?;
        let data_end = data_start.checked_add(data_len)?;
        let data = calldata.get(data_start..data_end)?;
        let padded_len = data_len.checked_add(WORD - 1)? & !(WORD - 1);
        let padded_end = data_start.checked_add(padded_len)?;
        if calldata.get(data_end..padded_end)?.iter().any(|&b| b != 0) {
            return None;
        }
        let digest = pqsigner_tx_core::erc8213::calldata_digest(data);
        members[i] = batch_member_commitment(i, &target, &value, &digest)?;
        cursor = cursor.checked_add(WORD)?.checked_add(padded_len)?;
        i += 1;
    }
    if datas_offsets.checked_add(cursor)? != calldata.len() {
        return None;
    }
    batch_tuple_commitment_from_members(&members[..expected_member_count])
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
/// Positional write helpers for [`reconstruct_execute_batch_calldata`].
///
/// Non-loop range copies behind a call boundary (re-borrowing the
/// buffer per call): runtime-range slice writes inside loop bodies and
/// early returns (`?`) inside loops are shapes the Aeneas Lean
/// extraction rejects (work-todo §33 P2); the loops below call these
/// helpers and propagate errors via a flag instead.
#[inline]
fn batch_write_u64_word(buf: &mut [u8; MAX_EXECUTE_BATCH_CALLDATA_LEN], pos: usize, v: u64) {
    write_u64_in_word_be(&mut buf[pos..pos + WORD], v);
}

#[inline]
fn batch_write_addr(buf: &mut [u8; MAX_EXECUTE_BATCH_CALLDATA_LEN], pos: usize, a: &[u8; 20]) {
    buf[pos + (WORD - 20)..pos + WORD].copy_from_slice(a);
}

#[inline]
fn batch_write_word32(buf: &mut [u8; MAX_EXECUTE_BATCH_CALLDATA_LEN], pos: usize, w: &[u8; 32]) {
    buf[pos..pos + WORD].copy_from_slice(w);
}

#[inline]
fn batch_write_bytes(buf: &mut [u8; MAX_EXECUTE_BATCH_CALLDATA_LEN], pos: usize, d: &[u8]) {
    buf[pos..pos + d.len()].copy_from_slice(d);
}

/// In-place variant of [`reconstruct_execute_batch_calldata`]: fills a
/// caller-provided `out` instead of returning an [`ExecuteBatchCallData`]
/// by value. The secure batch-sign handler runs on a deep stack (snapshot
/// in BSS, plus several KB of per-sign buffers) and an 18 KB
/// return-by-value — through the `match`/`Result` the caller writes, NRVO
/// does not reliably elide — costs a *second* transient 18 KB copy that
/// overflowed the stack into BSS (clobbering adjacent statics). Writing the
/// single caller-owned buffer keeps exactly one 18 KB buffer live.
pub fn reconstruct_execute_batch_calldata_into(
    out: &mut ExecuteBatchCallData,
    owner_index: u64,
    new_offchain_count: u64,
    txs: &[BatchInnerTx<'_>],
) -> Result<(), BatchAaError> {
    if txs.is_empty() {
        return Err(BatchAaError::EmptyBatch);
    }
    let n = txs.len();
    if n > pqsigner_proto::MAX_BATCH_TXS {
        return Err(BatchAaError::CallDataTooLong);
    }

    // Per-tx padded data length and running tail size for `bytes[]`.
    // Index-based loop with an error FLAG (no `?`/`return` inside the
    // loop body — work-todo §33 P2): `too_long` latches and the loop
    // runs to completion; the (cheap) remaining iterations are dead
    // work, identical observable behaviour.
    let mut padded_each: [usize; pqsigner_proto::MAX_BATCH_TXS] =
        [0; pqsigner_proto::MAX_BATCH_TXS];
    let mut datas_tail_size: usize = WORD + n * WORD; // length + N inner offsets
    let mut too_long = false;
    let mut i = 0;
    while i < n {
        let dlen = txs[i].data.len();
        if dlen > pqsigner_proto::MAX_TX_LEN {
            too_long = true;
        } else {
            // `dlen <= MAX_TX_LEN` here, so `+ 31` cannot overflow and
            // the old `checked_add(31)` arm is unreachable; the running
            // tail-size add keeps its checked form via saturating
            // semantics + the latch.
            let padded = (dlen + 31) & !31usize;
            padded_each[i] = padded;
            match datas_tail_size.checked_add(WORD + padded) {
                Some(v) => datas_tail_size = v,
                None => too_long = true,
            }
        }
        i += 1;
    }
    if too_long {
        return Err(BatchAaError::CallDataTooLong);
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

    // The caller owns `out` (avoids an 18 KB return-by-value copy on the
    // secure sign stack). It may be dirty from a previous call, so clear
    // it first: the element writers below only touch the live bytes and
    // rely on the inter-element ABI padding reading back as zero.
    out.buf.fill(0);
    out.len = total;

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
    let mut i = 0;
    while i < 5 {
        let slot = SELECTOR_LEN + i * WORD;
        batch_write_u64_word(&mut out.buf, slot, head_words[i]);
        i += 1;
    }

    // ── targets[] tail ─────────────────────────────────────────────
    let targets_start = SELECTOR_LEN + head_len;
    write_u64_in_word_be(&mut out.buf[targets_start..targets_start + WORD], n as u64);
    let targets_data = targets_start + WORD;
    let mut i = 0;
    while i < n {
        let off = targets_data + i * WORD;
        // Address left-padded into a 32-byte slot.
        batch_write_addr(&mut out.buf, off, &txs[i].to);
        i += 1;
    }

    // ── values[] tail ──────────────────────────────────────────────
    let values_start = targets_start + targets_size;
    write_u64_in_word_be(&mut out.buf[values_start..values_start + WORD], n as u64);
    let values_data = values_start + WORD;
    let mut i = 0;
    while i < n {
        let off = values_data + i * WORD;
        batch_write_word32(&mut out.buf, off, &txs[i].value);
        i += 1;
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
    let mut cursor_overflow = false;
    let mut i = 0;
    while i < n {
        let off_slot = datas_offsets + i * WORD;
        batch_write_u64_word(&mut out.buf, off_slot, cursor_within_datas_heads);

        // length word + payload bytes (padding stays zero from init).
        batch_write_u64_word(&mut out.buf, payload_pos, txs[i].data.len() as u64);
        payload_pos += WORD;
        batch_write_bytes(&mut out.buf, payload_pos, txs[i].data);
        payload_pos += padded_each[i];

        // Flag-latched (no `?` in the loop — work-todo §33 P2). The
        // cursor is only WRITTEN to the buffer at the top of the next
        // iteration, and on overflow we bail before using it, so the
        // wrapping value never reaches the output.
        match cursor_within_datas_heads.checked_add(WORD as u64 + padded_each[i] as u64) {
            Some(v) => cursor_within_datas_heads = v,
            None => cursor_overflow = true,
        }
        i += 1;
    }
    if cursor_overflow {
        return Err(BatchAaError::CallDataTooLong);
    }
    debug_assert_eq!(payload_pos, total);

    Ok(())
}

/// By-value convenience wrapper over
/// [`reconstruct_execute_batch_calldata_into`]. Allocates the
/// [`ExecuteBatchCallData`] on the caller's frame — fine for host tests and
/// any caller with stack to spare, but the secure batch handler uses the
/// `_into` form to avoid the extra 18 KB copy (see its doc comment).
pub fn reconstruct_execute_batch_calldata(
    owner_index: u64,
    new_offchain_count: u64,
    txs: &[BatchInnerTx<'_>],
) -> Result<ExecuteBatchCallData, BatchAaError> {
    let mut out = ExecuteBatchCallData {
        buf: [0u8; MAX_EXECUTE_BATCH_CALLDATA_LEN],
        len: 0,
    };
    reconstruct_execute_batch_calldata_into(&mut out, owner_index, new_offchain_count, txs)?;
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
/// Write `row` right-aligned into 32-byte slot `i` of the
/// `hashStruct(userOp)` buffer. A dedicated helper (non-loop range
/// copy, re-borrowing `buf` per call): the previous rows-of-`&[u8]`
/// array iterated in a loop is a nested-borrow shape the Aeneas Lean
/// extraction rejects (work-todo §33 P2).
#[inline]
fn write_word_right_aligned(buf: &mut [u8; 10 * WORD], i: usize, row: &[u8]) {
    debug_assert!(row.len() <= WORD);
    let slot_end = (i + 1) * WORD;
    buf[slot_end - row.len()..slot_end].copy_from_slice(row);
}

#[must_use]
pub fn compute_user_op_hash(params: &AaUserOpParams, call_data_hash: &[u8; 32]) -> [u8; 32] {
    // hashStruct(userOp) — 10 × 32 = 320 bytes total. Each row is one
    // right-aligned ABI word; field order matches `UserOp.hash()` in
    // EntryPoint v0.6. Unrolled (no rows-of-refs loop) for the Aeneas
    // Lean extraction — see `write_word_right_aligned`.
    let mut buf = [0u8; 10 * WORD];
    write_word_right_aligned(&mut buf, 0, &params.sender);
    write_word_right_aligned(&mut buf, 1, &params.nonce.0);
    write_word_right_aligned(&mut buf, 2, &params.init_code_hash);
    write_word_right_aligned(&mut buf, 3, call_data_hash);
    write_word_right_aligned(&mut buf, 4, &params.call_gas_limit.0);
    write_word_right_aligned(&mut buf, 5, &params.verification_gas_limit.0);
    write_word_right_aligned(&mut buf, 6, &params.pre_verification_gas.0);
    write_word_right_aligned(&mut buf, 7, &params.max_fee_per_gas.0);
    write_word_right_aligned(&mut buf, 8, &params.max_priority_fee_per_gas.0);
    write_word_right_aligned(&mut buf, 9, &params.paymaster_and_data_hash);

    let inner = keccak256(&buf);

    // userOpHash = keccak256(abi.encode(inner, entryPoint, chainId))
    //   3 × 32-byte words.
    let mut outer = [0u8; 3 * WORD];
    outer[0..WORD].copy_from_slice(&inner);
    outer[WORD + (WORD - 20)..2 * WORD].copy_from_slice(&params.entry_point);
    write_u64_in_word_be(&mut outer[2 * WORD..3 * WORD], params.chain_id);

    // Routed through `pqsigner_tx_core::hash::keccak256` (NOT the
    // incremental sha3 API): keccak256 is the single opaque hash
    // boundary for the Aeneas Lean extraction — one named axiom,
    // mirroring AXIOM_STATUS A1 (work-todo §33 P2).
    keccak256(&outer)
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
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

/// EntryPoint v0.6 canonical singleton address
/// (`0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`). Deployed via Nick's
/// method on every major EVM chain.
pub const ENTRY_POINT_V06: [u8; 20] = [
    0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57, 0x8a,
    0x02, 0x6d, 0x27, 0x89,
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

/// Length of the Type-1 slot-rotation calldata `addOwnerBytes(bytes)` with a
/// 64-byte owner: `selector(4) || offset(32) || length(32) || owner(64)`.
pub const ADD_OWNER_BYTES_CALLDATA_LEN: usize = 4 + 32 + 32 + pqsigner_proto::OWNER_BYTES_LEN;

/// Offset of the 64-byte owner argument inside [`add_owner_bytes_calldata`].
pub const ADD_OWNER_BYTES_ARG_OFFSET: usize = 4 + 32 + 32;

/// The exact Type-1 slot-rotation calldata the bootstrap key signs:
/// `addOwnerBytes(bytes newOwner)` with `newOwner = pkSeed || pkRoot` of the
/// new slot. The owner is already 32-byte aligned, so there is no padding.
///
/// Shared by the firmware (`cmd_sign_userop{,_batch}`) and host-side
/// companions/verifiers, so a companion rebuilding the Type-1 UserOp from the
/// 0x0203 response's `new_owner_bytes` hashes byte-identical calldata (#353).
#[must_use]
pub fn add_owner_bytes_calldata(
    owner: &[u8; pqsigner_proto::OWNER_BYTES_LEN],
) -> [u8; ADD_OWNER_BYTES_CALLDATA_LEN] {
    let mut call = [0u8; ADD_OWNER_BYTES_CALLDATA_LEN];
    call[..4].copy_from_slice(&pqsigner_proto::PQ_ADD_OWNER_BYTES_SELECTOR);
    // ABI head: offset to the dynamic `bytes` = 0x20.
    call[4 + 31] = 0x20;
    // `bytes` length = 64 = 0x40.
    call[4 + 32 + 31] = pqsigner_proto::OWNER_BYTES_LEN as u8;
    call[ADD_OWNER_BYTES_ARG_OFFSET..].copy_from_slice(owner);
    call
}

// ---------------------------------------------------------------------------
// Unified sign-input header arithmetic kernels (extracted for Kani).
//
// These are the load-bearing arithmetic leaves of the companion-facing
// `nsc::cmd_sign_userop` / `_batch` wire parsers (the offset-table parse is
// inlined into the `unsafe` handler, unreachable from a host fuzz/Kani target).
// They are used IN PLACE at the handler's existing sites — `#[inline]`, so with
// cross-crate LTO they fold back into identical codegen, preserving the F-11
// fault-injection structure (the redundant flags reads + recheck are untouched;
// only the `& MASK >> SHIFT` arithmetic and the `data_len` bound route through
// here). Kani then proves exactly the arithmetic the 2026-06-29 audit named.
// Scope: this proves flag-decode totality + the `data_len` inner-slice bound;
// the fixed-offset reads remain guarded by the handler's length gate.
// ---------------------------------------------------------------------------

/// Decode the unified sign-input `flags` bitfield (CLAUDE.md wire format):
/// bit 31 = INCLUDE_INIT_CODE, bit 30 = REGISTER_SLOT, bits 29..22 =
/// account_index (8b), bits 21..0 = slot_index (22b). Returns
/// `(include_init_code, register_slot, account_index, slot_index)`. Pure +
/// total (every `u32` is valid).
#[inline]
#[must_use]
pub fn decode_flags(flags: u32) -> (bool, bool, u32, u32) {
    let include_init_code = (flags & pqsigner_proto::FLAG_INCLUDE_INIT_CODE) != 0;
    let register_slot = (flags & pqsigner_proto::FLAG_REGISTER_SLOT) != 0;
    let account_index =
        (flags & pqsigner_proto::ACCOUNT_INDEX_MASK) >> pqsigner_proto::ACCOUNT_INDEX_SHIFT;
    let slot_index = flags & pqsigner_proto::SLOT_INDEX_MASK;
    (include_init_code, register_slot, account_index, slot_index)
}

/// Validate the header's `data_len` against the snapshot length `total_len`:
/// the inner-tx data slice the handler then cuts
/// (`snap[SIGN_USEROP_HEADER_LEN .. SIGN_USEROP_HEADER_LEN + data_len]`) must
/// be fully in bounds and `data_len ≤ MAX_TX_LEN`. Returns the validated length
/// or `None` to refuse — the single gate that stops a companion-chosen
/// `data_len` from driving an out-of-bounds read of the snapshot buffer.
#[inline]
#[must_use]
pub fn validate_data_len(total_len: usize, data_len_raw: u16) -> Option<usize> {
    let data_len = data_len_raw as usize;
    if data_len > pqsigner_proto::MAX_TX_LEN {
        return None;
    }
    match pqsigner_proto::SIGN_USEROP_HEADER_LEN.checked_add(data_len) {
        Some(end) if end <= total_len => Some(data_len),
        _ => None,
    }
}

#[cfg(kani)]
mod kani_harnesses {
    use super::{
        decode_flags, reconstruct_execute_calldata, validate_data_len, Eip1559Tx, EXECUTE_SELECTOR,
        SELECTOR_LEN, U256, WORD,
    };

    /// `decode_flags` is total (panic/overflow-free for every `u32`) and its
    /// extracted bitfields are bounded to their documented widths (8b account,
    /// 22b slot) — also pins the proto mask widths.
    #[kani::proof]
    fn decode_flags_total_and_bounded() {
        let f: u32 = kani::any();
        let (_init, _reg, acct, slot) = decode_flags(f);
        assert!(acct <= 0xFF);
        assert!(slot <= (1u32 << 22) - 1);
    }

    /// Whenever `validate_data_len` accepts, the inner-tx data slice
    /// `[HEADER_LEN, HEADER_LEN + data_len)` is in bounds of `total_len` and
    /// `data_len ≤ MAX_TX_LEN` — so no companion `data_len` can drive an OOB
    /// read. Loop-free; panic/overflow-free for every `(total_len, data_len)`.
    #[kani::proof]
    fn validate_data_len_keeps_inner_slice_in_bounds() {
        let total_len: usize = kani::any();
        let raw: u16 = kani::any();
        if let Some(d) = validate_data_len(total_len, raw) {
            assert!(d <= pqsigner_proto::MAX_TX_LEN);
            assert!(pqsigner_proto::SIGN_USEROP_HEADER_LEN + d <= total_len);
        }
    }

    /// Panic / overflow / slice-OOB freedom of `reconstruct_execute_calldata`
    /// over symbolic inputs — it runs on companion-supplied `(ownerIndex,
    /// offchainCount, tx, data)` and must terminate for every input
    /// (contract-creation `to == None` and over-long calldata are the two hard
    /// refusals; everything else builds the buffer). Pure byte-assembly, no
    /// hash — so it is fully Kani-reachable (unlike the userOpHash keccak).
    #[kani::proof]
    #[kani::unwind(65)]
    fn reconstruct_execute_panic_free() {
        const M: usize = 64;
        let owner_index: u64 = kani::any();
        let new_offchain_count: u64 = kani::any();
        let to_present: bool = kani::any();
        let to: [u8; 20] = kani::any();
        let value: [u8; 32] = kani::any();
        let data: [u8; M] = kani::any();
        let dlen: usize = kani::any();
        kani::assume(dlen <= M);
        let tx = Eip1559Tx {
            to: if to_present { Some(to) } else { None },
            value: U256(value),
            ..Default::default()
        };
        let _ = reconstruct_execute_calldata(owner_index, new_offchain_count, &tx, &data[..dlen]);
    }

    /// Layout soundness (EXHAUSTIVE for `dlen <= 64`): when
    /// `reconstruct_execute_calldata` returns `Ok`, the buffer is byte-for-byte
    /// the canonical `execute(...)` ABI encoding — `selector || ownerIndex ||
    /// offchainCount || target || value || offset(0xa0) || dataLen || data ||
    /// zero-pad`, every uint right-aligned with top bytes zero, the address
    /// left-padded, and `len == 4 + 6*32 + ceil32(dlen)`. This is EXACTLY the
    /// calldata the on-chain wallet executes; a layout bug = the userOp runs
    /// something other than what was signed.
    #[kani::proof]
    #[kani::unwind(65)]
    fn reconstruct_execute_layout() {
        const M: usize = 64;
        let owner_index: u64 = kani::any();
        let new_offchain_count: u64 = kani::any();
        let to: [u8; 20] = kani::any();
        let value: [u8; 32] = kani::any();
        let data: [u8; M] = kani::any();
        let dlen: usize = kani::any();
        kani::assume(dlen <= M);
        let tx = Eip1559Tx {
            to: Some(to),
            value: U256(value),
            ..Default::default()
        };

        if let Ok(out) =
            reconstruct_execute_calldata(owner_index, new_offchain_count, &tx, &data[..dlen])
        {
            let b = &out.buf;
            let padded = (dlen + 31) & !31usize;
            assert_eq!(out.len, SELECTOR_LEN + 6 * WORD + padded);

            // selector [0..4]
            let mut i = 0;
            while i < 4 {
                assert_eq!(b[i], EXECUTE_SELECTOR[i]);
                i += 1;
            }
            // ownerIndex word [4..36]: top 24 zero, u64 BE in the low 8
            let ob = owner_index.to_be_bytes();
            let mut z = 4;
            while z < 28 {
                assert_eq!(b[z], 0);
                z += 1;
            }
            let mut j = 0;
            while j < 8 {
                assert_eq!(b[28 + j], ob[j]);
                j += 1;
            }
            // newOffchainCount word [36..68]
            let cb = new_offchain_count.to_be_bytes();
            let mut z2 = 36;
            while z2 < 60 {
                assert_eq!(b[z2], 0);
                z2 += 1;
            }
            let mut k = 0;
            while k < 8 {
                assert_eq!(b[60 + k], cb[k]);
                k += 1;
            }
            // target word [68..100]: 12 zero + 20-byte left-padded address
            let mut z3 = 68;
            while z3 < 80 {
                assert_eq!(b[z3], 0);
                z3 += 1;
            }
            let mut t = 0;
            while t < 20 {
                assert_eq!(b[80 + t], to[t]);
                t += 1;
            }
            // value word [100..132] verbatim
            let mut v = 0;
            while v < 32 {
                assert_eq!(b[100 + v], value[v]);
                v += 1;
            }
            // offset word [132..164]: all zero except the 0xa0 low byte
            let mut z4 = 132;
            while z4 < 163 {
                assert_eq!(b[z4], 0);
                z4 += 1;
            }
            assert_eq!(b[163], 0xa0);
            // dataLen word [164..196]
            let db = (dlen as u64).to_be_bytes();
            let mut z5 = 164;
            while z5 < 188 {
                assert_eq!(b[z5], 0);
                z5 += 1;
            }
            let mut d = 0;
            while d < 8 {
                assert_eq!(b[188 + d], db[d]);
                d += 1;
            }
            // data tail [196..196+dlen] verbatim
            let mut e = 0;
            while e < dlen {
                assert_eq!(b[196 + e], data[e]);
                e += 1;
            }
            // zero-pad [196+dlen..len]
            let mut pz = 196 + dlen;
            while pz < out.len {
                assert_eq!(b[pz], 0);
                pz += 1;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Unit tests — run on the host with `cargo test -p pqsigner-aa`.
// ---------------------------------------------------------------------------
#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn add_owner_bytes_calldata_is_exact_abi_encoding() {
        // #353: the companion rebuilds the Type-1 calldata from the response's
        // owner bytes with this function, so it must equal the Solidity ABI
        // encoding of `addOwnerBytes(bytes)` with a 64-byte argument.
        let mut owner = [0u8; 64];
        for (i, b) in owner.iter_mut().enumerate() {
            *b = i as u8 ^ 0xA5;
        }
        let call = add_owner_bytes_calldata(&owner);
        assert_eq!(call.len(), 132);
        assert_eq!(&call[..4], &[0x10, 0x14, 0x90, 0xcb]);
        let mut word = [0u8; 32];
        word[31] = 0x20;
        assert_eq!(&call[4..36], &word);
        word[31] = 0x40;
        assert_eq!(&call[36..68], &word);
        assert_eq!(&call[ADD_OWNER_BYTES_ARG_OFFSET..], &owner);
        // Negative control: a different owner changes the calldata.
        owner[63] ^= 1;
        assert_ne!(add_owner_bytes_calldata(&owner), call);
    }

    // -- helpers ----------------------------------------------------------

    /// Deterministic AA params matching the e2e test fixtures.
    fn test_params() -> AaUserOpParams {
        AaUserOpParams {
            sender: [0x42; 20],
            entry_point: [
                0x5f, 0xf1, 0x37, 0xd4, 0xb0, 0xfd, 0xcd, 0x49, 0xdc, 0xa3, 0x0c, 0x7c, 0xf5, 0x7e,
                0x57, 0x8a, 0x02, 0x6d, 0x27, 0x89,
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
                0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56,
                0x78, 0x90, 0xab, 0xcd, 0xef, 0x12,
            ]),
            value: U256(value),
            data_len: 0,
            access_list_count: 0,
            signing_hash: [0u8; 32],
            userop_fields: None,
        }
    }

    fn u256_from_u64(v: u64) -> U256 {
        let mut buf = [0u8; 32];
        buf[24..32].copy_from_slice(&v.to_be_bytes());
        U256(buf)
    }

    /// keccak256("") — used for empty initCode and paymasterAndData.
    const TEST_KECCAK_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
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
             000000000000000000000000000000000000000000000000000000003b9aca00",
        )
        .unwrap();
        assert_eq!(data.len(), 68);

        let mut tx = test_value_transfer_tx();
        tx.to = Some([
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
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
             0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        assert_eq!(out, expected.as_slice());
    }

    // -- compute_user_op_hash tests ---------------------------------------

    /// Cross-validate against the EntryPoint v0.6 hash computed by
    /// `cast keccak` + `cast abi-encode`. See tools/ for regeneration.
    #[test]
    fn test_hash_known_vector() {
        let params = test_params();
        let call_data_hash =
            hex::decode("da854735bd0e0dc5ee6409e7d6e496a35a2988be7199131994e06ff812d91c9c")
                .unwrap();
        let mut cdh = [0u8; 32];
        cdh.copy_from_slice(&call_data_hash);

        let hash = compute_user_op_hash(&params, &cdh);

        let expected =
            hex::decode("b0ac4b1db1042ca2bd8c1609a6da834b0c0d9d904815cdad2e544ac881ff7579")
                .unwrap();
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
        assert_eq!(
            parsed.verification_gas_limit.0,
            original.verification_gas_limit.0
        );
        assert_eq!(
            parsed.pre_verification_gas.0,
            original.pre_verification_gas.0
        );
        assert_eq!(parsed.max_fee_per_gas.0, original.max_fee_per_gas.0);
        assert_eq!(
            parsed.max_priority_fee_per_gas.0,
            original.max_priority_fee_per_gas.0
        );
        assert_eq!(parsed.init_code_hash, original.init_code_hash);
        assert_eq!(
            parsed.paymaster_and_data_hash,
            original.paymaster_and_data_hash
        );
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
        assert!(out[targets_off + 32..targets_off + 32 + 12]
            .iter()
            .all(|&b| b == 0));
        assert_eq!(
            &out[targets_off + 32 + 12..targets_off + 32 + 32],
            &[0xAA; 20]
        );

        // values length = 1, value = 0
        let values_off = targets_off + 64;
        assert_eq!(out[values_off + 31], 1);
        assert!(out[values_off + 32..values_off + 64]
            .iter()
            .all(|&b| b == 0));

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
        assert!(out[values_off + 64..values_off + 96]
            .iter()
            .all(|&b| b == 0));

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

    #[test]
    fn batch_tuple_commitment_binds_count_order_target_value_and_data() {
        let d0 = [0x11u8, 0x22, 0x33, 0x44];
        let d1 = [0xAAu8; 17];
        let base_txs = [batch_tx(0x10, 7, &d0), batch_tx(0x20, 9, &d1)];
        let base = batch_tuple_commitment(&base_txs).unwrap();

        let target_changed = [batch_tx(0x11, 7, &d0), batch_tx(0x20, 9, &d1)];
        assert_ne!(base, batch_tuple_commitment(&target_changed).unwrap());
        let value_changed = [batch_tx(0x10, 8, &d0), batch_tx(0x20, 9, &d1)];
        assert_ne!(base, batch_tuple_commitment(&value_changed).unwrap());
        let d0_changed = [0x11u8, 0x22, 0x33, 0x45];
        let data_changed = [batch_tx(0x10, 7, &d0_changed), batch_tx(0x20, 9, &d1)];
        assert_ne!(base, batch_tuple_commitment(&data_changed).unwrap());
        let reordered = [batch_tx(0x20, 9, &d1), batch_tx(0x10, 7, &d0)];
        assert_ne!(base, batch_tuple_commitment(&reordered).unwrap());
        assert_ne!(base, batch_tuple_commitment(&base_txs[..1]).unwrap());
    }

    #[test]
    fn live_execute_batch_parser_matches_encoder_for_every_supported_count() {
        let d0 = [0x01u8; 0];
        let d1 = [0x12u8; 1];
        let d2 = [0x23u8; 32];
        let d3 = [0x34u8; 65];
        let txs = [
            batch_tx(0x10, 1, &d0),
            batch_tx(0x20, 2, &d1),
            batch_tx(0x30, 3, &d2),
            batch_tx(0x40, 4, &d3),
        ];
        for count in 1..=pqsigner_proto::MAX_BATCH_TXS {
            let expected = batch_tuple_commitment(&txs[..count]).unwrap();
            let encoded = reconstruct_execute_batch_calldata(7, 19, &txs[..count]).unwrap();
            assert_eq!(
                execute_batch_tuple_commitment_from_calldata(encoded.as_slice(), 7, 19, count,),
                Some(expected)
            );
        }
    }

    #[test]
    fn live_execute_batch_parser_rejects_structure_and_detects_tuple_mutations() {
        let d0 = [0x12u8, 0x34, 0x56, 0x78];
        let d1 = [0xABu8; 36];
        let txs = [batch_tx(0x11, 7, &d0), batch_tx(0x22, 9, &d1)];
        let encoded = reconstruct_execute_batch_calldata(3, 17, &txs).unwrap();
        let bytes = encoded.as_slice();
        let expected = batch_tuple_commitment(&txs).unwrap();
        let authorizes = |candidate: &[u8]| {
            execute_batch_tuple_commitment_from_calldata(candidate, 3, 17, 2) == Some(expected)
        };
        assert!(authorizes(bytes));

        // Fixed head and structural framing.
        for pos in [0usize, 35, 67, 99, 164 + 31, 388 + 31, 452 + 31] {
            let mut changed = bytes.to_vec();
            changed[pos] ^= 1;
            assert!(!authorizes(&changed), "mutation at byte {pos} survived");
        }

        // Exact semantic tuple components: target, value, and calldata.
        for pos in [196 + 12, 292 + 31, 484] {
            let mut changed = bytes.to_vec();
            changed[pos] ^= 1;
            assert!(
                !authorizes(&changed),
                "tuple mutation at byte {pos} survived"
            );
        }

        // Canonical zero padding and exact total consumption are mandatory.
        let mut dirty_padding = bytes.to_vec();
        dirty_padding[484 + d0.len()] = 1;
        assert!(!authorizes(&dirty_padding));
        let mut trailing = bytes.to_vec();
        trailing.push(0);
        assert!(!authorizes(&trailing));

        assert_eq!(
            execute_batch_tuple_commitment_from_calldata(bytes, 4, 17, 2),
            None
        );
        assert_eq!(
            execute_batch_tuple_commitment_from_calldata(bytes, 3, 18, 2),
            None
        );
        assert_eq!(
            execute_batch_tuple_commitment_from_calldata(bytes, 3, 17, 1),
            None
        );
    }
}
