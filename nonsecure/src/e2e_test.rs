// Post-cutover e2e test runner: exercises the stateless, companion-driven
// sign-userop command end-to-end (all-SPHINCS+C10).
//
// The companion decides whether to ask for a Type 1 slot registration
// by setting `FLAG_REGISTER_SLOT` in the flags u32, and picks the slot
// directly via the low 30 bits. The firmware keeps zero slot state on
// disk — each scenario is a pure function of `(chain_id, slot_index,
// flags)` and the master seed.
//
// Compiled only with `--features e2e-test`. The matching feature on
// the secure crate auto-provisions the wallet, marks PIN_VERIFIED
// true, and short-circuits every confirm() dialog so this runner can
// drive signs without any human input.
#![allow(static_mut_refs)]

use crate::nsc_api;
use cortex_m_semihosting::{debug, hprintln};
use sha3::{Digest, Keccak256};
use sphincs_tz_shared::{
    NscStatus, APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, EXEC_TRANSACTION_MIN_CALLDATA_LEN,
    EXEC_TRANSACTION_SELECTOR, FLAG_REGISTER_SLOT, GPV2_SETTLEMENT_ADDRESS,
    GPV2_VAULT_RELAYER_ADDRESS, MAX_BATCH_TXS, MAX_SIGN_RESPONSE_LEN,
    MULTISEND_CALL_ONLY_ADDRESSES, MULTI_SEND_SELECTOR, SAFE_DOMAIN_TYPEHASH, SAFE_OFF_CHAIN_ID,
    SAFE_OFF_DATA_HASH, SAFE_OFF_NONCE, SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO,
    SAFE_TX_TYPEHASH, SAFE_V1_CANONICAL_LEN, SIGN_USEROP_BATCH_HEADER_LEN, SIGN_USEROP_HEADER_LEN,
    SIG_TYPE1_LEN, SIG_TYPE2_LEN, TRAILER_KIND_ERC20, TRAILER_KIND_ERC7730, TRAILER_KIND_SAFE_V1,
};

// === Scratch buffers =======================================================

static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN] = [0u8; MAX_SIGN_RESPONSE_LEN];
// Sized for the largest scenario: the multiSend safe-wrapped CoW presign
// carries a native 204-byte order trailer plus a safe_v1 trailer
// whose raw_data is the ~484-byte multiSend calldata (2 + 281 + 2 + 484)
// on top of the 36 B `approveHash` inner_data — ~1.1 KB of trailers. We
// don't need the firmware's 16 KB SNAP_LEN budget because every e2e
// scenario uses small inner_data.
static mut PAYLOAD_BUF: [u8; SIGN_USEROP_HEADER_LEN + 4096] = [0u8; SIGN_USEROP_HEADER_LEN + 4096];

// === Helpers ===============================================================

/// EntryPoint v0.6 canonical singleton address.
const ENTRY_POINT_V06: [u8; 20] = [
    0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57, 0x8a,
    0x02, 0x6d, 0x27, 0x89,
];

/// `sha256("")` — used for empty paymasterAndData under the all-SHA256
/// sphincs digest.
const SHA256_EMPTY: [u8; 32] = [
    0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9, 0x24,
    0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52, 0xb8, 0x55,
];

fn build_sign_payload(
    buf: &mut [u8],
    sender: &[u8; 20],
    chain_id: u64,
    slot_index: u32,
    register_slot: bool,
    nonce_seq: u64,
    to: &[u8; 20],
    value_wei: u128,
    inner_data: &[u8],
) -> usize {
    let mut nonce = [0u8; 32];
    nonce[24..32].copy_from_slice(&nonce_seq.to_be_bytes());

    fn u128_be_slot(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    let call_gas = u128_be_slot(50_000);
    let ver_gas = u128_be_slot(300_000);
    let pre_gas = u128_be_slot(100_000);
    let max_fee = u128_be_slot(10_000_000_000);
    let max_prio = u128_be_slot(2_000_000_000);

    let mut value = [0u8; 32];
    value[16..32].copy_from_slice(&value_wei.to_be_bytes());

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
    off += 8;
    let flags: u32 = slot_index | if register_slot { FLAG_REGISTER_SLOT } else { 0 };
    buf[off..off + 4].copy_from_slice(&flags.to_be_bytes());
    off += 4;
    buf[off..off + 20].copy_from_slice(sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
    off += 20;
    buf[off..off + 32].copy_from_slice(&nonce);
    off += 32;
    buf[off..off + 32].copy_from_slice(&call_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&ver_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&pre_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_fee);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_prio);
    off += 32;
    buf[off..off + 32].copy_from_slice(&SHA256_EMPTY);
    off += 32;
    buf[off..off + 20].copy_from_slice(to);
    off += 20;
    buf[off..off + 32].copy_from_slice(&value);
    off += 32;
    buf[off..off + 2].copy_from_slice(&(inner_data.len() as u16).to_be_bytes());
    off += 2;
    buf[off..off + inner_data.len()].copy_from_slice(inner_data);
    off += inner_data.len();
    off
}

/// Minimal canonical `Safe.execTransaction(...)` calldata: a zero-value Call
/// to `to`, with empty data and signature tails. This is sufficient to prove
/// that selector ownership does not accidentally reject the valid route; the
/// strict decoder remains the source of truth for the complete ABI.
fn build_minimal_safe_exec(to: &[u8; 20]) -> [u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN] {
    const HEAD_LEN: usize = 10 * 32;
    let mut out = [0u8; EXEC_TRANSACTION_MIN_CALLDATA_LEN];
    out[..4].copy_from_slice(&EXEC_TRANSACTION_SELECTOR);
    out[4 + 12..4 + 32].copy_from_slice(to);

    // Dynamic offsets are measured from the start of the ABI head (after the
    // selector). The first empty length word follows the head; the second
    // follows that first 32-byte length word.
    out[4 + 2 * 32 + 28..4 + 3 * 32].copy_from_slice(&(HEAD_LEN as u32).to_be_bytes());
    out[4 + 9 * 32 + 28..4 + 10 * 32].copy_from_slice(&((HEAD_LEN + 32) as u32).to_be_bytes());
    out
}

/// Canonical ABI for the synthetic E2E
/// `forward(address target, bytes data)` parent carrying one
/// `transfer(address,uint256)` child. The dynamic tail owns the complete
/// parent body, including zero right-padding, exactly as the enrolled policy
/// requires.
fn build_nested_calldata_forward() -> [u8; 196] {
    const PARENT_SELECTOR: [u8; 4] = [0x6f, 0xad, 0xcf, 0x72];
    const CHILD_SELECTOR: [u8; 4] = [0xa9, 0x05, 0x9c, 0xbb];
    const CHILD_CONTRACT: [u8; 20] = [0x56; 20];

    let mut out = [0u8; 196];
    out[..4].copy_from_slice(&PARENT_SELECTOR);
    out[4 + 12..4 + 32].copy_from_slice(&CHILD_CONTRACT);
    out[4 + 32 + 24..4 + 64].copy_from_slice(&64u64.to_be_bytes());
    out[4 + 64 + 24..4 + 96].copy_from_slice(&68u64.to_be_bytes());

    let child = 4 + 96;
    out[child..child + 4].copy_from_slice(&CHILD_SELECTOR);
    out[child + 4 + 12..child + 4 + 32].copy_from_slice(&[0x78; 20]);
    out[child + 4 + 32 + 24..child + 4 + 64].copy_from_slice(&123_456u64.to_be_bytes());
    out
}

/// Canonical ABI for the synthetic E2E
/// `annotate(string subject, string memo)` call. Both independent dynamic
/// tails exactly tile the bytes after the two-word static head.
fn build_multi_tail_two_strings() -> [u8; 196] {
    const SUBJECT: &[u8] = b"alpha subject";
    const MEMO: &[u8] = b"exact memo";
    const FIRST_TAIL: usize = 64;
    const SECOND_TAIL: usize = 128;

    let mut out = [0u8; 196];
    out[..4].copy_from_slice(&keccak256(b"annotate(string,string)")[..4]);
    out[4 + 24..4 + 32].copy_from_slice(&(FIRST_TAIL as u64).to_be_bytes());
    out[4 + 32 + 24..4 + 64].copy_from_slice(&(SECOND_TAIL as u64).to_be_bytes());

    out[4 + FIRST_TAIL + 24..4 + FIRST_TAIL + 32]
        .copy_from_slice(&(SUBJECT.len() as u64).to_be_bytes());
    out[4 + FIRST_TAIL + 32..4 + FIRST_TAIL + 32 + SUBJECT.len()].copy_from_slice(SUBJECT);
    out[4 + SECOND_TAIL + 24..4 + SECOND_TAIL + 32]
        .copy_from_slice(&(MEMO.len() as u64).to_be_bytes());
    out[4 + SECOND_TAIL + 32..4 + SECOND_TAIL + 32 + MEMO.len()].copy_from_slice(MEMO);
    out
}

// === Safe-multisig (`safe_v1`) trailer helpers =============================

#[inline]
fn keccak256(input: &[u8]) -> [u8; 32] {
    let mut h = Keccak256::new();
    h.update(input);
    let mut out = [0u8; 32];
    out.copy_from_slice(&h.finalize());
    out
}

/// Build a 281-byte canonical SafeTx for `(chain_id, safe_address, to,
/// raw_data, nonce_seq, operation)`. All other fields default to zero
/// (typical for a relayer-less Safe approval). `operation` is 0 (Call)
/// for single-call SafeTxs, 1 (DelegateCall) for a MultiSendCallOnly
/// batch.
fn build_safe_canonical(
    chain_id: u64,
    safe_address: &[u8; 20],
    to: &[u8; 20],
    raw_data: &[u8],
    nonce_seq: u64,
    operation: u8,
) -> [u8; SAFE_V1_CANONICAL_LEN] {
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&chain_id.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(safe_address);
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(to);
    let dh = keccak256(raw_data);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&dh);
    c[SAFE_OFF_OPERATION] = operation;
    let mut n = [0u8; 32];
    n[24..32].copy_from_slice(&nonce_seq.to_be_bytes());
    c[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32].copy_from_slice(&n);
    c
}

/// Compute the SafeTx EIP-712 digest natively. Mirrors
/// `secure/src/tx/eip712/safe::compute_safe_tx_hash` byte-for-byte —
/// any divergence here would surface as a calldata cross-check
/// failure when the secure world re-computes the hash.
fn compute_safe_tx_hash(canonical: &[u8; SAFE_V1_CANONICAL_LEN]) -> [u8; 32] {
    // ── Domain separator ───────────────────────────────────────────
    let mut dom_buf = [0u8; 96];
    dom_buf[0..32].copy_from_slice(&SAFE_DOMAIN_TYPEHASH);
    // chainId as uint256 (left-padded)
    dom_buf[32 + 24..32 + 32].copy_from_slice(&canonical[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8]);
    // verifyingContract as address (left-padded to 32)
    dom_buf[64 + 12..64 + 32]
        .copy_from_slice(&canonical[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20]);
    let domain = keccak256(&dom_buf);

    // ── Struct hash ────────────────────────────────────────────────
    let mut sh_buf = [0u8; 32 * 11];
    sh_buf[0..32].copy_from_slice(&SAFE_TX_TYPEHASH);
    // [1] to (left-padded address)
    sh_buf[32 + 12..32 + 32].copy_from_slice(&canonical[SAFE_OFF_TO..SAFE_OFF_TO + 20]);
    // [2] value (uint256)
    sh_buf[64..96].copy_from_slice(&canonical[48..80]);
    // [3] data_hash (bytes32)
    sh_buf[96..128].copy_from_slice(&canonical[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32]);
    // [4] operation (left-padded)
    sh_buf[128 + 31] = canonical[SAFE_OFF_OPERATION];
    // [5..7] safe_tx_gas / base_gas / gas_price (all uint256, defaults zero)
    sh_buf[160..192].copy_from_slice(&canonical[113..145]);
    sh_buf[192..224].copy_from_slice(&canonical[145..177]);
    sh_buf[224..256].copy_from_slice(&canonical[177..209]);
    // [8] gas_token (address left-padded)
    sh_buf[256 + 12..256 + 32].copy_from_slice(&canonical[209..229]);
    // [9] refund_receiver (address left-padded)
    sh_buf[288 + 12..288 + 32].copy_from_slice(&canonical[229..249]);
    // [10] nonce (uint256)
    sh_buf[320..352].copy_from_slice(&canonical[SAFE_OFF_NONCE..SAFE_OFF_NONCE + 32]);
    let struct_hash = keccak256(&sh_buf);

    // ── Final digest: keccak(0x19 || 0x01 || domain || struct) ─────
    let mut final_buf = [0u8; 2 + 32 + 32];
    final_buf[0] = 0x19;
    final_buf[1] = 0x01;
    final_buf[2..34].copy_from_slice(&domain);
    final_buf[34..66].copy_from_slice(&struct_hash);
    keccak256(&final_buf)
}

/// Build `approveHash(bytes32)` calldata for a 32-byte `safeTxHash`.
fn build_approve_hash_calldata(safe_tx_hash: &[u8; 32]) -> [u8; APPROVE_HASH_CALLDATA_LEN] {
    let mut cd = [0u8; APPROVE_HASH_CALLDATA_LEN];
    cd[..4].copy_from_slice(&APPROVE_HASH_SELECTOR);
    cd[4..36].copy_from_slice(safe_tx_hash);
    cd
}

/// Append a `safe_v1` trailer (canonical || u16 raw_data_len || raw_data)
/// to `buf` at `off`. Returns the new offset.
fn append_safe_v1_trailer(
    buf: &mut [u8],
    off: usize,
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
    raw_data: &[u8],
) -> usize {
    let payload_len = SAFE_V1_CANONICAL_LEN + 2 + raw_data.len();
    buf[off..off + 2].copy_from_slice(&(payload_len as u16).to_be_bytes());
    let mut o = off + 2;
    buf[o..o + SAFE_V1_CANONICAL_LEN].copy_from_slice(canonical);
    o += SAFE_V1_CANONICAL_LEN;
    buf[o..o + 2].copy_from_slice(&(raw_data.len() as u16).to_be_bytes());
    o += 2;
    buf[o..o + raw_data.len()].copy_from_slice(raw_data);
    o + raw_data.len()
}

/// Append the three zero-length trailers that come *before* `safe_v1`
/// in the payload framing — ERC-20 bundle, reserved slot, native CoW order — followed by
/// the supplied `safe_v1` payload, then a zero-count names section.
/// Returns the new offset.
fn append_safe_only_trailers(
    buf: &mut [u8],
    off: usize,
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
    raw_data: &[u8],
) -> usize {
    // erc20 bundle absent
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes());
    // reserved compatibility slot absent
    buf[off + 2..off + 4].copy_from_slice(&0u16.to_be_bytes());
    // native CoW order absent
    buf[off + 4..off + 6].copy_from_slice(&0u16.to_be_bytes());
    let mut o = off + 6;
    o = append_safe_v1_trailer(buf, o, canonical, raw_data);
    // No selector trailer, no names-count byte: the parser treats
    // `cursor == total_len` (no byte to read) as `count == 0`.
    // Writing an explicit zero here would leave one trailing byte
    // the cursor doesn't advance past, tripping the
    // `"trailing bytes"` final check.
    o
}

// === CoW GPv2Order native canonical helpers ================================

/// CoW GPv2Order EIP-712 digest, mirroring
/// `secure/src/tx/eip712/cowswap::compute_digest` byte-for-byte (same
/// rationale as `compute_safe_tx_hash` above — any divergence surfaces
/// as an orderDigest cross-check refusal in the secure world).
fn compute_cow_order_digest(canonical: &[u8; 204]) -> [u8; 32] {
    const ORDER_TYPEHASH_PREIMAGE: &[u8] = b"Order(address sellToken,address buyToken,address receiver,uint256 sellAmount,uint256 buyAmount,uint32 validTo,bytes32 appData,uint256 feeAmount,string kind,bool partiallyFillable,string sellTokenBalance,string buyTokenBalance)";

    // ── Domain separator (name "Gnosis Protocol", version "v2") ────
    let domain_typehash = keccak256(
        b"EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)",
    );
    let mut dom = [0u8; 32 * 5];
    dom[0..32].copy_from_slice(&domain_typehash);
    dom[32..64].copy_from_slice(&keccak256(b"Gnosis Protocol"));
    dom[64..96].copy_from_slice(&keccak256(b"v2"));
    dom[96 + 24..128].copy_from_slice(&canonical[0..8]); // chainId
    dom[128 + 12..160].copy_from_slice(&GPV2_SETTLEMENT_ADDRESS);
    let domain = keccak256(&dom);

    // ── Struct hash (13 words, field order per the typehash) ───────
    let kind_hash = if canonical[168] == 0 {
        keccak256(b"sell")
    } else {
        keccak256(b"buy")
    };
    let sell_bal = match canonical[170] {
        0 => keccak256(b"erc20"),
        1 => keccak256(b"external"),
        _ => keccak256(b"internal"),
    };
    let buy_bal = match canonical[171] {
        0 => keccak256(b"erc20"),
        _ => keccak256(b"internal"),
    };
    let mut sh = [0u8; 32 * 13];
    sh[0..32].copy_from_slice(&keccak256(ORDER_TYPEHASH_PREIMAGE));
    sh[32 + 12..64].copy_from_slice(&canonical[8..28]); // sellToken
    sh[64 + 12..96].copy_from_slice(&canonical[28..48]); // buyToken
    sh[96 + 12..128].copy_from_slice(&canonical[48..68]); // receiver
    sh[128..160].copy_from_slice(&canonical[68..100]); // sellAmount
    sh[160..192].copy_from_slice(&canonical[100..132]); // buyAmount
    sh[192 + 28..224].copy_from_slice(&canonical[164..168]); // validTo
    sh[224..256].copy_from_slice(&canonical[172..204]); // appData
    sh[256..288].copy_from_slice(&canonical[132..164]); // feeAmount
    sh[288..320].copy_from_slice(&kind_hash);
    sh[320 + 31] = canonical[169]; // partiallyFillable
    sh[352..384].copy_from_slice(&sell_bal);
    sh[384..416].copy_from_slice(&buy_bal);
    let struct_hash = keccak256(&sh);

    let mut fin = [0u8; 66];
    fin[0] = 0x19;
    fin[1] = 0x01;
    fin[2..34].copy_from_slice(&domain);
    fin[34..66].copy_from_slice(&struct_hash);
    keccak256(&fin)
}

/// Build the 164-byte `setPreSignature(orderUid, true)` calldata for
/// `(orderDigest, owner, validTo)`. orderUid = digest(32) || owner(20)
/// || validTo(4).
fn build_presign_calldata(
    order_digest: &[u8; 32],
    owner: &[u8; 20],
    valid_to_be: &[u8],
) -> [u8; 164] {
    let mut cd = [0u8; 164];
    cd[0..4].copy_from_slice(&[0xec, 0x6c, 0xb1, 0x3f]);
    cd[35] = 0x40; // bytes offset
    cd[67] = 1; // signed = true
    cd[99] = 56; // bytes length
    cd[100..132].copy_from_slice(order_digest);
    cd[132..152].copy_from_slice(owner);
    cd[152..156].copy_from_slice(valid_to_be);
    cd
}

/// Build strict 68-byte `approve(spender, amount)` ERC-20 calldata.
fn build_erc20_approve_calldata(spender: &[u8; 20], amount_low: u64) -> [u8; 68] {
    let mut cd = [0u8; 68];
    cd[0..4].copy_from_slice(&[0x09, 0x5e, 0xa7, 0xb3]);
    cd[16..36].copy_from_slice(spender);
    cd[60..68].copy_from_slice(&amount_low.to_be_bytes());
    cd
}

/// Pack one multiSend record at `off`:
/// `op(1) || to(20) || value(32, zero) || dataLen(32) || data`.
/// Returns the new offset.
fn pack_multisend_record(out: &mut [u8], off: usize, op: u8, to: &[u8; 20], data: &[u8]) -> usize {
    out[off] = op;
    out[off + 1..off + 21].copy_from_slice(to);
    out[off + 21..off + 53].fill(0); // value = 0
    out[off + 53..off + 85].fill(0);
    out[off + 81..off + 85].copy_from_slice(&(data.len() as u32).to_be_bytes());
    out[off + 85..off + 85 + data.len()].copy_from_slice(data);
    off + 85 + data.len()
}

fn build_flyingtulip_deposit(asset: &[u8; 20], amount: u64) -> [u8; 68] {
    let mut calldata = [0u8; 68];
    calldata[..4].copy_from_slice(&[0x47, 0xe7, 0xef, 0x24]);
    calldata[16..36].copy_from_slice(asset);
    calldata[60..68].copy_from_slice(&amount.to_be_bytes());
    calldata
}

/// Canonical one-record `multiSend(bytes)` whose record merely targets a
/// token. It is deliberately carried inside an invalid Safe trailer by the
/// RT-ERC20 regression: these raw bytes must never grant metadata authority.
fn build_one_record_multisend(out: &mut [u8; 256], target: &[u8; 20]) -> usize {
    let records_start = 68;
    let mut end = pack_multisend_record(out, records_start, 0, target, &[]);
    let packed_len = end - records_start;
    out[..4].copy_from_slice(&MULTI_SEND_SELECTOR);
    out[4..36].fill(0);
    out[35] = 0x20;
    out[36..68].fill(0);
    out[64..68].copy_from_slice(&(packed_len as u32).to_be_bytes());
    let pad = (32 - packed_len % 32) % 32;
    out[end..end + pad].fill(0);
    end += pad;
    end
}

/// Encode only the Safe-v1 TLV payload (no legacy single-wire u16 prefix).
fn build_safe_v1_payload(
    out: &mut [u8],
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
    raw_data: &[u8],
) -> usize {
    let total = SAFE_V1_CANONICAL_LEN + 2 + raw_data.len();
    out[..SAFE_V1_CANONICAL_LEN].copy_from_slice(canonical);
    out[SAFE_V1_CANONICAL_LEN..SAFE_V1_CANONICAL_LEN + 2]
        .copy_from_slice(&(raw_data.len() as u16).to_be_bytes());
    out[SAFE_V1_CANONICAL_LEN + 2..total].copy_from_slice(raw_data);
    total
}

/// Build canonical `multiSend(bytes)` calldata for the Safe-UI CoW
/// flow: `[approve(vault relayer) on sell_token, setPreSignature]`.
/// `approve_op` is the approve record's operation byte — 0 for the
/// happy path, 1 to exercise the per-record op gate. Returns the
/// calldata length within `out`.
fn build_cow_multisend_calldata(
    out: &mut [u8; 512],
    approve_op: u8,
    sell_token: &[u8; 20],
    approve_cd: &[u8],
    presign_cd: &[u8; 164],
) -> usize {
    // Packed records start after selector(4) + offset word(32) +
    // length word(32).
    let records_start = 68;
    let mut p = records_start;
    p = pack_multisend_record(out, p, approve_op, sell_token, approve_cd);
    p = pack_multisend_record(out, p, 0, &GPV2_SETTLEMENT_ADDRESS, presign_cd);
    let packed_len = p - records_start;

    out[0..4].copy_from_slice(&MULTI_SEND_SELECTOR);
    out[4..36].fill(0);
    out[35] = 0x20; // bytes head offset = 32
    out[36..68].fill(0);
    out[64..68].copy_from_slice(&(packed_len as u32).to_be_bytes());
    // Zero-pad the bytes tail to a 32-byte boundary, like Solidity.
    let pad = (32 - packed_len % 32) % 32;
    out[p..p + pad].fill(0);
    p + pad
}

/// Append a native kind-3 trailer (bare 204-byte GPv2Order canonical)
/// AND a `safe_v1`
/// trailer, preceded by zero-length ERC-20 and reserved sections. This is
/// the Safe-wrapped CoW presign wire shape. Returns the new offset.
fn append_cow_canonical_and_safe_trailers(
    buf: &mut [u8],
    off: usize,
    order_canonical: &[u8; 204],
    canonical: &[u8; SAFE_V1_CANONICAL_LEN],
    raw_data: &[u8],
) -> usize {
    // erc20 bundle absent
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes());
    // reserved compatibility slot absent
    buf[off + 2..off + 4].copy_from_slice(&0u16.to_be_bytes());
    // Frozen kind-3 slot = bare native canonical.
    buf[off + 4..off + 6].copy_from_slice(&204u16.to_be_bytes());
    let mut o = off + 6;
    buf[o..o + 204].copy_from_slice(order_canonical);
    o += 204;
    o = append_safe_v1_trailer(buf, o, canonical, raw_data);
    // No selector trailer, no names-count byte (see
    // `append_safe_only_trailers` for the trailing-bytes rationale).
    o
}

/// Append the four trailers that come BEFORE the selector trailer
/// (erc20=0, reserved_v1=0, cow_order=0, safe_v1=0) followed by a selector
/// bundle built by the host-stub `selectors_db::build_bundle` for
/// `selector`. Returns the new offset. Caller is responsible for
/// keeping `buf` large enough.
///
/// Wire shape after this function:
///   off..off+2  : erc20_len = 0
///   off+2..+4   : reserved_v1_len = 0
///   off+4..+6   : cow_order_len = 0
///   off+6..+8   : safe_v1_len = 0
///   off+8..+10  : selector_len (u16 BE)
///   off+10..    : selector bundle bytes
///
/// No trailing names section — `cursor == total_len` after the
/// selector bundle is treated as zero name bundles.
fn append_selector_only_trailers(buf: &mut [u8], off: usize, selector: &[u8; 4]) -> Option<usize> {
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes());
    buf[off + 2..off + 4].copy_from_slice(&0u16.to_be_bytes());
    buf[off + 4..off + 6].copy_from_slice(&0u16.to_be_bytes());
    buf[off + 6..off + 8].copy_from_slice(&0u16.to_be_bytes());
    let mut scratch = [0u8; 1100];
    let n = crate::selectors_db::build_bundle(selector, &mut scratch)?;
    if n > u16::MAX as usize {
        return None;
    }
    buf[off + 8..off + 10].copy_from_slice(&(n as u16).to_be_bytes());
    buf[off + 10..off + 10 + n].copy_from_slice(&scratch[..n]);
    Some(off + 10 + n)
}

/// Build a self-attest selector bundle: `selector(4) ||
/// text_sig_len(1) || text_sig(<=63)`. The companion is responsible
/// for ensuring `keccak256(text_sig)[..4] == selector`; this builder
/// does NOT recompute keccak so callers can also exercise mismatch
/// scenarios.
fn build_self_attest_bundle(out: &mut [u8], selector: &[u8; 4], text_sig: &[u8]) -> Option<usize> {
    if text_sig.is_empty() || text_sig.len() > 63 {
        return None;
    }
    let needed = 4 + 1 + text_sig.len();
    if out.len() < needed {
        return None;
    }
    out[..4].copy_from_slice(selector);
    out[4] = text_sig.len() as u8;
    out[5..5 + text_sig.len()].copy_from_slice(text_sig);
    Some(needed)
}

/// Append five zero-length trailers (erc20=0, reserved1=0, cow_order=0,
/// safe_v1=0, selector=0) followed by a self-attest trailer carrying
/// `(selector, text_sig)`. Returns the new offset. Caller is
/// responsible for keeping `buf` large enough.
///
/// Wire shape after this function:
///   off..off+2   : erc20_len   = 0
///   off+2..+4    : reserved1_len = 0
///   off+4..+6    : cow_order_len   = 0
///   off+6..+8    : safe_v1_len = 0
///   off+8..+10   : selector_len = 0
///   off+10..+12  : self_attest_len (u16 BE)
///   off+12..     : self-attest bundle bytes
fn append_self_attest_only_trailers(
    buf: &mut [u8],
    off: usize,
    selector: &[u8; 4],
    text_sig: &[u8],
) -> Option<usize> {
    for i in 0..5 {
        buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&0u16.to_be_bytes());
    }
    let mut scratch = [0u8; 68];
    let n = build_self_attest_bundle(&mut scratch, selector, text_sig)?;
    if n > u16::MAX as usize {
        return None;
    }
    buf[off + 10..off + 12].copy_from_slice(&(n as u16).to_be_bytes());
    buf[off + 12..off + 12 + n].copy_from_slice(&scratch[..n]);
    Some(off + 12 + n)
}

/// Pre-built ERC-7730 trailer payload for WETH on Sepolia (chain
/// 11155111). Generated at build time by `build.rs` from
/// `tools/companion-stub/erc7730_db_e2e.bin` to keep this NS test
/// firmware self-contained (no runtime catalog parsing). Phase 3
/// smoke step uses this to drive `cmd_sign_userop` with a real
/// ERC-7730 trailer attached.
#[cfg(feature = "e2e-test")]
const ERC7730_TRAILER_WETH_SEPOLIA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erc7730_e2e_weth_sepolia.bin"));

/// Mainnet WETH bundle used only as a cryptographically-valid but deliberately
/// mis-bound trailer in the known-call refusal differential.
#[cfg(feature = "e2e-test")]
const ERC7730_TRAILER_WETH_MAINNET: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erc7730_e2e_weth_mainnet.bin"));

#[cfg(feature = "e2e-test")]
const ERC7730_TRAILER_FLYINGTULIP_MAINNET: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/erc7730_e2e_flyingtulip_positions_mainnet.bin"
));

/// Generated typed-data fixture:
/// `[domain_separator(32) | primary_type_hash(32) | ERC-7730 trailer]`.
/// All binding values come from the checked-in E2E catalogue at build time.
#[cfg(feature = "e2e-test")]
const ERC7730_EIP712_DELEGATION_SEPOLIA: &[u8] = include_bytes!(concat!(
    env!("OUT_DIR"),
    "/erc7730_e2e_delegation_sepolia.bin"
));

/// Generated versioned proof set for the synthetic chain-31337
/// parent/child pair. Both legacy bundles and their Merkle proofs are derived
/// from the exact checked-in E2E catalogue by `build.rs`.
#[cfg(feature = "e2e-test")]
const ERC7730_PROOF_SET_NESTED_CALLDATA: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erc7730_e2e_nested_calldata.bin"));

/// Generated legacy bundle for the synthetic rooted two-string descriptor.
#[cfg(feature = "e2e-test")]
const ERC7730_TRAILER_MULTI_TAIL: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/erc7730_e2e_multi_tail.bin"));

/// Append zero-length placeholders for every prior trailer slot and
/// then the supplied ERC-7730 bundle. Sign-input wire ordering is
/// `erc20 → reserved1 → cow_order → safe_v1 → selector → self_attest →
/// erc7730 → names`; we want only the ERC-7730 slot populated so the
/// six prior slots get `[u16 = 0]` empties.
fn append_erc7730_only_trailers(buf: &mut [u8], off: usize, bundle: &[u8]) -> Option<usize> {
    // 6 prior trailers × 2 bytes of zero-length prefix.
    for i in 0..6 {
        buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&0u16.to_be_bytes());
    }
    if bundle.len() > u16::MAX as usize {
        return None;
    }
    let n = bundle.len();
    buf[off + 12..off + 14].copy_from_slice(&(n as u16).to_be_bytes());
    buf[off + 14..off + 14 + n].copy_from_slice(bundle);
    Some(off + 14 + n)
}

/// Append BOTH a curated selector trailer AND a self-attest trailer
/// (the firmware must refuse this with InvalidPointer — they're
/// declared mutually exclusive at the wire level).
fn append_both_selector_trailers(
    buf: &mut [u8],
    off: usize,
    curated_selector: &[u8; 4],
    self_attest_selector: &[u8; 4],
    self_attest_text: &[u8],
) -> Option<usize> {
    // erc20 / reserved1 / cow_order / safe_v1 absent
    for i in 0..4 {
        buf[off + i * 2..off + i * 2 + 2].copy_from_slice(&0u16.to_be_bytes());
    }
    let mut o = off + 8;
    // curated bundle
    let mut scratch = [0u8; 1100];
    let n_cur = crate::selectors_db::build_bundle(curated_selector, &mut scratch)?;
    if n_cur > u16::MAX as usize {
        return None;
    }
    buf[o..o + 2].copy_from_slice(&(n_cur as u16).to_be_bytes());
    o += 2;
    buf[o..o + n_cur].copy_from_slice(&scratch[..n_cur]);
    o += n_cur;
    // self-attest bundle
    let mut sa = [0u8; 68];
    let n_sa = build_self_attest_bundle(&mut sa, self_attest_selector, self_attest_text)?;
    if n_sa > u16::MAX as usize {
        return None;
    }
    buf[o..o + 2].copy_from_slice(&(n_sa as u16).to_be_bytes());
    o += 2;
    buf[o..o + n_sa].copy_from_slice(&sa[..n_sa]);
    Some(o + n_sa)
}

/// Append an ERC-20 metadata trailer (slot 1) built by the host-side
/// companion stub `erc20_db::build_bundle` for `(chain_id, token)`.
/// This is the wire shape the real companion app emits now that the
/// ERC-20 DB lives host-side: the device holds only `ERC20_DB_ROOT` and
/// Merkle-verifies the bundle in S-world. ERC-20 is the first trailer
/// slot, so every later slot is left absent (cursor == total ⇒ treated
/// as empty), matching the `append_*_only_trailers` pattern. Returns the
/// new offset, or `None` if the token isn't in the host DB.
fn append_erc20_only_trailer(
    buf: &mut [u8],
    off: usize,
    chain_id: u64,
    token: &[u8; 20],
) -> Option<usize> {
    // Matches `MAX_ERC20_BUNDLE_LEN` in `secure/src/erc20/bundle.rs`.
    let mut bundle = [0u8; 1120];
    let n = crate::erc20_db::build_bundle(chain_id, token, &mut bundle)?;
    if n > u16::MAX as usize {
        return None;
    }
    buf[off..off + 2].copy_from_slice(&(n as u16).to_be_bytes());
    buf[off + 2..off + 2 + n].copy_from_slice(&bundle[..n]);
    Some(off + 2 + n)
}

/// Append an address-name trailer (slot 8) for `(chain_id, address)`
/// built by the host-side companion stub `names_db::build_bundle`. The
/// names section sits after the seven u16-prefixed trailer slots, so we
/// emit seven zero-length prefixes (erc20 … erc7730), a 1-byte count,
/// then the `[u16 len | bundle]`. Same trust model as ERC-20 — the
/// device holds only `NAMES_DB_ROOT` and Merkle-verifies in S-world.
/// Returns the new offset, or `None` if the address isn't in the host
/// names DB.
fn append_names_only_trailer(
    buf: &mut [u8],
    off: usize,
    chain_id: u64,
    address: &[u8; 20],
) -> Option<usize> {
    // Matches the `MAX_NAME_BUNDLE_LEN` upper bound.
    let mut bundle = [0u8; 1200];
    let n = crate::names_db::build_bundle(chain_id, address, &mut bundle)?;
    if n > u16::MAX as usize {
        return None;
    }
    // Seven empty u16 prefixes, secure-parser order:
    // erc20, reserved1, cow_order, safe_v1, selector, self_attest, erc7730.
    let mut o = off;
    for _ in 0..7 {
        buf[o..o + 2].copy_from_slice(&0u16.to_be_bytes());
        o += 2;
    }
    buf[o] = 1; // names count
    o += 1;
    buf[o..o + 2].copy_from_slice(&(n as u16).to_be_bytes());
    o += 2;
    buf[o..o + n].copy_from_slice(&bundle[..n]);
    Some(o + n)
}

/// One inner tx descriptor used by the batch e2e helper.
struct E2eBatchTx<'a> {
    to: [u8; 20],
    value_wei: u128,
    data: &'a [u8],
}

/// Build a `CMD_SIGN_USEROP_BATCH` wire payload from a slice of inner
/// txs. Mirrors the firmware's parser in
/// `secure/src/nsc/cmd_sign_userop_batch.rs` byte-for-byte.
fn build_batch_payload(
    buf: &mut [u8],
    sender: &[u8; 20],
    chain_id: u64,
    slot_index: u32,
    register_slot: bool,
    nonce_seq: u64,
    inner: &[E2eBatchTx<'_>],
) -> usize {
    assert!(inner.len() <= MAX_BATCH_TXS);
    assert!(!inner.is_empty());

    let mut nonce = [0u8; 32];
    nonce[24..32].copy_from_slice(&nonce_seq.to_be_bytes());

    fn u128_be_slot(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..32].copy_from_slice(&v.to_be_bytes());
        out
    }

    let call_gas = u128_be_slot(60_000);
    let ver_gas = u128_be_slot(400_000);
    let pre_gas = u128_be_slot(120_000);
    let max_fee = u128_be_slot(10_000_000_000);
    let max_prio = u128_be_slot(2_000_000_000);

    let flags: u32 = slot_index | if register_slot { FLAG_REGISTER_SLOT } else { 0 };

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&flags.to_be_bytes());
    off += 4;
    buf[off..off + 20].copy_from_slice(sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
    off += 20;
    buf[off..off + 32].copy_from_slice(&nonce);
    off += 32;
    buf[off..off + 32].copy_from_slice(&call_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&ver_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&pre_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_fee);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_prio);
    off += 32;
    buf[off..off + 32].copy_from_slice(&SHA256_EMPTY);
    off += 32;
    debug_assert_eq!(off, SIGN_USEROP_BATCH_HEADER_LEN - 2);
    // Wire v2: version byte at offset 276, batch_count at offset 277.
    buf[off] = sphincs_tz_shared::SIGN_USEROP_BATCH_WIRE_VERSION;
    off += 1;
    buf[off] = inner.len() as u8;
    off += 1;
    debug_assert_eq!(off, SIGN_USEROP_BATCH_HEADER_LEN);

    for tx in inner.iter() {
        let mut value = [0u8; 32];
        value[16..32].copy_from_slice(&tx.value_wei.to_be_bytes());
        buf[off..off + 20].copy_from_slice(&tx.to);
        off += 20;
        buf[off..off + 32].copy_from_slice(&value);
        off += 32;
        buf[off..off + 2].copy_from_slice(&(tx.data.len() as u16).to_be_bytes());
        off += 2;
        buf[off..off + tx.data.len()].copy_from_slice(tx.data);
        off += tx.data.len();
    }

    // Empty TLV-tagged trailer list — `trailer_count = 0`. The
    // legacy single-ERC-7730 trailer slot is gone; companions that
    // want trailers emit them as kind/tx_idx/len/bytes records here.
    // Without an explicit terminator byte the firmware refuses the
    // payload (parse_batch_trailers expects `total_len` to consume to
    // exactly one byte past `cursor` for the empty case).
    buf[off] = 0u8;
    off += 1;

    off
}

/// Replace the empty batch-trailer terminator emitted by
/// [`build_batch_payload`] with one per-transaction TLV record.
fn append_one_batch_trailer(
    buf: &mut [u8],
    payload_len: usize,
    kind: u8,
    tx_idx: u8,
    trailer: &[u8],
) -> Option<usize> {
    append_batch_trailers(buf, payload_len, &[(kind, tx_idx, trailer)])
}

fn append_batch_trailers(
    buf: &mut [u8],
    payload_len: usize,
    trailers: &[(u8, u8, &[u8])],
) -> Option<usize> {
    let count_off = payload_len.checked_sub(1)?;
    if buf[count_off] != 0 || trailers.len() > u8::MAX as usize {
        return None;
    }
    buf[count_off] = trailers.len() as u8;
    let mut off = payload_len;
    for &(kind, tx_idx, trailer) in trailers {
        let len = u16::try_from(trailer.len()).ok()?;
    let end = off.checked_add(4)?.checked_add(trailer.len())?;
    if end > buf.len() {
        return None;
    }
    buf[off] = kind;
    buf[off + 1] = tx_idx;
        buf[off + 2..off + 4].copy_from_slice(&len.to_be_bytes());
    off += 4;
    buf[off..end].copy_from_slice(trailer);
        off = end;
    }
    Some(off)
}

/// Parse a `[count(8)][ic_len|ic][type1_len|t1][type2_len|t2]` bundle and
/// assert basic shape.
///
/// Returns `(type1_present, type2_len)`.
fn parse_response(resp: &[u8]) -> (bool, usize) {
    // Skip the leading 8-byte new_offchain_count.
    let header = 8;
    let ic_len = u32::from_be_bytes([
        resp[header],
        resp[header + 1],
        resp[header + 2],
        resp[header + 3],
    ]) as usize;
    let t1_len_off = header + 4 + ic_len;
    let t1_len = u32::from_be_bytes([
        resp[t1_len_off],
        resp[t1_len_off + 1],
        resp[t1_len_off + 2],
        resp[t1_len_off + 3],
    ]) as usize;
    assert!(t1_len == 0 || t1_len == SIG_TYPE1_LEN);
    let t2_off = t1_len_off + 4 + t1_len;
    let t2_len = u32::from_be_bytes([
        resp[t2_off],
        resp[t2_off + 1],
        resp[t2_off + 2],
        resp[t2_off + 3],
    ]) as usize;
    assert_eq!(t2_len, SIG_TYPE2_LEN, "Type 2 is a fixed-length C10 sig");
    (t1_len != 0, t2_len)
}

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS][e2e] === unified sign runner ===");

    // The secure `e2e-test` feature auto-provisions and pre-unlocks the
    // gateway at boot. Under probe-rs the PIN-entry dialog would spin on
    // semihosting op 0x07 (SYS_READC) because probe-rs doesn't implement
    // it, so we intentionally skip `CMD_REQUEST_UNLOCK` here and just
    // verify the pre-unlock worked — same pattern `bench_key_speed` uses.
    if !nsc_api::is_unlocked() {
        hprintln!("[NS][e2e] FAIL: gateway not pre-unlocked (needs e2e-test on secure)");
        debug::exit(debug::EXIT_FAILURE);
        loop {}
    }
    hprintln!("[NS][e2e] gateway pre-unlocked: OK");

    // Use the same mnemonic/account-derived sender the production companion
    // obtains. Never bypass the secure-world sender gate under `e2e-test`:
    // these scenarios are its positive regression coverage.
    let mut wallet_sender = [0u8; 20];
    let address_status = nsc_api::get_wallet_address(&mut wallet_sender, 0, 0);
    assert_eq!(
        address_status,
        NscStatus::Ok as u32,
        "e2e GET_WALLET_ADDRESS(0) must succeed"
    );
    hprintln!("[NS][e2e] account-0 sender derived: OK");

    let to_alice: [u8; 20] = [
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12,
    ];

    // Scenario 0a: a one-bit companion sender substitution is rejected before
    // confirmation, key derivation for the slot, or signature release.
    hprintln!("[NS][e2e] Scenario 0a: mismatched single sender is refused");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &to_alice,
            1,
            &[],
        );
        PAYLOAD_BUF[12] ^= 0x01;
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "single UserOp with the wrong deterministic sender must be refused"
        );
    }

    // Scenario 0b: the atomic batch gateway enforces the same binding.
    hprintln!("[NS][e2e] Scenario 0b: mismatched batch sender is refused");
    unsafe {
        let inner = [E2eBatchTx {
            to: to_alice,
            value_wei: 1,
            data: &[],
        }];
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &inner,
        );
        PAYLOAD_BUF[12] ^= 0x01;
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "batch UserOp with the wrong deterministic sender must be refused"
        );
    }

    // Scenario 0c: the account-index bits are part of the sender binding. A
    // valid account-0 address must not be accepted when flags select account 1.
    hprintln!("[NS][e2e] Scenario 0c: cross-account sender is refused");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &to_alice,
            1,
            &[],
        );
        let mut flags = u32::from_be_bytes([
            PAYLOAD_BUF[8],
            PAYLOAD_BUF[9],
            PAYLOAD_BUF[10],
            PAYLOAD_BUF[11],
        ]);
        flags |= 1u32 << sphincs_tz_shared::ACCOUNT_INDEX_SHIFT;
        PAYLOAD_BUF[8..12].copy_from_slice(&flags.to_be_bytes());
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "account-0 sender must not pass an account-1 binding"
        );
    }

    // Scenario 0d: the single handler treats the wire EntryPoint as an
    // assertion against the firmware-pinned v0.6 singleton. A one-bit hostile
    // substitution must fail before any render or signature work.
    hprintln!("[NS][e2e] Scenario 0d: mismatched single EntryPoint is refused");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &to_alice,
            1,
            &[],
        );
        PAYLOAD_BUF[32] ^= 0x01;
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "single UserOp with a non-v0.6 EntryPoint must be refused"
        );
    }

    // Scenario 0e: the batch handler owns the same fixed EntryPoint domain.
    hprintln!("[NS][e2e] Scenario 0e: mismatched batch EntryPoint is refused");
    unsafe {
        let inner = [E2eBatchTx {
            to: to_alice,
            value_wei: 1,
            data: &[],
        }];
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &inner,
        );
        PAYLOAD_BUF[32] ^= 0x01;
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "batch UserOp with a non-v0.6 EntryPoint must be refused"
        );
    }

    // Scenario 0f: a selector-only Safe execTransaction claim is owned by the
    // Safe route even though it is too short to decode. It must never reach a
    // generic blind or selector-label fallback.
    hprintln!("[NS][e2e] Scenario 0f: selector-only Safe exec is refused");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &to_alice,
            0,
            &EXEC_TRANSACTION_SELECTOR,
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "selector-only Safe execTransaction must be refused"
        );
    }

    // Scenario 0g: the one-member batch route must enforce the identical
    // selector-only refusal before its CoW pre-pass or per-member ladder.
    hprintln!("[NS][e2e] Scenario 0g: selector-only Safe exec batch is refused");
    unsafe {
        let inner = [E2eBatchTx {
            to: to_alice,
            value_wei: 0,
            data: &EXEC_TRANSACTION_SELECTOR,
        }];
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &inner,
        );
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "one-member batch with selector-only Safe execTransaction must be refused"
        );
    }

    // Scenario 0h: the liveness control. A complete canonical Safe
    // execTransaction remains accepted; only malformed claims were narrowed.
    hprintln!("[NS][e2e] Scenario 0h: canonical Safe exec remains signable");
    unsafe {
        let safe_address = [0x5Au8; 20];
        let safe_target = [0xA5u8; 20];
        let inner_data = build_minimal_safe_exec(&safe_target);
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            0,
            &safe_address,
            0,
            &inner_data,
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "canonical Safe execTransaction must remain signable"
        );
        let (t1_present, _) = parse_response(&SIG_BUF);
        assert!(
            !t1_present,
            "canonical Safe exec control does not rotate a slot"
        );
    }

    // Scenario 1: rotation to slot 1 on chain A — expect Type 1 + Type 2.
    // (Post-Coinbase-port: REGISTER_SLOT requires slot_index >= 1 —
    // slot 0 is pre-registered by the factory at deploy time.)
    hprintln!("[NS][e2e] Scenario 1: register slot 1 on chain A (Type 1 + Type 2)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111, // Sepolia
            1,          // slot_index
            true,       // register_slot
            1,          // base nonce
            &to_alice,
            1_000_000_000_000_000_000u128, // 1 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 1 must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(t1_present, "scenario 1 must emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    // Scenario 2: repeat sign on same chain/slot, no flag — expect Type 2 only.
    hprintln!("[NS][e2e] Scenario 2: repeat sign on chain A slot 1 (Type 2 only)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false, // slot already registered
            2,
            &to_alice,
            500_000_000_000_000_000u128, // 0.5 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 2 must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 2 must NOT emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    // Scenario 3: companion rotates to slot 2 on the same chain — expect
    // Type 1 (new slot registration) + Type 2.
    hprintln!("[NS][e2e] Scenario 3: rotate to slot 2 on chain A (Type 1 + Type 2)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            2, // new slot
            true,
            3,
            &to_alice,
            250_000_000_000_000_000u128, // 0.25 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 3 must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(t1_present, "scenario 3 must emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    // Scenario 4: FirstSign on a different chain_id — expect
    // Type 1 + Type 2. Uses slot_index=1 per the post-Coinbase-port
    // rule (slot 0 is the factory-deployed slot).
    hprintln!("[NS][e2e] Scenario 4: register slot 1 on chain B (Type 1 + Type 2)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            84_532, // Base Sepolia
            1,
            true,
            1,
            &to_alice,
            100_000_000_000_000_000u128, // 0.1 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 4 must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(t1_present, "scenario 4 must emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    // Scenario 4a: a zero-value call with empty calldata — the
    // `value_transfer` painter's "Contract call?" flavour (pixel family
    // `contract_call`).
    hprintln!("[NS][e2e] Scenario 4a: zero-value contract call");
    unsafe {
        let contract: [u8; 20] = [
            0x9e, 0x3b, 0x5c, 0x0f, 0x7a, 0x1d, 0x24, 0xe8, 0x6c, 0x3f, 0x0b, 0x7d, 0x5a, 0x2e, 0x4c,
            0x6f, 0x8b, 0x1d, 0x3a, 0x7c,
        ];
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            4,
            &contract,
            0u128,
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 4a must succeed");
        let (t1_present, _) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 4a must NOT emit a Type 1");
    }

    // Scenario 4b: an ERC-20 transfer of a token with no verified metadata
    // (the `erc20_unknown` painter; pixel family `transfer_unknown_token`).
    hprintln!("[NS][e2e] Scenario 4b: unknown-token ERC-20 transfer");
    unsafe {
        let token: [u8; 20] = [
            0x3c, 0xa9, 0xe5, 0xf1, 0xb7, 0x2d, 0x04, 0xe8, 0xa6, 0xc1, 0xd9, 0xb3, 0xf5, 0x7e, 0x28,
            0xa0, 0xc4, 0xd6, 0xb1, 0xe9,
        ];
        let mut data = [0u8; 68];
        data[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data[16..36].copy_from_slice(&to_alice);
        data[52..68].copy_from_slice(&12_345_678_901_234_567_890u128.to_be_bytes());
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            5,
            &token,
            0u128,
            &data,
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 4b must succeed");
        let (t1_present, _) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 4b must NOT emit a Type 1");
    }

    // Scenario 4c: the first UserOp of a counterfactual wallet — slot 0 with
    // `FLAG_INCLUDE_INIT_CODE`, so the response carries the 4280-B initCode
    // and the confirmation carries the loud deployment page (pixel: the
    // `! DEPLOY` trailer twin).
    hprintln!("[NS][e2e] Scenario 4c: first deploy with initCode");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            8453, // Base
            0,
            false,
            0,
            &to_alice,
            10_000_000_000_000_000u128, // 0.01 ETH
            &[],
        );
        let flags: u32 = sphincs_tz_shared::FLAG_INCLUDE_INIT_CODE;
        PAYLOAD_BUF[8..12].copy_from_slice(&flags.to_be_bytes());
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 4c must succeed");
        let ic_len = u32::from_be_bytes([SIG_BUF[8], SIG_BUF[9], SIG_BUF[10], SIG_BUF[11]]);
        assert_eq!(ic_len, 4280, "scenario 4c must emit the initCode");
        let (t1_present, _) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 4c must NOT emit a Type 1");
        hprintln!("[NS][e2e]   → init_code_len={}", ic_len);
    }

    // Scenario 5: Safe-multisig `approveHash` clear-sign.
    //
    // Build a synthetic SafeTx that calls
    // `IERC20.transfer(0xRECIPIENT, 250_000_000)` (250 USDC, 6 decimals)
    // on a Safe deployed at `0xSAFE…` on Sepolia. The companion
    // assembles the canonical + raw_data + safeTxHash, the firmware
    // independently re-keccaks both chains and byte-compares against
    // `inner_data[4..36]`. A successful sign proves the trailer parser,
    // cross-check pipeline, and renderer are all wired correctly.
    hprintln!("[NS][e2e] Scenario 5: Safe approveHash clear-sign");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
        ];
        let usdc_addr: [u8; 20] = [
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ];
        let recipient: [u8; 20] = [0xab; 20];

        // ERC-20 `transfer(recipient, 250_000_000)` calldata.
        let mut raw_data = [0u8; 4 + 32 + 32];
        raw_data[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        raw_data[16..36].copy_from_slice(&recipient);
        let amount: u64 = 250_000_000;
        raw_data[60..68].copy_from_slice(&amount.to_be_bytes());

        let chain_id: u64 = 11_155_111; // Sepolia
        let safe_nonce: u64 = 17;
        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &usdc_addr,
            &raw_data,
            safe_nonce,
            0, // Call
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        // Build the outer UserOp: `to = safe_address` (the wallet calls
        // approveHash on its parent Safe), `value = 0`,
        // `data = approveHash(safeTxHash)`.
        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,     // already-registered slot 1 (after Scenario 1's rotation)
            false, // no slot rotation; already registered on Sepolia from Scenario 1
            4,     // base nonce
            &safe_address,
            0u128,
            &inner_data,
        );

        // Strip the 0-length trailers `build_sign_payload` doesn't write
        // — it stops at the inner_data end. Append the four trailer
        // sections (erc20=0, reserved_v1=0, cow_order=0,
        // safe_v1=payload, names=0).
        len = append_safe_only_trailers(&mut PAYLOAD_BUF, len, &canonical, &raw_data);

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5 must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(
            !t1_present,
            "scenario 5 must NOT emit Type 1 (slot already registered)"
        );
        hprintln!("[NS][e2e]   → safe_v1 verified, t2_len={}", t2_len);
    }

    // Scenario 5b: Verified function-selector → text-signature bundle,
    // typed-args render path (Phase 2).
    //
    // Build calldata for `balanceOf(address)` (selector 0x70a08231).
    // This selector is NOT one of the three hardcoded ERC-20
    // selectors (transfer / transferFrom / approve), so the dispatch
    // ladder falls through past the ERC-20 branch — and into the
    // Phase 2 typed-args gate that fires before BLIND SIGN.
    //
    // The secure side must:
    //   1. parse the optional selector trailer,
    //   2. Merkle-verify the bundle against SELECTOR_DB_ROOT_E2E,
    //   3. cross-check `bundle.selector == calldata[0..4]`,
    //   4. parse the verified text_sig "balanceOf(address)",
    //   5. ABI-walk the 32-byte body and decode the single address arg,
    //   6. render the typed-args flow (banner + 1 typed arg + To +
    //      Chain + 2 fee pages + Nonce — Value page skipped since
    //      value is zero on this UserOp).
    //
    // Asserting Ok proves the full happy path; the OLED capture in
    // the QEMU log shows the typed render with "arg 0 address:"
    // followed by the decoded recipient.
    hprintln!("[NS][e2e] Scenario 5b: verified function-selector bundle");
    unsafe {
        // Calldata = balanceOf(0xQUERY_ADDRESS) — selector 0x70a08231.
        let query_addr: [u8; 20] = [0xab; 20];
        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]);
        calldata[16..36].copy_from_slice(&query_addr);

        // Target an address NOT in the ERC-20 DB; it doesn't matter
        // for this path (balanceOf isn't an ERC-20 hardcoded
        // selector) but keeps the test independent of token
        // metadata.
        let unknown_contract: [u8; 20] = [0xfe; 20];

        let chain_id: u64 = 11_155_111; // Sepolia (slot 1 already registered)
        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,     // already-registered slot 1
            false, // no slot rotation
            5,     // base nonce
            &unknown_contract,
            0u128,
            &calldata,
        );

        // Append the four zero-length trailers + selector bundle.
        let new_len =
            append_selector_only_trailers(&mut PAYLOAD_BUF, len, &[0x70, 0xa0, 0x82, 0x31])
        .expect("selector bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5b must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5b must NOT emit Type 1");
        hprintln!("[NS][e2e]   → selector bundle verified, t2_len={}", t2_len);
    }

    // Scenario 5v: companion-supplied ERC-20 metadata trailer.
    //
    // The ERC-20 DB now lives host-side (tools/companion-stub/erc20_db.bin);
    // the device ships only ERC20_DB_ROOT. This scenario plays the
    // companion: it builds the (chain_id, token) bundle via the host-stub
    // `erc20_db::build_bundle` and attaches it as the slot-1 trailer. The
    // secure world must Merkle-verify it against the pinned root and
    // render the token-aware "Send TEL" page instead of Erc20Unknown.
    // Registers a fresh slot on Base (8453) so the test is self-contained.
    hprintln!("[NS][e2e] Scenario 5v: companion-supplied ERC-20 metadata trailer");
    unsafe {
        let chain_id: u64 = 8453; // Base — present in the ERC-20 DB
        // Telcoin (TEL), 2 decimals — secure/data/erc20.json.
        let tel_addr: [u8; 20] = [
            0x09, 0xbe, 0x16, 0x92, 0xca, 0x16, 0xe0, 0x6f, 0x53, 0x6f, 0x00, 0x38, 0xff, 0x11,
            0xd1, 0xda, 0x85, 0x24, 0xad, 0xb1,
        ];
        let recipient: [u8; 20] = [0xcd; 20];
        // transfer(recipient, 12_345)
        let mut calldata = [0u8; 4 + 32 + 32];
        calldata[0..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        calldata[16..36].copy_from_slice(&recipient);
        let amount: u64 = 12_345;
        calldata[60..68].copy_from_slice(&amount.to_be_bytes());

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            5,    // fresh slot
            true, // register (Type 1 + Type 2)
            6,    // base nonce
            &tel_addr,
            0u128,
            &calldata,
        );
        len = append_erc20_only_trailer(&mut PAYLOAD_BUF, len, chain_id, &tel_addr)
            .expect("TEL must be in the host ERC-20 DB");

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5v must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(
            t1_present,
            "scenario 5v registers a fresh slot ⇒ Type 1 present"
        );
        hprintln!("[NS][e2e]   → ERC-20 bundle verified, t2_len={}", t2_len);
    }

    // Scenario 5m-nested: submit the generated two-bundle proof set through
    // the real single-sign gateway. Success requires the secure handler to
    // authenticate both leaves, derive the child interval/target/selector
    // from these signed bytes, render the nested V2 transcript, confirm, and
    // release a Type-2 signature.
    hprintln!("[NS][e2e] Scenario 5m-nested: ERC-7730 nested proof set matches + signs");
    #[cfg(feature = "e2e-test")]
    unsafe {
        const NESTED_PARENT: [u8; 20] = [0x34; 20];
        let calldata = build_nested_calldata_forward();
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            31_337,
            1,
            true,
            44,
            &NESTED_PARENT,
            0,
            &calldata,
        );
        let new_len = append_erc7730_only_trailers(
            &mut PAYLOAD_BUF,
            header_len,
            ERC7730_PROOF_SET_NESTED_CALLDATA,
        )
        .expect("nested ERC-7730 proof set fits PAYLOAD_BUF");
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..new_len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5m-nested: rooted nested calldata must render and sign"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(
            t1_present,
            "scenario 5m-nested: chain-31337 slot is registered"
        );
        hprintln!(
            "[NS][e2e]   → nested ERC-7730 dispatch accepted, t2_len={}",
            t2_len
        );
    }

    // Scenario 5m-multi-tail: authenticate one legacy bundle for a descriptor
    // with two top-level dynamic strings, prove the complete tail partition,
    // render both values, and release a Type-2 signature.
    hprintln!("[NS][e2e] Scenario 5m-multi-tail: ERC-7730 two-string tails match + signs");
    #[cfg(feature = "e2e-test")]
    unsafe {
        const MULTI_TAIL_CONTRACT: [u8; 20] = [0x78; 20];
        let calldata = build_multi_tail_two_strings();
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            31_337,
            1,
            false,
            45,
            &MULTI_TAIL_CONTRACT,
            0,
            &calldata,
        );
        let new_len =
            append_erc7730_only_trailers(&mut PAYLOAD_BUF, header_len, ERC7730_TRAILER_MULTI_TAIL)
                .expect("multi-tail ERC-7730 trailer fits PAYLOAD_BUF");
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..new_len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5m-multi-tail: rooted two-string calldata must render and sign"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5m-multi-tail requests Type 2 only");
        hprintln!(
            "[NS][e2e]   → multi-tail ERC-7730 dispatch accepted, t2_len={}",
            t2_len
        );
    }

    // Scenario 5w: companion-supplied address-name trailer.
    //
    // The names DB also lives host-side now; the device ships only
    // NAMES_DB_ROOT. The companion stub builds the (chain_id, address)
    // bundle and attaches it as the trailing names section. The secure
    // world Merkle-verifies it and may render the human-readable name in
    // place of the raw 40-hex address. Uses a wildcard-chain entry.
    hprintln!("[NS][e2e] Scenario 5w: companion-supplied address-name trailer");
    unsafe {
        let chain_id: u64 = 8453;
        // Uniswap V3 Router — a wildcard-chain entry in names.json.
        let router: [u8; 20] = [
            0xe5, 0x92, 0x42, 0x7a, 0x0a, 0xec, 0xe9, 0x2d, 0xe3, 0xed, 0xee, 0x1f, 0x18, 0xe0,
            0x15, 0x7c, 0x05, 0x86, 0x15, 0x64,
        ];
        // Plain value transfer to the named contract (no inner calldata).
        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            6,    // fresh slot
            true, // register
            7,    // base nonce
            &router,
            // Keep the transfer nonzero while remaining exactly representable
            // by the trusted six-decimal native-value display.
            1_000_000_000_000u128,
            &[],
        );
        len = append_names_only_trailer(&mut PAYLOAD_BUF, len, chain_id, &router)
            .expect("Uniswap V3 Router must be in the host names DB");

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5w must succeed (got {})",
            status
        );
        let (t1_present, _t2_len) = parse_response(&SIG_BUF);
        assert!(
            t1_present,
            "scenario 5w registers a fresh slot ⇒ Type 1 present"
        );
        hprintln!("[NS][e2e]   → names bundle verified");
    }

    // Scenario 5c: Selector cross-check enforcement.
    //
    // Use the same `balanceOf` calldata as 5b but attach a
    // `transfer(address,uint256)` bundle (selector 0xa9059cbb). The
    // Merkle proof verifies (transfer is in the curated e2e set), but
    // the cross-check `bundle.selector == calldata[0..4]` fails
    // (`0xa9059cbb` != `0x70a08231`), so the firmware SILENTLY drops
    // the bundle. The displayed pages must NOT include a FUNCTION
    // page — the OLED log shows the standard 9-page blind-sign flow.
    // The signed tx is identical to one with no selector bundle at
    // all; the test asserts Ok and Type 2 only.
    hprintln!("[NS][e2e] Scenario 5c: cross-check rejects mismatched selector");
    unsafe {
        let query_addr: [u8; 20] = [0xab; 20];
        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&[0x70, 0xa0, 0x82, 0x31]); // balanceOf
        calldata[16..36].copy_from_slice(&query_addr);

        let unknown_contract: [u8; 20] = [0xfe; 20];
        let chain_id: u64 = 11_155_111;

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            6,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_selector_only_trailers(
            &mut PAYLOAD_BUF,
            len,
            // Mismatched selector: transfer, not balanceOf.
            &[0xa9, 0x05, 0x9c, 0xbb],
        )
        .expect("selector bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5c must still succeed (mismatched bundle is silently dropped)"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5c must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → mismatched bundle dropped, sign proceeded as blind, t2_len={}",
            t2_len
        );
    }

    // Scenario 5d: Phase 2 typed walker declines on shape mismatch ⇒
    // graceful fallback to BLIND SIGN with the FUNCTION page intact.
    //
    // Build calldata that LOOKS like a `transfer(address,uint256)`
    // call (selector 0xa9059cbb matches the bundle) but supplies only
    // 32 bytes of body — far short of the 64-byte head the type list
    // demands. The walker's static-shape check refuses, so
    // `try_render_typed_call` returns `None` and the caller falls
    // through to `render_blind_sign_pages` with the verified meta
    // still in hand.
    //
    // Outcome on the OLED: 10-page Phase-1-style flow (banner,
    // FUNCTION page, To, Value, Sel+Data, Data hash, Chain, Max fee,
    // Worst-case, Nonce). The signed tx is the same as it would be
    // for an unrecognised call — Phase 2 never produces a partial
    // typed render.
    hprintln!("[NS][e2e] Scenario 5d: typed walker declines, blind-sign fallback");
    unsafe {
        // 4 bytes of selector + only ONE 32-byte word of body — a
        // canonical-encoded `transfer(address,uint256)` would need 64.
        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        // Half-fill an address word so the bytes aren't all zero.
        calldata[16..36].copy_from_slice(&[0xcd; 20]);

        let unknown_contract: [u8; 20] = [0xfe; 20];
        let chain_id: u64 = 11_155_111;

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            7,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len =
            append_selector_only_trailers(&mut PAYLOAD_BUF, len, &[0xa9, 0x05, 0x9c, 0xbb])
        .expect("selector bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5d must succeed (typed walker declines, blind-sign fires)"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5d must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → walker declined, blind-sign fallback rendered, t2_len={}",
            t2_len
        );
    }

    // Scenario 5j: Phase 2b self-attest happy path.
    //
    // Companion-supplied (selector, text_sig) pair for a function NOT
    // in the curated DB. The firmware:
    //   1. Parses the self-attest trailer.
    //   2. Verifies `keccak256(text_sig)[..4] == bundle.selector`.
    //   3. Cross-checks `bundle.selector == calldata[..4]`.
    //   4. Parses the verified text_sig + ABI-walks the body.
    //   5. Renders the typed-args flow with a `! UNVERIFIED` banner.
    //
    // We use `transfer(uint256)` (selector 0x12514bba) — a hypothetical
    // single-arg transfer that's NOT in `secure/data/selectors-e2e.json`,
    // so this exercises the self-attest fallback path specifically.
    hprintln!("[NS][e2e] Scenario 5j: self-attest typed render");
    unsafe {
        // keccak256("transfer(uint256)")[..4] = 0x12514bba.
        let text = b"transfer(uint256)" as &[u8];
        let mut k = Keccak256::new();
        k.update(text);
        let sel_full = k.finalize();
        let mut selector = [0u8; 4];
        selector.copy_from_slice(&sel_full[0..4]);
        assert_eq!(selector, [0x12, 0x51, 0x4b, 0xba]);

        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&selector);
        // Body = u256 1000 (big-endian).
        calldata[4 + 32 - 2..4 + 32].copy_from_slice(&1000u16.to_be_bytes());

        let unknown_contract: [u8; 20] = [0xfe; 20];
        let chain_id: u64 = 11_155_111;

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            8,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_self_attest_only_trailers(&mut PAYLOAD_BUF, len, &selector, text)
        .expect("self-attest bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5j must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5j must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → self-attest typed render verified, t2_len={}",
            t2_len
        );
    }

    // Scenario 5k: self-attest with mismatched keccak.
    //
    // Companion sends a self-attest trailer where `keccak256(text_sig)`
    // does NOT start with the supplied selector. The firmware silently
    // drops the bundle (parse_self_attest_bundle returns None) — the
    // tx still signs, but the OLED falls back to BLIND SIGN with no
    // FUNCTION/GUESS page. From NS we can only assert "Ok + Type 2";
    // the OLED capture in the QEMU log shows the blind-sign view.
    hprintln!("[NS][e2e] Scenario 5k: self-attest keccak mismatch dropped");
    unsafe {
        // Use 0x12514bba (real `transfer(uint256)` selector) but
        // supply a deliberately wrong text_sig that hashes to something
        // else.
        let selector: [u8; 4] = [0x12, 0x51, 0x4b, 0xba];
        let bad_text = b"drainAll(uint256)" as &[u8]; // hashes to a different prefix

        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&selector);
        let unknown_contract: [u8; 20] = [0xfe; 20];
        let chain_id: u64 = 11_155_111;

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            9,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_self_attest_only_trailers(&mut PAYLOAD_BUF, len, &selector, bad_text)
        .expect("self-attest bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5k must still succeed (mismatched keccak silently dropped)"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5k must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → keccak mismatch dropped, blind-sign fallback, t2_len={}",
            t2_len
        );
    }

    // Scenario 5l: both selector trailers present → InvalidPointer.
    //
    // The firmware refuses any payload that carries BOTH a curated
    // bundle and a self-attest bundle for the same call. A confused
    // companion sending both would otherwise leave the user
    // wondering which banner the device chose.
    hprintln!("[NS][e2e] Scenario 5l: both selector trailers refused");
    unsafe {
        // calldata = balanceOf(0xab..ab) — selector 0x70a08231 IS in
        // the curated e2e DB. The self-attest payload duplicates the
        // same selector with a hand-built text_sig that ALSO has
        // matching keccak (i.e. both bundles are individually valid).
        let curated_sel: [u8; 4] = [0x70, 0xa0, 0x82, 0x31];
        let self_attest_text = b"balanceOf(address)" as &[u8]; // keccak matches
        let self_attest_sel = curated_sel;

        let query_addr: [u8; 20] = [0xab; 20];
        let mut calldata = [0u8; 4 + 32];
        calldata[..4].copy_from_slice(&curated_sel);
        calldata[16..36].copy_from_slice(&query_addr);

        let unknown_contract: [u8; 20] = [0xfe; 20];
        let chain_id: u64 = 11_155_111;

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            10,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_both_selector_trailers(
            &mut PAYLOAD_BUF,
            len,
            &curated_sel,
            &self_attest_sel,
            self_attest_text,
        )
        .expect("dual-bundle build failed");
        len = new_len;

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "scenario 5l must return InvalidPointer (got {})",
            status
        );
        hprintln!("[NS][e2e]   → both-selector-trailers refused as expected");
    }

    // Scenario 5e: atomic batch sign — three inner txs into one UserOp.
    //
    // Builds a 3-tx batch that calls three different recipients with
    // different values + calldata, drives the firmware's
    // `CMD_SIGN_USEROP_BATCH` handler, and asserts the response is the
    // same wire shape as a single-tx sign (Type 2 only — slot 1 is
    // already registered on Sepolia from Scenario 1).
    //
    // Validates end-to-end:
    //   * batch payload parser inside the secure world,
    //   * per-tx clear-signing render pipeline (all three inner txs
    //     pass through `pick_sign_pages` with `e2e-test`'s auto-confirm
    //     fast path),
    //   * `executeBatchWithOffchainCount(...)` calldata reconstruction,
    //   * SHA-256 sphincs digest covers the new batch calldata,
    //   * Type 2 wrapper emits ownerIndex = slot_index + 1 = 2.
    hprintln!("[NS][e2e] Scenario 5e: atomic batch sign (3 inner txs)");
    unsafe {
        let to0: [u8; 20] = [0xa0; 20];
        let to1: [u8; 20] = [0xa1; 20];
        let to2: [u8; 20] = [0xa2; 20];
        // Inner tx 0: plain ETH transfer (empty data).
        let data0: [u8; 0] = [];
        // Inner tx 1: ERC-20 `transfer(0xab.., 250e6)`.
        let mut data1 = [0u8; 4 + 32 + 32];
        data1[..4].copy_from_slice(&[0xa9, 0x05, 0x9c, 0xbb]);
        data1[16..36].copy_from_slice(&[0xab; 20]);
        data1[60..68].copy_from_slice(&250_000_000u64.to_be_bytes());
        // Inner tx 2: opaque blind-sign-style calldata.
        let data2: [u8; 9] = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0, 0x42];

        let inner = [
            E2eBatchTx {
                to: to0,
                value_wei: 100_000_000_000_000_000u128, // 0.1 ETH
                data: &data0,
            },
            E2eBatchTx {
                to: to1,
                value_wei: 0,
                data: &data1,
            },
            E2eBatchTx {
                to: to2,
                value_wei: 0,
                data: &data2,
            },
        ];

        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111, // Sepolia (slot 1 already registered in Scenario 1)
            1,          // slot_index
            false,      // no rotation; slot already on-chain
            8,          // base nonce — fresh
            &inner,
        );
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "batch sign must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "batch on registered slot must NOT emit Type 1");
        assert_eq!(t2_len, SIG_TYPE2_LEN);
        hprintln!("[NS][e2e]   → batch sign OK, t2_len={}", t2_len);
    }

    // Scenario 5e-7730: the TLV-tagged batch wire must route a kind-7
    // descriptor to the selected inner transaction, bind it to that exact
    // chain/target/selector, render it, and sign. This is deliberately separate
    // from 5m (single UserOp) and 5p (off-chain typed data).
    hprintln!("[NS][e2e] Scenario 5e-7730: batch ERC-7730 trailer matches + signs");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        const WETH_DEPOSIT_CALL: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
        let inner = [E2eBatchTx {
            to: weth_sepolia,
            value_wei: 10_000_000_000_000_000u128,
            data: &WETH_DEPOSIT_CALL,
        }];
        let base_len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            81,
            &inner,
        );
        let len = append_one_batch_trailer(
            &mut PAYLOAD_BUF,
            base_len,
            TRAILER_KIND_ERC7730,
            0,
            ERC7730_TRAILER_WETH_SEPOLIA,
        )
        .expect("batch ERC-7730 trailer fits");
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "batch ERC-7730 descriptor must verify and sign"
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present);
        assert_eq!(t2_len, SIG_TYPE2_LEN);
        hprintln!("[NS][e2e]   → batch ERC-7730 trailer accepted");
    }

    // Regression for RT-ERC20-01: raw bytes in an INVALID Safe trailer must
    // not decide whether a direct ERC-7730 member may consume authenticated
    // ERC-20 metadata. Both FlyingTulip deposits carry valid descriptor and
    // token proofs; the same invalid Safe raw MultiSend names only asset A.
    // The fixed dispatcher binds each metadata object to the signed tokenPath,
    // so both deposits render and their full token-contract pages differ.
    hprintln!("[NS][e2e] Scenario 5e-rt-erc20: invalid Safe cannot gate ERC-7730 token metadata");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let positions_manager: [u8; 20] = [
            0xbe, 0x40, 0x50, 0xa7, 0x3a, 0x7f, 0xb3, 0x84, 0xc6, 0x5e, 0x88, 0x5a, 0x15, 0xc3,
            0x34, 0x61, 0xa4, 0xb2, 0x00, 0x55,
        ];
        let asset_a: [u8; 20] = [
            0x1c, 0xdd, 0x2e, 0xab, 0x61, 0x11, 0x26, 0x97, 0x62, 0x6f, 0x7b, 0x4b, 0xb0, 0xe2,
            0x3d, 0xa4, 0xfe, 0xbf, 0x7b, 0x7c,
        ];
        let asset_b: [u8; 20] = [
            0xda, 0xc1, 0x7f, 0x95, 0x8d, 0x2e, 0xe5, 0x23, 0xa2, 0x20, 0x62, 0x06, 0x99, 0x45,
            0x97, 0xc1, 0x3d, 0x83, 0x1e, 0xc7,
        ];
        let deposit_a = build_flyingtulip_deposit(&asset_a, 100_000_000);
        let deposit_b = build_flyingtulip_deposit(&asset_b, 100_000_000);
        let inner = [
            E2eBatchTx {
                to: positions_manager,
                value_wei: 0,
                data: &deposit_a,
            },
            E2eBatchTx {
                to: positions_manager,
                value_wei: 0,
                data: &deposit_b,
            },
        ];

        let mut meta_a = [0u8; 1120];
        let meta_a_len = crate::erc20_db::build_bundle(1, &asset_a, &mut meta_a)
            .expect("asset A exists in E2E ERC-20 DB");
        let mut meta_b = [0u8; 1120];
        let meta_b_len = crate::erc20_db::build_bundle(1, &asset_b, &mut meta_b)
            .expect("asset B exists in E2E ERC-20 DB");

        let mut raw_multisend = [0u8; 256];
        let raw_len = build_one_record_multisend(&mut raw_multisend, &asset_a);
        let fake_safe = [0x55; 20];
        let safe_canonical = build_safe_canonical(
            1,
            &fake_safe,
            &MULTISEND_CALL_ONLY_ADDRESSES[0],
            &raw_multisend[..raw_len],
            1,
            1,
        );
        let mut safe_payload = [0u8; 768];
        let safe_len = build_safe_v1_payload(
            &mut safe_payload,
            &safe_canonical,
            &raw_multisend[..raw_len],
        );

        let base_len =
            build_batch_payload(&mut PAYLOAD_BUF, &wallet_sender, 1, 0, false, 83, &inner);
        let len = append_batch_trailers(
            &mut PAYLOAD_BUF,
            base_len,
            &[
                (TRAILER_KIND_ERC20, 0, &meta_a[..meta_a_len]),
                (TRAILER_KIND_SAFE_V1, 0, &safe_payload[..safe_len]),
                (TRAILER_KIND_ERC7730, 0, ERC7730_TRAILER_FLYINGTULIP_MAINNET),
                (TRAILER_KIND_ERC7730, 1, ERC7730_TRAILER_FLYINGTULIP_MAINNET),
                (TRAILER_KIND_SAFE_V1, 1, &safe_payload[..safe_len]),
                (TRAILER_KIND_ERC20, 1, &meta_b[..meta_b_len]),
            ],
        )
        .expect("RT-ERC20 regression trailers fit");
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32);
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present);
        assert_eq!(t2_len, SIG_TYPE2_LEN);
        hprintln!("[NS][e2e]   → RT-ERC20 trusted pages complete");
    }

    // Same valid proof, wrong deployment. The tuple is firmware-known, so
    // dropping the failed descriptor must hard-refuse rather than falling back
    // to a generic batch page.
    hprintln!("[NS][e2e] Scenario 5e-7730-mismatch: batch mis-bound descriptor is refused");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        const WETH_DEPOSIT_CALL: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
        let inner = [E2eBatchTx {
            to: weth_sepolia,
            value_wei: 10_000_000_000_000_000u128,
            data: &WETH_DEPOSIT_CALL,
        }];
        let base_len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            82,
            &inner,
        );
        let len = append_one_batch_trailer(
            &mut PAYLOAD_BUF,
            base_len,
            TRAILER_KIND_ERC7730,
            0,
            ERC7730_TRAILER_WETH_MAINNET,
        )
        .expect("batch mis-bound ERC-7730 trailer fits");
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "known batch call with a proof for another deployment must refuse"
        );
        hprintln!("[NS][e2e]   → batch binding mismatch refused");
    }

    // Scenario 5f: 1-tx batch — degenerate case the on-chain
    // `executeBatchWithOffchainCount` accepts. Confirms the firmware
    // path doesn't refuse `batch_count == 1`.
    hprintln!("[NS][e2e] Scenario 5f: degenerate 1-tx batch");
    unsafe {
        let to0: [u8; 20] = [0xb0; 20];
        // Keep the VALUE load-bearing even though this scenario is about
        // `batch_count == 1`: known-chain dust now uses the exact base-unit
        // fallback (`1` / `wei`) rather than rounding or refusing. This gives
        // the E2E path a real regression vector for that trusted display.
        let inner = [E2eBatchTx {
            to: to0,
            value_wei: 1,
            data: &[],
        }];
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            9,
            &inner,
        );
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "1-tx batch must succeed (got {})",
            status
        );
        let (t1_present, _t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present);
        hprintln!("[NS][e2e]   → 1-tx batch OK");
    }

    // Scenario 5g: max-size batch (MAX_BATCH_TXS inner txs).
    hprintln!("[NS][e2e] Scenario 5g: max-size batch (N=MAX_BATCH_TXS)");
    unsafe {
        let mut tos: [[u8; 20]; MAX_BATCH_TXS] = [[0u8; 20]; MAX_BATCH_TXS];
        for i in 0..MAX_BATCH_TXS {
            tos[i] = [0xc0 + i as u8; 20];
        }
        let inner_buf: [E2eBatchTx<'_>; MAX_BATCH_TXS] = core::array::from_fn(|i| E2eBatchTx {
                to: tos[i],
                value_wei: (i as u128) * 1_000_000_000_000u128,
                data: &[],
        });
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            10,
            &inner_buf,
        );
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "max-batch sign must succeed (got {})",
            status
        );
        hprintln!("[NS][e2e]   → max batch (N={}) OK", MAX_BATCH_TXS);
    }

    // Scenario 5h: empty batch (count=0) — refused.
    hprintln!("[NS][e2e] Scenario 5h: empty batch is refused");
    unsafe {
        // Write a header by hand with batch_count=0 and no inner txs.
        let chain_id: u64 = 11_155_111;
        let mut off = 0usize;
        PAYLOAD_BUF[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
        off += 8;
        PAYLOAD_BUF[off..off + 4].copy_from_slice(&0u32.to_be_bytes());
        off += 4;
        // sender
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&wallet_sender);
        off += 20;
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
        off += 20;
        // nonce + 5*gas + paymaster_hash
        for _ in 0..(32 + 5 * 32 + 32) {
            PAYLOAD_BUF[off] = 0;
            off += 1;
        }
        PAYLOAD_BUF[off] = sphincs_tz_shared::SIGN_USEROP_BATCH_WIRE_VERSION;
        off += 1;
        PAYLOAD_BUF[off] = 0; // batch_count = 0
        off += 1;
        debug_assert_eq!(off, SIGN_USEROP_BATCH_HEADER_LEN);
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..off], &mut SIG_BUF);
        // Header alone is shorter than `header + at least one tx prefix`,
        // so the firmware rejects it as too short with InvalidPointer.
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "empty batch must be refused (got {})",
            status
        );
        hprintln!("[NS][e2e]   → empty batch refused as expected");
    }

    // Scenario 5i: `batch_count` inside the legal range but inner-tx
    // bytes truncated past the declared count. Must reject.
    hprintln!("[NS][e2e] Scenario 5i: truncated inner-tx block is refused");
    unsafe {
        let chain_id: u64 = 11_155_111;
        let mut off = 0usize;
        PAYLOAD_BUF[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
        off += 8;
        PAYLOAD_BUF[off..off + 4].copy_from_slice(&1u32.to_be_bytes()); // slot 1
        off += 4;
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&wallet_sender);
        off += 20;
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
        off += 20;
        for _ in 0..(32 + 5 * 32 + 32) {
            PAYLOAD_BUF[off] = 0;
            off += 1;
        }
        PAYLOAD_BUF[off] = sphincs_tz_shared::SIGN_USEROP_BATCH_WIRE_VERSION;
        off += 1;
        PAYLOAD_BUF[off] = 1; // batch_count
        off += 1;
        debug_assert_eq!(off, SIGN_USEROP_BATCH_HEADER_LEN);
        // Write a full per-tx prefix with `data_len = 1000` and zero
        // trailing data bytes, so the parser hits the
        // `data_len > MAX_TX_LEN || cursor + data_len > total_len`
        // branch and rejects the truncated inner-tx block.
        let mut off2 = off;
        PAYLOAD_BUF[off2..off2 + 20].fill(0xaa);
        off2 += 20;
        // value
        for _ in 0..32 {
            PAYLOAD_BUF[off2] = 0;
            off2 += 1;
        }
        // data_len = 1000 (>> trailing bytes)
        PAYLOAD_BUF[off2] = 0x03;
        PAYLOAD_BUF[off2 + 1] = 0xe8;
        off2 += 2;
        // Append zero data bytes — will be way short of declared 1000.
        let total = off2;
        let status = nsc_api::sign_userop_batch(&PAYLOAD_BUF[..total], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "truncated inner-tx must be refused"
        );
        hprintln!("[NS][e2e]   → truncated inner-tx refused as expected");
    }

    // Scenario 6: brute-force protection check. Drives the secure-
    // world `CMD_TEST_PIN_LOCKOUT` handler which burns MAX_ATTEMPTS
    // wrong PINs followed by one correct PIN and verifies the MCU
    // gate rejects the correct attempt. Destructive — leaves MCU
    // Scenario 5m: ERC-7730 clear-signing trailer (Phase 3).
    //
    // Build a WETH `deposit()` call on Sepolia + attach the pre-computed
    // ERC-7730 trailer. The live renderer selects a format from the first
    // four calldata bytes, so an empty-data ETH transfer is deliberately not
    // equivalent to `deposit()` even when sent to WETH. Success proves the
    // trailer, binding, exact selector, trusted-display render, and sign path.
    hprintln!("[NS][e2e] Scenario 5m: ERC-7730 trailer matches + signs");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        // keccak256("deposit()")[..4]
        const WETH_DEPOSIT_CALL: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            42,
            &weth_sepolia,
            10_000_000_000_000_000u128, // 0.01 ETH
            &WETH_DEPOSIT_CALL,
        );
        let new_len = append_erc7730_only_trailers(
            &mut PAYLOAD_BUF,
            header_len,
            ERC7730_TRAILER_WETH_SEPOLIA,
        )
        .expect("erc7730 trailer fits PAYLOAD_BUF");
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..new_len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5m: ERC-7730 trailer must verify + sign (status {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5m: slot pre-registered, no Type 1");
        hprintln!("[NS][e2e]   → ERC-7730 trailer accepted, t2_len={}", t2_len);
    }

    // Scenario 5p: positive EIP-712 typed sign through CMD_SIGN_OFFCHAIN.
    // The build script selects a real EIP-712 leaf from the checked-in E2E
    // catalogue and emits its canonical domain separator, primary type hash,
    // and Merkle trailer as one receipt. This therefore exercises the full
    // parser → bundle → domain/deployment binding → renderer → confirmation →
    // C10 signature path, not merely an early rejection branch.
    hprintln!("[NS][e2e] Scenario 5p: EIP-712 typed sign + binding differential");
    #[cfg(feature = "e2e-test")]
    {
        const OFFCHAIN_KIND_EIP712_TYPED: u8 = 2;
        let fixture = ERC7730_EIP712_DELEGATION_SEPOLIA;
        assert!(fixture.len() > 64, "typed fixture must carry a trailer");
        let domain_separator = &fixture[..32];
        let primary_type_hash = &fixture[32..64];
        let trailer = &fixture[64..];

        // SIGN_OFFCHAIN header: account(1), chain(8), slot(4), kind(1),
        // payload_len(2), flags(1), payload(N). Slot 1 was registered on
        // Sepolia in Scenario 1, so an unregistered-slot result is never an
        // acceptable substitute for reaching the typed renderer.
        let mut offchain_input = [0u8; 2048];
        offchain_input[0] = 0; // account 0
        offchain_input[1..9].copy_from_slice(&11_155_111u64.to_be_bytes());
        offchain_input[9..13].copy_from_slice(&1u32.to_be_bytes());
        offchain_input[13] = OFFCHAIN_KIND_EIP712_TYPED;
        offchain_input[16] = 1; // ACCOUNT_DEPLOYED

        // Payload: ds_present || ds || primary_type_hash || encoded_data_len
        // || ABI encodeData(Delegation) || trailer_len || trailer.
        let payload_start = 17;
        let mut p = payload_start;
        offchain_input[p..p + 2].copy_from_slice(&1u16.to_be_bytes());
        p += 2;
        offchain_input[p..p + 32].copy_from_slice(domain_separator);
        p += 32;
        offchain_input[p..p + 32].copy_from_slice(primary_type_hash);
        p += 32;
        offchain_input[p..p + 2].copy_from_slice(&96u16.to_be_bytes());
        p += 2;
        let delegatee = [0x42u8; 20];
        offchain_input[p + 12..p + 32].copy_from_slice(&delegatee);
        offchain_input[p + 56..p + 64].copy_from_slice(&7u64.to_be_bytes());
        offchain_input[p + 88..p + 96].copy_from_slice(&2_000_000_000u64.to_be_bytes());
        p += 96;
        offchain_input[p..p + 2].copy_from_slice(&(trailer.len() as u16).to_be_bytes());
        p += 2;
        offchain_input[p..p + trailer.len()].copy_from_slice(trailer);
        p += trailer.len();
        let payload_len = p - payload_start;
        offchain_input[14..16].copy_from_slice(&(payload_len as u16).to_be_bytes());

        let mut offchain_out = [0u8; 4016];
        let status = nsc_api::sign_offchain(&offchain_input[..p], &mut offchain_out);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5p: valid typed descriptor must render and sign"
        );
        let new_count = u64::from_be_bytes(offchain_out[..8].try_into().unwrap());
        assert_eq!(new_count, 1, "first off-chain signature must advance to 1");

        // One-bit domain differential. Everything else—including a valid
        // Merkle proof and registered slot—remains identical, so only the
        // secure-world domain/deployment binding can explain the refusal.
        offchain_input[payload_start + 2] ^= 0x01;
        let bad_status = nsc_api::sign_offchain(&offchain_input[..p], &mut offchain_out);
        assert_eq!(
            bad_status,
            NscStatus::InvalidPointer as u32,
            "scenario 5p: one-bit domain mismatch must fail binding"
        );
        hprintln!("[NS][e2e]   → typed render signed; one-bit domain mismatch refused");
    }

    // Scenario 5p-personal: `personal_sign` through CMD_SIGN_OFFCHAIN (the
    // message text on the trusted display; port step 3 pixel twin).
    hprintln!("[NS][e2e] Scenario 5p-personal: personal_sign off-chain signature");
    {
        const OFFCHAIN_KIND_PERSONAL_SIGN: u8 = 1;
        let msg = b"Login to app.example.com? Nonce: 8f3a9c2e1b";
        let mut offchain_input = [0u8; 17 + 64];
        offchain_input[0] = 0;
        offchain_input[1..9].copy_from_slice(&11_155_111u64.to_be_bytes());
        offchain_input[9..13].copy_from_slice(&1u32.to_be_bytes());
        offchain_input[13] = OFFCHAIN_KIND_PERSONAL_SIGN;
        offchain_input[14..16].copy_from_slice(&(msg.len() as u16).to_be_bytes());
        offchain_input[16] = 1; // ACCOUNT_DEPLOYED
        offchain_input[17..17 + msg.len()].copy_from_slice(msg);
        let mut offchain_out = [0u8; 4016];
        let status = nsc_api::sign_offchain(&offchain_input[..17 + msg.len()], &mut offchain_out);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 5p-personal must sign (got {})", status);
        hprintln!("[NS][e2e]   → personal_sign signed");
    }

    // Scenario 5p-raw32: the loudly-labelled blind RAW32 tier.
    hprintln!("[NS][e2e] Scenario 5p-raw32: RAW32 off-chain signature");
    {
        const OFFCHAIN_KIND_RAW32: u8 = 0;
        let mut offchain_input = [0u8; 17 + 32];
        offchain_input[0] = 0;
        offchain_input[1..9].copy_from_slice(&11_155_111u64.to_be_bytes());
        offchain_input[9..13].copy_from_slice(&1u32.to_be_bytes());
        offchain_input[13] = OFFCHAIN_KIND_RAW32;
        offchain_input[14..16].copy_from_slice(&32u16.to_be_bytes());
        offchain_input[16] = 1; // ACCOUNT_DEPLOYED
        offchain_input[17..].copy_from_slice(&[0x7d; 32]);
        let mut offchain_out = [0u8; 4016];
        let status = nsc_api::sign_offchain(&offchain_input, &mut offchain_out);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 5p-raw32 must sign (got {})", status);
        hprintln!("[NS][e2e]   → RAW32 signed");
    }

    // Scenario 5n: a cryptographically-valid trailer for the wrong deployment
    // must not restore blind signing for a firmware-known call. The UserOp is
    // WETH Sepolia deposit(), while the attached proof is WETH mainnet. Bundle
    // verification succeeds, deployment binding fails, and the pinned
    // known-call filter makes rendering mandatory → hard refusal.
    hprintln!("[NS][e2e] Scenario 5n: known-call mis-bound descriptor is refused");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        const WETH_DEPOSIT_CALL: [u8; 4] = [0xd0, 0xe3, 0x0d, 0xb0];
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            11_155_111,
            1,
            false,
            43,
            &weth_sepolia,
            10_000_000_000_000_000u128,
            &WETH_DEPOSIT_CALL,
        );
        let new_len = append_erc7730_only_trailers(
            &mut PAYLOAD_BUF,
            header_len,
            ERC7730_TRAILER_WETH_MAINNET,
        )
        .expect("erc7730 trailer fits PAYLOAD_BUF");
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..new_len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "scenario 5n: known WETH deposit with a mainnet proof must refuse"
        );
        hprintln!("[NS][e2e]   → known-call binding mismatch refused");
    }

    // Scenario 5q: Safe-wrapped CoW presign clear-sign.
    //
    // The SafeTx's inner call is `GPv2Settlement.setPreSignature(uid,
    // true)` with `uid.owner = the Safe` (GPv2 requires owner ==
    // msg.sender, and the Safe is the caller at execution). The
    // companion attaches BOTH a `safe_v1` trailer (SafeTx canonical +
    // presign raw_data) and a native kind-3 trailer (bare 204-byte
    // GPv2Order canonical). The
    // secure world must: verify the safe trailer, resolve the CoW
    // binding to (presign raw_data, safe address), recompute the
    // orderDigest from the order canonical, byte-compare it against
    // the uid, and render the combined Safe + order pages. A
    // successful sign proves the whole Safe-wrapped pipeline.
    hprintln!("[NS][e2e] Scenario 5q: Safe-wrapped CoW presign clear-sign");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let chain_id: u64 = 11_155_111; // Sepolia (slot 1 registered in Scenario 1)

        // GPv2Order canonical: sell 1000 USDC for ≥ 0.5 WETH, zero
        // receiver (proceeds to the owner = the Safe), kind=SELL.
        let mut order = [0u8; 204];
        order[0..8].copy_from_slice(&chain_id.to_be_bytes());
        order[8..28].copy_from_slice(&[
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]); // sellToken = USDC
        order[28..48].copy_from_slice(&[
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]); // buyToken = WETH
        order[96..100].copy_from_slice(&1_000_000_000u32.to_be_bytes()); // sellAmount
        order[124..132].copy_from_slice(&0x06F0_5B59_D3B2_0000u64.to_be_bytes()); // buyAmount
        order[164..168].copy_from_slice(&0x6800_0000u32.to_be_bytes()); // validTo

        let order_digest = compute_cow_order_digest(&order);
        let presign_cd = build_presign_calldata(&order_digest, &safe_address, &order[164..168]);

        let safe_nonce: u64 = 18;
        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &GPV2_SETTLEMENT_ADDRESS,
            &presign_cd,
            safe_nonce,
            0, // Call
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,     // already-registered slot 1
            false, // no rotation
            5,     // base nonce
            &safe_address,
            0u128,
            &inner_data,
        );
        len = append_cow_canonical_and_safe_trailers(
            &mut PAYLOAD_BUF,
            len,
            &order,
            &canonical,
            &presign_cd,
        );

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5q must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5q must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → safe-wrapped CoW presign verified, t2_len={}",
            t2_len
        );
    }

    // Scenario 5q-direct: a direct CoW order (no Safe): the wallet itself
    // pre-signs `setPreSignature(uid, true)` on the settlement contract with
    // uid.owner = the wallet; the native kind-3 trailer carries the order.
    hprintln!("[NS][e2e] Scenario 5q-direct: direct CoW order clear-sign");
    unsafe {
        let chain_id: u64 = 11_155_111;
        let mut order = [0u8; 204];
        order[0..8].copy_from_slice(&chain_id.to_be_bytes());
        order[8..28].copy_from_slice(&[
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]); // sellToken = WETH
        order[28..48].copy_from_slice(&[
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ]); // buyToken = USDC
        order[92..100].copy_from_slice(&0x06F0_5B59_D3B2_0000u64.to_be_bytes()); // sellAmount 0.5e18
        order[128..132].copy_from_slice(&1_842_310_000u32.to_be_bytes()); // buyAmount
        order[164..168].copy_from_slice(&0x6800_0000u32.to_be_bytes()); // validTo
        let order_digest = compute_cow_order_digest(&order);
        let presign_cd = build_presign_calldata(&order_digest, &wallet_sender, &order[164..168]);
        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            6,
            &GPV2_SETTLEMENT_ADDRESS,
            0u128,
            &presign_cd,
        );
        // erc20 = 0, reserved = 0, kind-3 = the bare 204-byte order, safe_v1 = 0.
        PAYLOAD_BUF[len..len + 2].copy_from_slice(&0u16.to_be_bytes());
        PAYLOAD_BUF[len + 2..len + 4].copy_from_slice(&0u16.to_be_bytes());
        PAYLOAD_BUF[len + 4..len + 6].copy_from_slice(&204u16.to_be_bytes());
        PAYLOAD_BUF[len + 6..len + 210].copy_from_slice(&order);
        PAYLOAD_BUF[len + 210..len + 212].copy_from_slice(&0u16.to_be_bytes());
        len += 212;
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "scenario 5q-direct must succeed (got {})", status);
        let (t1_present, _t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5q-direct must NOT emit Type 1");
        hprintln!("[NS][e2e]   → direct CoW order verified and signed");
    }

    // Scenario 5r: Safe-wrapped CoW presign WITHOUT the cow_order trailer
    // must be REFUSED (downgrade-mitigation gate). Stripping the
    // trailer is exactly what a hostile companion would do to push the
    // user onto a blind-sign page for an order they never saw — the
    // gate refuses to sign instead, mirroring the direct-path
    // "v3 required" behaviour.
    hprintln!("[NS][e2e] Scenario 5r: safe-wrapped presign without cow_order is refused");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let chain_id: u64 = 11_155_111;

        // Same wire as 5q but with a placeholder uid (digest content is
        // irrelevant — the gate fires before any digest work) and NO
        // cow_order trailer.
        let presign_cd = build_presign_calldata(&[0xCD; 32], &safe_address, &[0x68, 0, 0, 0]);
        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &GPV2_SETTLEMENT_ADDRESS,
            &presign_cd,
            19,
            0, // Call
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            6,
            &safe_address,
            0u128,
            &inner_data,
        );
        len = append_safe_only_trailers(&mut PAYLOAD_BUF, len, &canonical, &presign_cd);

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "scenario 5r: safe-wrapped presign without cow_order must refuse \
             with InvalidPointer (got {}); Ok would mean the downgrade \
             gate is not firing for the Safe-wrapped path",
            status
        );
        hprintln!("[NS][e2e]   → refused as expected (v3 required)");
    }

    // Scenario 5s: multiSend-wrapped CoW presign clear-sign — the
    // ACTUAL Safe-web-UI wire shape. The SafeTx DELEGATECALLs the
    // canonical MultiSendCallOnly contract with `multiSend([approve(
    // vault relayer) on sellToken, setPreSignature(uid, true)])`. The
    // secure world must: open the operation gate for the allowlisted
    // target, strictly decode the packed records (op==0, exact
    // framing), bind the cow_order order to the presign RECORD's bytes
    // with uid.owner == the Safe, pass the page-budget gate, and
    // render divider + approve + order pages. A successful sign proves
    // the whole multiSend pipeline.
    hprintln!("[NS][e2e] Scenario 5s: multiSend (approve+presign) safe-wrapped CoW clear-sign");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let chain_id: u64 = 11_155_111;
        let usdc: [u8; 20] = [
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ];

        // Same 1000 USDC → ≥ 0.5 WETH order as 5q.
        let mut order = [0u8; 204];
        order[0..8].copy_from_slice(&chain_id.to_be_bytes());
        order[8..28].copy_from_slice(&usdc); // sellToken
        order[28..48].copy_from_slice(&[
            0xc0, 0x2a, 0xaa, 0x39, 0xb2, 0x23, 0xfe, 0x8d, 0x0a, 0x0e, 0x5c, 0x4f, 0x27, 0xea,
            0xd9, 0x08, 0x3c, 0x75, 0x6c, 0xc2,
        ]); // buyToken = WETH
        order[96..100].copy_from_slice(&1_000_000_000u32.to_be_bytes()); // sellAmount
        order[124..132].copy_from_slice(&0x06F0_5B59_D3B2_0000u64.to_be_bytes()); // buyAmount
        order[164..168].copy_from_slice(&0x6800_0000u32.to_be_bytes()); // validTo

        let order_digest = compute_cow_order_digest(&order);
        let presign_cd = build_presign_calldata(&order_digest, &safe_address, &order[164..168]);
        let approve_cd = build_erc20_approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1_000_000_000);

        let mut ms_buf = [0u8; 512];
        let ms_len = build_cow_multisend_calldata(&mut ms_buf, 0, &usdc, &approve_cd, &presign_cd);

        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &MULTISEND_CALL_ONLY_ADDRESSES[0], // v1.3.0 canonical
            &ms_buf[..ms_len],
            20,
            1, // DelegateCall — only legal against the allowlisted multiSend
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            7,
            &safe_address,
            0u128,
            &inner_data,
        );
        len = append_cow_canonical_and_safe_trailers(
            &mut PAYLOAD_BUF,
            len,
            &order,
            &canonical,
            &ms_buf[..ms_len],
        );

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5s must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5s must NOT emit Type 1");
        hprintln!(
            "[NS][e2e]   → multiSend approve+presign verified, t2_len={}",
            t2_len
        );
    }

    // Scenario 5t: multiSend with a DELEGATECALL record must be
    // REFUSED. The approve record's operation byte is 1 — on-chain
    // MultiSendCallOnly would revert, and the firmware's per-record
    // gate refuses on-device for the same reason (a nested
    // delegatecall is not honestly clear-signable). The refusal is the
    // dedicated msend verdict gate, not a blind-sign fallback.
    hprintln!("[NS][e2e] Scenario 5t: multiSend with a delegatecall record is refused");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let chain_id: u64 = 11_155_111;
        let usdc: [u8; 20] = [
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ];

        // Digest content is irrelevant — the record-op gate fires
        // before any CoW digest work.
        let presign_cd = build_presign_calldata(&[0xCD; 32], &safe_address, &[0x68, 0, 0, 0]);
        let approve_cd = build_erc20_approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1);

        let mut ms_buf = [0u8; 512];
        let ms_len = build_cow_multisend_calldata(
            &mut ms_buf,
            1, // approve record op = DELEGATECALL → refuse
            &usdc,
            &approve_cd,
            &presign_cd,
        );

        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &MULTISEND_CALL_ONLY_ADDRESSES[0],
            &ms_buf[..ms_len],
            21,
            1,
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            8,
            &safe_address,
            0u128,
            &inner_data,
        );
        len = append_cow_canonical_and_safe_trailers(
            &mut PAYLOAD_BUF,
            len,
            &[0u8; 204], // order content irrelevant — gate fires first
            &canonical,
            &ms_buf[..ms_len],
        );

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "scenario 5t: a multiSend record with operation=1 must refuse \
             with InvalidPointer (got {}); Ok would mean the per-record \
             op gate is not firing",
            status
        );
        hprintln!("[NS][e2e]   → refused as expected (msend rec op!=0)");
    }

    // Scenario 5u: multiSend presign WITHOUT the cow_order trailer must be
    // REFUSED — the downgrade-mitigation gate extends through the
    // multiSend wrapper. Stripping the trailer is what a hostile
    // companion would do to push the user onto blind pages for an
    // order they never saw; `resolve_cow_binding` claims the unique
    // presign record (via_safe = true) and the missing v3 refuses the
    // sign, mirroring scenario 5r's single-call behaviour.
    hprintln!("[NS][e2e] Scenario 5u: multiSend presign without cow_order is refused");
    unsafe {
        let safe_address: [u8; 20] = [
            0x5a, 0xfe, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x02,
        ];
        let chain_id: u64 = 11_155_111;
        let usdc: [u8; 20] = [
            0xa0, 0xb8, 0x69, 0x91, 0xc6, 0x21, 0x8b, 0x36, 0xc1, 0xd1, 0x9d, 0x4a, 0x2e, 0x9e,
            0xb0, 0xce, 0x36, 0x06, 0xeb, 0x48,
        ];

        let presign_cd = build_presign_calldata(&[0xCD; 32], &safe_address, &[0x68, 0, 0, 0]);
        let approve_cd = build_erc20_approve_calldata(&GPV2_VAULT_RELAYER_ADDRESS, 1);

        let mut ms_buf = [0u8; 512];
        let ms_len = build_cow_multisend_calldata(&mut ms_buf, 0, &usdc, &approve_cd, &presign_cd);

        let canonical = build_safe_canonical(
            chain_id,
            &safe_address,
            &MULTISEND_CALL_ONLY_ADDRESSES[0],
            &ms_buf[..ms_len],
            22,
            1,
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
            &wallet_sender,
            chain_id,
            1,
            false,
            9,
            &safe_address,
            0u128,
            &inner_data,
        );
        len = append_safe_only_trailers(&mut PAYLOAD_BUF, len, &canonical, &ms_buf[..ms_len]);

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::InvalidPointer as u32,
            "scenario 5u: multiSend presign without cow_order must refuse \
             with InvalidPointer (got {}); Ok would mean the downgrade \
             gate does not extend through the multiSend wrapper",
            status
        );
        hprintln!("[NS][e2e]   → refused as expected (v3 required)");
    }

        // counter at MAX and SE050 user UserID silicon-locked; next boot
    // recovers via `trigger_lockout_wipe` + fresh admin-wipe
    // re-provision.
    hprintln!("[NS][e2e] Scenario 6: brute-force protection (10 wrong PINs + 1 correct)");
    let lockout_status = nsc_api::test_pin_lockout();
    assert_eq!(
        lockout_status,
        NscStatus::Ok as u32,
        "scenario 6 must report brute-force blocked (got status {})",
        lockout_status
    );
    hprintln!("[NS][e2e]   → brute-force blocked (correct PIN rejected after exhaustion)");

    hprintln!("[NS][e2e] === All scenarios passed! ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
