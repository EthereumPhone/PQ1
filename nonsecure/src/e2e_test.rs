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
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, FLAG_REGISTER_SLOT, MAX_BATCH_TXS,
    MAX_SIGN_RESPONSE_LEN, NscStatus, SAFE_DOMAIN_TYPEHASH, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH,
    SAFE_OFF_NONCE, SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_TX_TYPEHASH,
    SAFE_V1_CANONICAL_LEN, SIGN_USEROP_BATCH_HEADER_LEN, SIGN_USEROP_HEADER_LEN, SIG_TYPE1_LEN,
    SIG_TYPE2_LEN,
};

// === Scratch buffers =======================================================

static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN] = [0u8; MAX_SIGN_RESPONSE_LEN];
// Sized for the largest scenario: SafeTx canonical (281) + u16 raw_data_len
// (2) + raw_data (≤ 256 in this runner) + 36 B `approveHash` inner_data +
// header. We don't need the firmware's 16 KB SNAP_LEN budget because every
// e2e scenario uses small inner_data.
static mut PAYLOAD_BUF: [u8; SIGN_USEROP_HEADER_LEN + 1024] =
    [0u8; SIGN_USEROP_HEADER_LEN + 1024];

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
    chain_id: u64,
    slot_index: u32,
    register_slot: bool,
    nonce_seq: u64,
    to: &[u8; 20],
    value_wei: u128,
    inner_data: &[u8],
) -> usize {
    let sender: [u8; 20] = [0x42; 20];
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
    buf[off..off + 20].copy_from_slice(&sender);
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
/// raw_data, nonce_seq)`. All other fields default to zero (typical
/// for a relayer-less Safe approval).
fn build_safe_canonical(
    chain_id: u64,
    safe_address: &[u8; 20],
    to: &[u8; 20],
    raw_data: &[u8],
    nonce_seq: u64,
) -> [u8; SAFE_V1_CANONICAL_LEN] {
    let mut c = [0u8; SAFE_V1_CANONICAL_LEN];
    c[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8].copy_from_slice(&chain_id.to_be_bytes());
    c[SAFE_OFF_SAFE_ADDRESS..SAFE_OFF_SAFE_ADDRESS + 20].copy_from_slice(safe_address);
    c[SAFE_OFF_TO..SAFE_OFF_TO + 20].copy_from_slice(to);
    let dh = keccak256(raw_data);
    c[SAFE_OFF_DATA_HASH..SAFE_OFF_DATA_HASH + 32].copy_from_slice(&dh);
    c[SAFE_OFF_OPERATION] = 0; // Call
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
    dom_buf[32 + 24..32 + 32]
        .copy_from_slice(&canonical[SAFE_OFF_CHAIN_ID..SAFE_OFF_CHAIN_ID + 8]);
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
/// in the payload framing — ERC-20 bundle, ZK v1, ZK v3 — followed by
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
    // zk v1 absent
    buf[off + 2..off + 4].copy_from_slice(&0u16.to_be_bytes());
    // zk v3 absent
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

/// Append the four trailers that come BEFORE the selector trailer
/// (erc20=0, zkv1=0, zkv3=0, safe_v1=0) followed by a selector
/// bundle built by the host-stub `selectors_db::build_bundle` for
/// `selector`. Returns the new offset. Caller is responsible for
/// keeping `buf` large enough.
///
/// Wire shape after this function:
///   off..off+2  : erc20_len = 0
///   off+2..+4   : zk_v1_len = 0
///   off+4..+6   : zk_v3_len = 0
///   off+6..+8   : safe_v1_len = 0
///   off+8..+10  : selector_len (u16 BE)
///   off+10..    : selector bundle bytes
///
/// No trailing names section — `cursor == total_len` after the
/// selector bundle is treated as zero name bundles.
fn append_selector_only_trailers(
    buf: &mut [u8],
    off: usize,
    selector: &[u8; 4],
) -> Option<usize> {
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
fn build_self_attest_bundle(
    out: &mut [u8],
    selector: &[u8; 4],
    text_sig: &[u8],
) -> Option<usize> {
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

/// Append five zero-length trailers (erc20=0, zk_v1=0, zk_v3=0,
/// safe_v1=0, selector=0) followed by a self-attest trailer carrying
/// `(selector, text_sig)`. Returns the new offset. Caller is
/// responsible for keeping `buf` large enough.
///
/// Wire shape after this function:
///   off..off+2   : erc20_len   = 0
///   off+2..+4    : zk_v1_len   = 0
///   off+4..+6    : zk_v3_len   = 0
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

/// Append zero-length placeholders for every prior trailer slot and
/// then the supplied ERC-7730 bundle. Sign-input wire ordering is
/// `erc20 → zk_v1 → zk_v3 → safe_v1 → selector → self_attest →
/// erc7730 → names`; we want only the ERC-7730 slot populated so the
/// six prior slots get `[u16 = 0]` empties.
fn append_erc7730_only_trailers(
    buf: &mut [u8],
    off: usize,
    bundle: &[u8],
) -> Option<usize> {
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
    // erc20 / zk_v1 / zk_v3 / safe_v1 absent
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
    chain_id: u64,
    slot_index: u32,
    register_slot: bool,
    nonce_seq: u64,
    inner: &[E2eBatchTx<'_>],
) -> usize {
    assert!(inner.len() <= MAX_BATCH_TXS);
    assert!(!inner.is_empty());

    let sender: [u8; 20] = [0x42; 20];
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
    buf[off..off + 20].copy_from_slice(&sender);
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

    let to_alice: [u8; 20] = [
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12,
    ];

    // Scenario 1: rotation to slot 1 on chain A — expect Type 1 + Type 2.
    // (Post-Coinbase-port: REGISTER_SLOT requires slot_index >= 1 —
    // slot 0 is pre-registered by the factory at deploy time.)
    hprintln!("[NS][e2e] Scenario 1: register slot 1 on chain A (Type 1 + Type 2)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
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
        );
        let safe_tx_hash = compute_safe_tx_hash(&canonical);
        let inner_data = build_approve_hash_calldata(&safe_tx_hash);

        // Build the outer UserOp: `to = safe_address` (the wallet calls
        // approveHash on its parent Safe), `value = 0`,
        // `data = approveHash(safeTxHash)`.
        let mut len = build_sign_payload(
            &mut PAYLOAD_BUF,
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
        // sections (erc20=0, zkv1=0, zkv3=0, safe_v1=payload, names=0).
        len = append_safe_only_trailers(&mut PAYLOAD_BUF, len, &canonical, &raw_data);

        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(
            status,
            NscStatus::Ok as u32,
            "scenario 5 must succeed (got {})",
            status
        );
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "scenario 5 must NOT emit Type 1 (slot already registered)");
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
            chain_id,
            1,     // already-registered slot 1
            false, // no slot rotation
            5,     // base nonce
            &unknown_contract,
            0u128,
            &calldata,
        );

        // Append the four zero-length trailers + selector bundle.
        let new_len = append_selector_only_trailers(
            &mut PAYLOAD_BUF,
            len,
            &[0x70, 0xa0, 0x82, 0x31],
        )
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
        hprintln!(
            "[NS][e2e]   → selector bundle verified, t2_len={}",
            t2_len
        );
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
            chain_id,
            1,
            false,
            7,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_selector_only_trailers(
            &mut PAYLOAD_BUF,
            len,
            &[0xa9, 0x05, 0x9c, 0xbb],
        )
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
            chain_id,
            1,
            false,
            8,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_self_attest_only_trailers(
            &mut PAYLOAD_BUF,
            len,
            &selector,
            text,
        )
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
            chain_id,
            1,
            false,
            9,
            &unknown_contract,
            0u128,
            &calldata,
        );
        let new_len = append_self_attest_only_trailers(
            &mut PAYLOAD_BUF,
            len,
            &selector,
            bad_text,
        )
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

    // Scenario 5f: 1-tx batch — degenerate case the on-chain
    // `executeBatchWithOffchainCount` accepts. Confirms the firmware
    // path doesn't refuse `batch_count == 1`.
    hprintln!("[NS][e2e] Scenario 5f: degenerate 1-tx batch");
    unsafe {
        let to0: [u8; 20] = [0xb0; 20];
        let inner = [E2eBatchTx {
            to: to0,
            value_wei: 1u128,
            data: &[],
        }];
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
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
        let inner_buf: [E2eBatchTx<'_>; MAX_BATCH_TXS] = core::array::from_fn(|i| {
            E2eBatchTx {
                to: tos[i],
                value_wei: (i as u128) * 1_000_000_000_000u128,
                data: &[],
            }
        });
        let len = build_batch_payload(
            &mut PAYLOAD_BUF,
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
        hprintln!(
            "[NS][e2e]   → max batch (N={}) OK",
            MAX_BATCH_TXS
        );
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
        PAYLOAD_BUF[off..off + 20].fill(0x42);
        off += 20;
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
        off += 20;
        // nonce + 5*gas + paymaster_hash
        for _ in 0..(32 + 5 * 32 + 32) {
            PAYLOAD_BUF[off] = 0;
            off += 1;
        }
        // batch_count = 0
        PAYLOAD_BUF[off] = 0;
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
        PAYLOAD_BUF[off..off + 20].fill(0x42);
        off += 20;
        PAYLOAD_BUF[off..off + 20].copy_from_slice(&ENTRY_POINT_V06);
        off += 20;
        for _ in 0..(32 + 5 * 32 + 32) {
            PAYLOAD_BUF[off] = 0;
            off += 1;
        }
        // batch_count = 1.
        PAYLOAD_BUF[off] = 1;
        // Write a full per-tx prefix with `data_len = 1000` and zero
        // trailing data bytes, so the parser hits the
        // `data_len > MAX_TX_LEN || cursor + data_len > total_len`
        // branch and rejects the truncated inner-tx block.
        let mut off2 = SIGN_USEROP_BATCH_HEADER_LEN;
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
    // Build a value-transfer to WETH on Sepolia + attach the
    // pre-computed ERC-7730 trailer (`deposit()` descriptor). Phase 3
    // contract: secure-world parses the trailer, verifies it against
    // the e2e-feature-gated `ERC7730_DESCRIPTORS_ROOT`, cross-checks
    // the binding against `(chain_id, to_address)`, logs the match,
    // and signs as a normal value transfer (no renderer yet — Phase
    // 4 swaps the log for descriptor pages). Success = the sign
    // completes with both T1 absence (slot already registered) and a
    // valid T2.
    hprintln!("[NS][e2e] Scenario 5m: ERC-7730 trailer matches + signs");
    #[cfg(feature = "e2e-test")]
    unsafe {
        let weth_sepolia: [u8; 20] = [
            0xff, 0xf9, 0x97, 0x67, 0x82, 0xd4, 0x6c, 0xc0, 0x56, 0x30, 0xd1, 0xf6, 0xeb, 0xab,
            0x18, 0xb2, 0x32, 0x4d, 0x6b, 0x14,
        ];
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            11_155_111,
            1,
            false,
            42,
            &weth_sepolia,
            10_000_000_000_000_000u128, // 0.01 ETH
            &[],
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
        hprintln!(
            "[NS][e2e]   → ERC-7730 trailer accepted, t2_len={}",
            t2_len
        );
    }

    // Scenario 5p: EIP-712 typed sign through CMD_SIGN_OFFCHAIN with
    // the kind=2 (OFFCHAIN_KIND_EIP712_TYPED) wire format (Phase 5
    // item 4). This drives the secure-world path:
    //
    //   parse offchain header → branch on kind=2 → parse
    //   (domain_separator, primary_type_hash, encoded_data, trailer)
    //   → verify trailer bundle → cross_check_eip712(chain_id,
    //   contract, domain_separator) → render via
    //   `display::erc7730::render_erc7730_eip712_pages` → ERC-8213
    //   fingerprint page → confirm → sign.
    //
    // Phase 5 v1 doesn't ship an EIP-712 descriptor in the seed
    // corpus (corpus is all contract-context today). The WETH
    // Sepolia bundle re-used here is a contract-context descriptor;
    // the cross_check_eip712 binding gate inside the secure world
    // will reject with `InvalidPointer` because the descriptor's
    // primary-type-hash selector won't match `keccak256("EIP712Domain...")
    // [..4]` of the EIP-712 message. That's the expected reject
    // path: we're verifying the WIRE FORMAT and the dispatcher
    // reaches kind=2 successfully — full happy-path coverage waits
    // for the Phase 5 EIP-712 descriptor mirror (handoff item 2).
    //
    // The pre-computed final EIP-712 hash invariant
    // (`keccak256(0x1901 || ds || keccak256(typehash || data))`)
    // is asserted at compile time via `eip712_final_hash` from
    // `pqsigner-tx-core::erc8213` so a future descriptor that DOES
    // match can flip the assertion from "expected reject" to
    // "expected Ok + fingerprint match" with no wire-format change.
    hprintln!("[NS][e2e] Scenario 5p: EIP-712 typed sign (kind=2) wire format");
    #[cfg(feature = "e2e-test")]
    unsafe {
        // OFFCHAIN_KIND_EIP712_TYPED = 2 (proto/src/lib.rs:849).
        const OFFCHAIN_KIND_EIP712_TYPED: u8 = 2;
        // SIGN_OFFCHAIN header layout (proto/src/lib.rs:787-793):
        //   account_index(1) || chain_id(8 BE) || slot_index(4 BE) ||
        //   kind(1) || payload_len(2 BE) || flags(1) || payload(N)
        let mut offchain_input = [0u8; 1024];
        offchain_input[0] = 0; // account 0
        offchain_input[1..9].copy_from_slice(&11_155_111u64.to_be_bytes());
        offchain_input[9..13].copy_from_slice(&1u32.to_be_bytes());
        offchain_input[13] = OFFCHAIN_KIND_EIP712_TYPED;
        // flags = 1 (ACCOUNT_DEPLOYED) — slot 1 doesn't exist on
        // a never-deployed wallet, so this avoids the ERC-6492 slot-0
        // constraint while still exercising kind=2 parsing.
        offchain_input[16] = 1;

        // Payload: domain_sep_present(2) || domain_sep(32) ||
        // primary_type_hash(32) || encoded_data_len(2) ||
        // encoded_data(N) || trailer_len(2) || trailer(M).
        let payload_start = 17;
        let mut p = payload_start;
        offchain_input[p..p + 2].copy_from_slice(&1u16.to_be_bytes()); // ds present
        p += 2;
        // Domain separator — WETH-Sepolia (computed offline against
        // EIP-712 EIP712Domain{name="Wrapped Ether",version="1",chainId=11155111,
        // verifyingContract=0xfff9...6b14}). Hardcoded for build-time stability;
        // the secure-side binding gate compares this byte-for-byte against
        // `descriptor.eip712.deployments[i].domain_separator` so a stale
        // value just trips the cross_check reject path (which is what
        // Phase 5 v1 expects — see scenario rationale above).
        let weth_sepolia_ds: [u8; 32] = [
            0x11; 32 // placeholder; real DS computed by host build tool when
                    // EIP-712 descriptor lands in corpus.
        ];
        offchain_input[p..p + 32].copy_from_slice(&weth_sepolia_ds);
        p += 32;
        // Primary type hash placeholder.
        let primary_type_hash: [u8; 32] = [0x22; 32];
        offchain_input[p..p + 32].copy_from_slice(&primary_type_hash);
        p += 32;
        // encoded_data: empty.
        offchain_input[p..p + 2].copy_from_slice(&0u16.to_be_bytes());
        p += 2;
        // trailer: WETH-Sepolia ERC-7730 bundle (re-used from
        // Scenario 5m). The secure side parses + verifies it
        // against ERC7730_DESCRIPTORS_ROOT, then rejects at the
        // cross_check_eip712 binding gate because (a) the WETH
        // descriptor is contract-context, not EIP-712, and (b)
        // even if it were EIP-712, the placeholder DS above won't
        // match the descriptor's deployment record.
        let trailer = ERC7730_TRAILER_WETH_SEPOLIA;
        offchain_input[p..p + 2].copy_from_slice(&(trailer.len() as u16).to_be_bytes());
        p += 2;
        offchain_input[p..p + trailer.len()].copy_from_slice(trailer);
        p += trailer.len();
        let payload_len = p - payload_start;
        offchain_input[14..16].copy_from_slice(&(payload_len as u16).to_be_bytes());

        // 4016 B = deployed-path output length (8 B counter + 4008 B sig).
        let mut offchain_out = [0u8; 4016];
        let status = nsc_api::sign_offchain(&offchain_input[..p], &mut offchain_out);
        // Expected reject path — see scenario rationale comment above.
        // We tolerate either NscStatus::InvalidPointer (binding gate
        // refuses) or OffchainSlotUnregistered (slot 1 not yet
        // registered for the test wallet). Anything else means the
        // wire-format dispatcher silently miscounted or the parser
        // accepted malformed bytes — that's a real bug.
        const NSC_STATUS_INVALID_POINTER: u32 = 3;
        const NSC_STATUS_OFFCHAIN_SLOT_UNREGISTERED: u32 = 17;
        assert!(
            status == NSC_STATUS_INVALID_POINTER
                || status == NSC_STATUS_OFFCHAIN_SLOT_UNREGISTERED,
            "scenario 5p: kind=2 wire dispatch reached the parser but \
             returned unexpected status {} (expected InvalidPointer={} \
             or OffchainSlotUnregistered={}); silent miscount would \
             have returned Ok or a CryptoError",
            status,
            NSC_STATUS_INVALID_POINTER,
            NSC_STATUS_OFFCHAIN_SLOT_UNREGISTERED
        );
        hprintln!(
            "[NS][e2e]   → kind=2 wire dispatch reached parser, returned status={} (expected reject)",
            status
        );
    }

    // Scenario 5n: ERC-7730 trailer with mismatched contract — firmware
    // must DROP the descriptor (binding fail banner) and fall through
    // to blind-sign. Per docs/companion-erc7730-implementation-guide.md
    // §1: "If it ships a wrong / malformed / mis-bound trailer, the
    // firmware refuses the descriptor and falls back to blind-sign with
    // a brief status-line banner. Clear signing is never required."
    hprintln!("[NS][e2e] Scenario 5n: ERC-7730 binding-mismatch falls through to blind-sign");
    #[cfg(feature = "e2e-test")]
    unsafe {
        // Same trailer (WETH descriptor) but `to` points at a different
        // contract → cross_check_contract fails. The userop must still
        // sign because clear-signing is an enhancement layer, not a
        // precondition.
        let other: [u8; 20] = [0xDE; 20];
        let header_len = build_sign_payload(
            &mut PAYLOAD_BUF,
            11_155_111,
            1,
            false,
            43,
            &other,
            10_000_000_000_000_000u128,
            &[],
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
            "scenario 5n: binding mismatch must fall through to blind-sign \
             (got status {}); InvalidPointer would mean the firmware \
             aborted the userop instead of dropping the descriptor",
            status
        );
        hprintln!("[NS][e2e]   → ERC-7730 binding mismatch dropped, blind-sign proceeded");
    }

    // counter at MAX and SE050 user UserID silicon-locked; next boot
    // recovers via `trigger_lockout_wipe` + fresh admin-wipe
    // re-provision.
    hprintln!("[NS][e2e] Scenario 6: brute-force protection (10 wrong PINs + 1 correct)");
    let lockout_status = nsc_api::test_pin_lockout();
    assert_eq!(
        lockout_status, NscStatus::Ok as u32,
        "scenario 6 must report brute-force blocked (got status {})",
        lockout_status
    );
    hprintln!("[NS][e2e]   → brute-force blocked (correct PIN rejected after exhaustion)");

    hprintln!("[NS][e2e] === All scenarios passed! ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
