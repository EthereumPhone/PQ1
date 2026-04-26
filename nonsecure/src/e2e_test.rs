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
    APPROVE_HASH_CALLDATA_LEN, APPROVE_HASH_SELECTOR, FLAG_REGISTER_SLOT, MAX_SIGN_RESPONSE_LEN,
    NscStatus, SAFE_DOMAIN_TYPEHASH, SAFE_OFF_CHAIN_ID, SAFE_OFF_DATA_HASH, SAFE_OFF_NONCE,
    SAFE_OFF_OPERATION, SAFE_OFF_SAFE_ADDRESS, SAFE_OFF_TO, SAFE_TX_TYPEHASH,
    SAFE_V1_CANONICAL_LEN, SIGN_USEROP_HEADER_LEN, SIG_TYPE1_LEN, SIG_TYPE2_LEN,
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
    // No names-count byte: the parser treats `cursor == total_len`
    // (no byte to read) as `count == 0`. Writing an explicit zero
    // here would leave one trailing byte the cursor doesn't advance
    // past, tripping the `"trailing bytes"` final check.
    o
}

/// Parse a `[ic_len|ic][type1_len|t1][type2_len|t2]` bundle and assert
/// basic shape.
///
/// Returns `(type1_present, type2_len)`.
fn parse_response(resp: &[u8]) -> (bool, usize) {
    let ic_len = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
    let t1_len_off = 4 + ic_len;
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

    // Scenario 6: brute-force protection check. Drives the secure-
    // world `CMD_TEST_PIN_LOCKOUT` handler which burns MAX_ATTEMPTS
    // wrong PINs followed by one correct PIN and verifies the MCU
    // gate rejects the correct attempt. Destructive — leaves MCU
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
