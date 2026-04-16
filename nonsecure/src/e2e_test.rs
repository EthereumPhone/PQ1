// Post-cutover e2e test runner: exercises the unified JARDÍN Type 1 /
// Type 2 sign command end-to-end.
//
// Compiled only with `--features e2e-test`. The matching feature on
// the secure crate auto-provisions the wallet, marks PIN_VERIFIED
// true, and short-circuits every confirm() dialog so this runner can
// drive back-to-back signs (first → Type 1 + Type 2, second → Type 2
// only) without any human input.
#![allow(static_mut_refs)]

use crate::nsc_api;
use cortex_m_semihosting::{debug, hprintln};
use sphincs_tz_shared::{
    JARDIN_TYPE1_LEN, JARDIN_TYPE2_MARKER, MAX_JARDIN_RESPONSE_LEN, NscStatus,
    SIGN_USEROP_HEADER_LEN,
};

// === Scratch buffers =======================================================

static mut SIG_BUF: [u8; MAX_JARDIN_RESPONSE_LEN] = [0u8; MAX_JARDIN_RESPONSE_LEN];
static mut PAYLOAD_BUF: [u8; SIGN_USEROP_HEADER_LEN + 256] =
    [0u8; SIGN_USEROP_HEADER_LEN + 256];

// === Helpers ===============================================================

/// EntryPoint v0.9 canonical Sepolia address.
const ENTRY_POINT_V09: [u8; 20] = [
    0x43, 0x37, 0x09, 0x00, 0x9B, 0x83, 0x30, 0xFD, 0xa3, 0x23, 0x11, 0xDF, 0x1C, 0x2A, 0xFA, 0x40,
    0x2e, 0xD8, 0xD0, 0x09,
];

/// `keccak256("")` — used for empty paymasterAndData.
const KECCAK_EMPTY: [u8; 32] = [
    0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03, 0xc0,
    0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85, 0xa4, 0x70,
];

fn build_sign_payload(
    buf: &mut [u8],
    chain_id: u64,
    slot_index_hint: u32,
    nonce_seq: u64,
    to: &[u8; 20],
    value_wei: u128,
    inner_data: &[u8],
) -> usize {
    let sender: [u8; 20] = [0x42; 20];
    let mut nonce = [0u8; 32];
    nonce[24..32].copy_from_slice(&nonce_seq.to_be_bytes());

    // accountGasLimits = (300_000 << 128) | 50_000
    let mut agl = [0u8; 32];
    agl[0..16].copy_from_slice(&300_000u128.to_be_bytes());
    agl[16..32].copy_from_slice(&50_000u128.to_be_bytes());

    let mut pre_gas = [0u8; 32];
    pre_gas[28..32].copy_from_slice(&100_000u32.to_be_bytes());

    // gasFees = (2 gwei << 128) | 10 gwei
    let mut gf = [0u8; 32];
    gf[0..16].copy_from_slice(&2_000_000_000u128.to_be_bytes());
    gf[16..32].copy_from_slice(&10_000_000_000u128.to_be_bytes());

    let mut value = [0u8; 32];
    value[16..32].copy_from_slice(&value_wei.to_be_bytes());

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&slot_index_hint.to_be_bytes());
    off += 4;
    buf[off..off + 20].copy_from_slice(&sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&ENTRY_POINT_V09);
    off += 20;
    buf[off..off + 32].copy_from_slice(&nonce);
    off += 32;
    buf[off..off + 32].copy_from_slice(&agl);
    off += 32;
    buf[off..off + 32].copy_from_slice(&pre_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&gf);
    off += 32;
    buf[off..off + 32].copy_from_slice(&KECCAK_EMPTY);
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

/// Parse a `[type1_len|t1][type2_len|t2]` bundle and assert basic shape.
///
/// Returns `(type1_present, type2_len)`.
fn parse_response(resp: &[u8]) -> (bool, usize) {
    let t1_len = u32::from_be_bytes([resp[0], resp[1], resp[2], resp[3]]) as usize;
    assert!(t1_len == 0 || t1_len == JARDIN_TYPE1_LEN);
    if t1_len != 0 {
        assert_eq!(resp[4], 0x01, "Type 1 marker must be 0x01");
    }
    let t2_off = 4 + t1_len;
    let t2_len = u32::from_be_bytes([
        resp[t2_off],
        resp[t2_off + 1],
        resp[t2_off + 2],
        resp[t2_off + 3],
    ]) as usize;
    let t2_body = t2_off + 4;
    assert_eq!(resp[t2_body], JARDIN_TYPE2_MARKER, "Type 2 marker must be 0x02");
    (t1_len != 0, t2_len)
}

#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS][e2e] === JARDÍN unified sign runner ===");

    // Unlock (auto-short-circuited by e2e-test feature on the secure side).
    let status = nsc_api::request_unlock();
    assert_eq!(status, NscStatus::Ok as u32);
    hprintln!("[NS][e2e] unlock: OK");

    // Scenario 1: first-sign — expect Type 1 + Type 2.
    hprintln!("[NS][e2e] Scenario 1: first sign (Type 1 + Type 2)");
    let to_alice: [u8; 20] = [
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12,
    ];
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            11_155_111, // Sepolia
            0,          // slot_index hint
            1,          // base nonce
            &to_alice,
            1_000_000_000_000_000_000u128, // 1 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "first-sign must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(t1_present, "first-sign must emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    // Scenario 2: second-sign on same chain — expect Type 2 only.
    hprintln!("[NS][e2e] Scenario 2: second sign (Type 2 only)");
    unsafe {
        let len = build_sign_payload(
            &mut PAYLOAD_BUF,
            11_155_111,
            0,
            2,
            &to_alice,
            500_000_000_000_000_000u128, // 0.5 ETH
            &[],
        );
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..len], &mut SIG_BUF);
        assert_eq!(status, NscStatus::Ok as u32, "second-sign must succeed");
        let (t1_present, t2_len) = parse_response(&SIG_BUF);
        assert!(!t1_present, "second-sign must NOT emit a Type 1");
        hprintln!("[NS][e2e]   → t1_present={}, t2_len={}", t1_present, t2_len);
    }

    hprintln!("[NS][e2e] === All scenarios passed! ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}
