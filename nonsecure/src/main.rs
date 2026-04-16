#![no_std]
#![no_main]
// The `e2e-test` build swaps out the interactive main() for a scripted
// runner in e2e_test.rs.
#![cfg_attr(feature = "e2e-test", allow(dead_code))]

#[cfg(not(feature = "usb"))]
use cortex_m_semihosting::{debug, hprintln};
#[cfg(not(feature = "usb"))]
use panic_semihosting as _;
#[cfg(feature = "usb")]
use panic_halt as _;

// Interactive demo (mainly for `make play`): uses the unified JARDÍN
// Type 1 / Type 2 sign command to sign a single value-transfer tx.
#[cfg(all(not(feature = "e2e-test"), feature = "usb"))]
use cortex_m_semihosting::{debug, hprintln};
#[cfg(not(feature = "e2e-test"))]
use sphincs_tz_shared::{
    NscStatus, MAX_JARDIN_RESPONSE_LEN, SIGN_USEROP_HEADER_LEN,
};

#[cfg(feature = "e2e-test")]
mod e2e_test;
mod nsc_api;
#[cfg(feature = "usb")]
mod usb;

/// Scratch buffer for the unified sign command response (Type 1 + Type 2).
#[cfg(not(feature = "e2e-test"))]
static mut SIG_BUF: [u8; MAX_JARDIN_RESPONSE_LEN] = [0u8; MAX_JARDIN_RESPONSE_LEN];

/// Scratch buffer for a sign payload (header + up to 256B inner calldata).
#[cfg(not(feature = "e2e-test"))]
const PAYLOAD_BUF_LEN: usize = SIGN_USEROP_HEADER_LEN + 256;
#[cfg(not(feature = "e2e-test"))]
static mut PAYLOAD_BUF: [u8; PAYLOAD_BUF_LEN] = [0u8; PAYLOAD_BUF_LEN];

// ---------------------------------------------------------------------------
// USB main loop: polls USB HID, dispatches APDUs to the NSC gateway.
// Active when the `usb` feature is enabled (hardware builds with host comms).
// ---------------------------------------------------------------------------
#[cfg(all(feature = "usb", not(feature = "e2e-test")))]
#[cortex_m_rt::entry]
fn main() -> ! {
    let mut stack = unsafe { usb::init() };

    loop {
        if stack.device.poll(&mut [&mut stack.transport.hid]) {
            if !stack.transport.is_tx_active() {
                if let Some(apdu) = stack.transport.try_receive() {
                    let resp = unsafe { stack.commands.dispatch(apdu) };
                    unsafe { stack.transport.queue_response(resp.ptr, resp.len) };
                }
            }
        }
        stack.transport.poll_tx();
    }
}

// ---------------------------------------------------------------------------
// Interactive QEMU demo (no USB). Exercises the unified JARDÍN sign
// command end-to-end: unlock → sign a value-transfer → print result.
// ---------------------------------------------------------------------------
#[cfg(all(not(feature = "e2e-test"), not(feature = "usb")))]
#[cortex_m_rt::entry]
fn main() -> ! {
    hprintln!("[NS] Non-secure world started!");

    let attempts = nsc_api::get_remaining_attempts();
    hprintln!("[NS] Remaining PIN attempts: {}", attempts);

    hprintln!("[NS] Requesting unlock (PIN entry on trusted UI)...");
    let status = nsc_api::request_unlock();
    hprintln!("[NS] Unlock: {:?}", NscStatus::from(status));
    assert_eq!(status, NscStatus::Ok as u32);

    hprintln!("[NS] Signing a value-transfer (1 ETH → 0xAB..12)...");
    unsafe {
        let payload_len = build_value_transfer_payload(&mut PAYLOAD_BUF);
        let status = nsc_api::sign_userop(&PAYLOAD_BUF[..payload_len], &mut SIG_BUF);
        hprintln!("[NS] sign_userop: {:?}", NscStatus::from(status));
        if status == NscStatus::Ok as u32 {
            let t1_len = u32::from_be_bytes([SIG_BUF[0], SIG_BUF[1], SIG_BUF[2], SIG_BUF[3]]);
            let t2_off = 4 + t1_len as usize;
            let t2_len = u32::from_be_bytes([
                SIG_BUF[t2_off],
                SIG_BUF[t2_off + 1],
                SIG_BUF[t2_off + 2],
                SIG_BUF[t2_off + 3],
            ]);
            hprintln!("[NS] type1_len: {}, type2_len: {}", t1_len, t2_len);
        }
    }

    hprintln!("\n[NS] === Interactive demo complete ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

/// Build a unified-sign payload for a value-transfer tx.
/// Output layout matches `sphincs_tz_shared::SIGN_USEROP_HEADER_LEN`.
#[cfg(all(not(feature = "e2e-test"), not(feature = "usb")))]
fn build_value_transfer_payload(buf: &mut [u8]) -> usize {
    // Sepolia chain_id, slot_index hint = 0, empty inner data.
    let chain_id: u64 = 11_155_111;
    let sender: [u8; 20] = [0x42; 20];
    let entry_point: [u8; 20] = [
        0x43, 0x37, 0x09, 0x00, 0x9B, 0x83, 0x30, 0xFD, 0xa3, 0x23, 0x11, 0xDF, 0x1C, 0x2A, 0xFA,
        0x40, 0x2e, 0xD8, 0xD0, 0x09,
    ];
    let mut nonce = [0u8; 32];
    nonce[31] = 1;

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

    const KECCAK_EMPTY: [u8; 32] = [
        0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7, 0x03,
        0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04, 0x5d, 0x85,
        0xa4, 0x70,
    ];

    let to_address: [u8; 20] = [
        0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78,
        0x90, 0xab, 0xcd, 0xef, 0x12,
    ];
    let mut value = [0u8; 32];
    // 1 ETH = 10^18 wei.
    let wei = 1_000_000_000_000_000_000u128.to_be_bytes();
    value[16..32].copy_from_slice(&wei);

    let mut off = 0usize;
    buf[off..off + 8].copy_from_slice(&chain_id.to_be_bytes());
    off += 8;
    buf[off..off + 4].copy_from_slice(&0u32.to_be_bytes()); // slot_index_hint
    off += 4;
    buf[off..off + 20].copy_from_slice(&sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&entry_point);
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
    buf[off..off + 20].copy_from_slice(&to_address);
    off += 20;
    buf[off..off + 32].copy_from_slice(&value);
    off += 32;
    buf[off..off + 2].copy_from_slice(&0u16.to_be_bytes());
    off += 2;
    debug_assert_eq!(off, SIGN_USEROP_HEADER_LEN);
    off
}
