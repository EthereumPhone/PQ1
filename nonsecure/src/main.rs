#![no_std]
#![no_main]
// The `e2e-test` build swaps out the interactive main() for a scripted
// runner in e2e_test.rs; `bench-key-speed` swaps it for a timing bench;
// `fwup-hw-test` swaps it for the non-destructive FW_* logic checker.
// All three repurpose the crate entry point, so the interactive imports
// and helpers end up unused — silence the resulting warnings.
#![cfg_attr(feature = "e2e-test", allow(dead_code))]
#![cfg_attr(feature = "bench-key-speed", allow(dead_code, unused_imports))]
#![cfg_attr(feature = "fwup-hw-test", allow(dead_code, unused_imports))]
#![cfg_attr(feature = "gtzc-test", allow(dead_code, unused_imports))]
#![cfg_attr(feature = "tzic-wipe-test", allow(dead_code, unused_imports))]

// Panic handler selection. The QEMU/test paths use semihosting so panics
// surface via `make e2e` / `make play`; the USB hardware build halts
// silently because semihosting without a debugger attached BKPTs and
// HardFaults.
#[cfg(not(feature = "usb"))]
use panic_semihosting as _;
#[cfg(feature = "usb")]
use panic_halt as _;
// `debug` / `hprintln` are imported by each entry point that actually
// uses them — the alternates (e2e_test, bench_key_speed, fwup_hw_test,
// usb-main) all re-import locally so the default-features build stays
// warning-clean.
#[cfg(all(
    not(feature = "e2e-test"),
    not(feature = "bench-key-speed"),
    not(feature = "fwup-hw-test"),
    not(feature = "gtzc-test"),
    not(feature = "tzic-wipe-test"),
    not(feature = "usb"),
))]
use cortex_m_semihosting::{debug, hprintln};

// Imports for the interactive QEMU demo (no USB, no test runner). The
// other entry points pull what they need locally to keep the default-
// features build (which exists only to satisfy `cargo check`) free of
// dead-code warnings.
#[cfg(all(
    not(feature = "e2e-test"),
    not(feature = "bench-key-speed"),
    not(feature = "fwup-hw-test"),
    not(feature = "gtzc-test"),
    not(feature = "tzic-wipe-test"),
    not(feature = "usb"),
))]
use sphincs_tz_shared::{NscStatus, MAX_SIGN_RESPONSE_LEN, SIGN_USEROP_HEADER_LEN};

// `gtzc-test` / `tzic-wipe-test` each own their own `#[entry]`, so
// exclude the other entry-owning modules when either is on (they
// each declare a competing `#[cortex_m_rt::entry] fn main()` which
// would fail to link).
#[cfg(all(feature = "e2e-test", not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
mod e2e_test;
#[cfg(all(feature = "bench-key-speed", not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
mod bench_key_speed;
#[cfg(all(feature = "fwup-hw-test", not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
mod fwup_hw_test;
// GTZC1 TZSC enforcement validation driver. Hardware-only.
#[cfg(feature = "gtzc-test")]
mod gtzc_test;
// GTZC1 illegal-access → wipe escalation demo. Hardware-only.
#[cfg(feature = "tzic-wipe-test")]
mod tzic_wipe_test;
// The trailer-injection DBs are consumed only by the USB-side APDU
// router (`usb::commands::maybe_inject_*`). Gating them on `usb`
// keeps the QEMU smoke build and the test entry points from baking
// in the ~MB of static rodata blobs.
#[cfg(feature = "usb")]
mod erc20_db;
#[cfg(feature = "usb")]
mod names_db;
#[cfg(feature = "usb")]
mod vk_db;
mod nsc_api;
// The selectors DB blob lives on the host; only the e2e-test build
// stubs in a companion-side bundle builder so the QEMU NS test
// driver can act as a dev-only companion.
// `selectors_db` is the e2e harness's host-side companion bundle
// builder. Pulled in by `e2e-test` but irrelevant to `gtzc-test`,
// which doesn't sign anything.
#[cfg(all(feature = "e2e-test", not(feature = "gtzc-test")))]
mod selectors_db;
#[cfg(feature = "usb")]
mod usb;

/// Scratch buffer for the unified sign command response (Type 1 + Type 2).
/// Only the no-USB interactive QEMU demo uses these — the USB router in
/// `usb::commands` owns its own buffers, and the test entry points each
/// declare their own.
#[cfg(all(
    not(feature = "e2e-test"),
    not(feature = "bench-key-speed"),
    not(feature = "fwup-hw-test"),
    not(feature = "gtzc-test"),
    not(feature = "tzic-wipe-test"),
    not(feature = "usb"),
))]
static mut SIG_BUF: [u8; MAX_SIGN_RESPONSE_LEN] = [0u8; MAX_SIGN_RESPONSE_LEN];

/// Scratch buffer for a sign payload (header + up to 256B inner calldata).
#[cfg(all(
    not(feature = "e2e-test"),
    not(feature = "bench-key-speed"),
    not(feature = "fwup-hw-test"),
    not(feature = "gtzc-test"),
    not(feature = "tzic-wipe-test"),
    not(feature = "usb"),
))]
const PAYLOAD_BUF_LEN: usize = SIGN_USEROP_HEADER_LEN + 256;
#[cfg(all(
    not(feature = "e2e-test"),
    not(feature = "bench-key-speed"),
    not(feature = "fwup-hw-test"),
    not(feature = "gtzc-test"),
    not(feature = "tzic-wipe-test"),
    not(feature = "usb"),
))]
static mut PAYLOAD_BUF: [u8; PAYLOAD_BUF_LEN] = [0u8; PAYLOAD_BUF_LEN];

// ---------------------------------------------------------------------------
// USB main loop: polls USB HID, dispatches APDUs to the NSC gateway.
// Active when the `usb` feature is enabled (hardware builds with host comms).
// ---------------------------------------------------------------------------
#[cfg(all(feature = "usb", not(feature = "e2e-test"), not(feature = "bench-key-speed"), not(feature = "fwup-hw-test"), not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
#[cortex_m_rt::entry]
fn main() -> ! {
    ns_debug_log("[NS] main() entered");

    // Dump USB-relevant register state before usb::init() hits the DWC2
    // core soft-reset. Gated on DHCSR.C_DEBUGEN so the standalone build
    // (no debugger attached) doesn't BKPT → HardFault before USB even
    // comes up — without the gate, `hprintln!` executes BKPT 0xAB and
    // the CPU halts silently because NS uses `panic_halt`.
    unsafe {
        const DHCSR: *const u32 = 0xE000_EDF0 as *const u32;
        if (core::ptr::read_volatile(DHCSR) & 1) != 0 {
            // Read via the NS alias (secure aliases HardFault from NS).
            const RCC_NS: u32 = 0x4602_0C00;
            let ccipr1 = core::ptr::read_volatile((RCC_NS + 0xE0) as *const u32);
            let cr = core::ptr::read_volatile((RCC_NS + 0x00) as *const u32);
            let ahb2enr1 = core::ptr::read_volatile((RCC_NS + 0x8C) as *const u32);
            let _ = cortex_m_semihosting::hprintln!(
                "[NS] pre-usb regs: RCC_CR=0x{:08x} CCIPR1=0x{:08x} AHB2ENR1=0x{:08x}",
                cr, ccipr1, ahb2enr1
            );
            // USB OTG FS GOTGCTL / GRSTCTL
            const USB_NS: u32 = 0x4204_0000;
            let gotgctl = core::ptr::read_volatile(USB_NS as *const u32);
            let grstctl = core::ptr::read_volatile((USB_NS + 0x10) as *const u32);
            let gccfg = core::ptr::read_volatile((USB_NS + 0x38) as *const u32);
            let _ = cortex_m_semihosting::hprintln!(
                "[NS] pre-usb OTG: GOTGCTL=0x{:08x} GRSTCTL=0x{:08x} GCCFG=0x{:08x}",
                gotgctl, grstctl, gccfg
            );
        }
    }

    ns_debug_log("[NS] calling usb::init()");
    let mut stack = unsafe { usb::init() };
    ns_debug_log("[NS] usb::init() returned — entering poll loop");

    let mut poll_counter: u32 = 0;
    loop {
        if stack.device.poll(&mut [&mut stack.transport.hid]) {
            if poll_counter == 0 {
                ns_debug_log("[NS] first poll() returned true");
            }
            poll_counter = poll_counter.saturating_add(1);
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

/// Emit a semihosting log line only if a debugger is attached (DHCSR.C_DEBUGEN=1).
/// Required because NS uses `panic_halt` and `hprintln!` without a debugger
/// BKPTs → HardFault → silent halt.
#[cfg(all(feature = "usb", not(feature = "e2e-test"), not(feature = "bench-key-speed"), not(feature = "fwup-hw-test"), not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
fn ns_debug_log(msg: &str) {
    const DHCSR: *const u32 = 0xE000_EDF0 as *const u32;
    let c_debugen = unsafe { core::ptr::read_volatile(DHCSR) } & 1;
    if c_debugen != 0 {
        let _ = cortex_m_semihosting::hprintln!("{}", msg);
    }
}

// ---------------------------------------------------------------------------
// Interactive QEMU demo (no USB). Exercises the unified sign
// command end-to-end: unlock → sign a value-transfer → print result.
// ---------------------------------------------------------------------------
#[cfg(all(not(feature = "e2e-test"), not(feature = "usb"), not(feature = "bench-key-speed"), not(feature = "fwup-hw-test"), not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
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
    // SAFETY: this interactive demo is single-threaded and the only writer
    // of PAYLOAD_BUF / SIG_BUF; we take exclusive raw refs for the duration
    // of the call and drop them before the next iteration.
    unsafe {
        let payload = &mut *core::ptr::addr_of_mut!(PAYLOAD_BUF);
        let sig = &mut *core::ptr::addr_of_mut!(SIG_BUF);
        let payload_len = build_value_transfer_payload(payload);
        let status = nsc_api::sign_userop(&payload[..payload_len], sig);
        hprintln!("[NS] sign_userop: {:?}", NscStatus::from(status));
        if status == NscStatus::Ok as u32 {
            let ic_len = u32::from_be_bytes([sig[0], sig[1], sig[2], sig[3]]);
            let t1_off = 4 + ic_len as usize;
            let t1_len = u32::from_be_bytes([
                sig[t1_off],
                sig[t1_off + 1],
                sig[t1_off + 2],
                sig[t1_off + 3],
            ]);
            let t2_off = t1_off + 4 + t1_len as usize;
            let t2_len = u32::from_be_bytes([
                sig[t2_off],
                sig[t2_off + 1],
                sig[t2_off + 2],
                sig[t2_off + 3],
            ]);
            hprintln!(
                "[NS] init_code_len: {}, type1_len: {}, type2_len: {}",
                ic_len, t1_len, t2_len
            );
        }
    }

    hprintln!("\n[NS] === Interactive demo complete ===");
    debug::exit(debug::EXIT_SUCCESS);
    loop {}
}

/// Build a unified-sign payload for a value-transfer tx.
/// Output layout matches `sphincs_tz_shared::SIGN_USEROP_HEADER_LEN`.
#[cfg(all(not(feature = "e2e-test"), not(feature = "usb"), not(feature = "bench-key-speed"), not(feature = "fwup-hw-test"), not(feature = "gtzc-test"), not(feature = "tzic-wipe-test")))]
fn build_value_transfer_payload(buf: &mut [u8]) -> usize {
    // Sepolia chain_id, slot 0 with FLAG_REGISTER_SLOT so the demo first-
    // sign emits the expected Type 1 + Type 2 bundle. (The stateless
    // firmware has no way to know on its own whether this slot has been
    // registered on-chain yet.)
    use sphincs_tz_shared::FLAG_REGISTER_SLOT;
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
    // flags: slot_index=0 | FLAG_REGISTER_SLOT
    buf[off..off + 4].copy_from_slice(&FLAG_REGISTER_SLOT.to_be_bytes());
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
