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


// ---------------------------------------------------------------------------
// Board selection — mirrors the secure world's rule
// ---------------------------------------------------------------------------
//
// The NS crate has a board axis only so `gtzc_test`'s denial probe can cover
// the peripherals a given board actually secures (pq1 gives the SE050 its own
// I2C4 bus; iota2 has no equivalent). But `gtzc_test.rs` reads the axis as
// `not(board-pq1) => iota2`, so an image built with NEITHER feature silently
// claims to be iota2 — and until 2026-08-31 the Makefile did not forward the
// board to NS at all, so `make e2e-hw BOARD=pq1` produced exactly that: a pq1
// secure world paired with an NS world that skipped pq1's I2C4 probe and
// reported a pass.
//
// Both-at-once is always wrong. Neither-when-it-matters is wrong only where
// the axis is actually read, so the mandatory arm is scoped to `gtzc-test`
// rather than to every `stm32u585` build — the secure side's rule is
// crate-wide because its `board` module drives every pin; here it is not.
#[cfg(all(feature = "board-iota2", feature = "board-pq1"))]
compile_error!(
    "board-iota2 and board-pq1 are mutually exclusive: pick exactly one \
     (`make <target> BOARD=iota2|pq1`)."
);

#[cfg(all(
    feature = "gtzc-test",
    not(feature = "board-iota2"),
    not(feature = "board-pq1")
))]
compile_error!(
    "a `gtzc-test` build must name its board: pass `board-iota2` or `board-pq1`. \
     Without one, gtzc_test.rs defaults to the iota2 probe list and SKIPS pq1's \
     I2C4 (the SE050's own bus) while still reporting a pass — a GTZC receipt \
     that never tested the bit it claims to cover. `make <target> BOARD=pq1` \
     forwards the board to both worlds."
);

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
// The ERC20 / Names / Selectors / ERC-7730 DB blobs live on the HOST (companion app)
// under `tools/companion-stub/`, never in the firmware image — the
// production device only holds the 32-byte Merkle roots and verifies
// companion-supplied bundles against them. These modules are the
// QEMU companion stub: the `e2e-test` driver `include_bytes!`s the
// host blob and builds bundles so it can act as a dev-only companion
// (mirrors `selectors_db` below). `gtzc-test` doesn't sign, so it's
// excluded. Production `usb` builds compile none of this in.
#[cfg(all(feature = "e2e-test", not(feature = "gtzc-test")))]
mod erc20_db;
#[cfg(all(feature = "e2e-test", not(feature = "gtzc-test")))]
mod names_db;
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

// IWDG USB-loop heartbeat counter. Bumped once per poll-loop iteration;
// its address is registered with the secure IWDG watcher at boot (see
// `secure/src/hw/iwdg.rs`). A live loop keeps this advancing; a hang
// freezes it, and after a sustained stall the secure SysTick stops
// feeding the watchdog → reset. Plain counter, not a secret — wrapping
// is fine (the watcher only checks "did it change").
#[cfg(feature = "iwdg")]
static mut USB_HEARTBEAT: u32 = 0;

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

    // Register the USB-loop heartbeat with the secure IWDG watcher. The
    // secure SysTick feeds the watchdog while this counter advances (or
    // a gateway handler is busy); if the loop hangs, the counter stops
    // and the IWDG resets the device. See `secure/src/hw/iwdg.rs`.
    #[cfg(feature = "iwdg")]
    {
        let addr = core::ptr::addr_of!(USB_HEARTBEAT) as u32;
        let rc = nsc_api::register_heartbeat(addr);
        ns_debug_log(if rc == 0 {
            "[NS] IWDG heartbeat registered"
        } else {
            "[NS] IWDG heartbeat registration REJECTED"
        });
    }

    let mut poll_counter: u32 = 0;
    loop {
        // IWDG heartbeat: bump once per poll-loop iteration so the
        // secure watcher can tell a live (even idle-polling) loop from
        // a hung one. Single store; no-op build when `iwdg` is off.
        #[cfg(feature = "iwdg")]
        unsafe {
            let p = core::ptr::addr_of_mut!(USB_HEARTBEAT);
            core::ptr::write_volatile(p, core::ptr::read_volatile(p).wrapping_add(1));
        }

        // Bound how long a partial APDU may sit half-reassembled. The
        // frame clock (OTG_DSTS.FNSOF) only advances while the host is
        // sending SOFs, so this never false-trips an idle link.
        let now_frame = usb::usb_frame_number();
        let _ = stack.transport.check_rx_timeout(now_frame);
        // Bound how long an abandoned chunked GET_RESPONSE drain may pin
        // the pending buffer (30 s inter-chunk timeout; 120 s absolute
        // total-drain deadline so a slow-drain keepalive can't pin the
        // F11 router lease — finding F2).
        unsafe { stack.commands.check_response_timeout(now_frame) };
        // Bound the total lifetime of a chained-APDU exchange (30 s) so a
        // stalled or keepalive-dripped chain can't pin the lease either
        // (work-todo X17-UC1).
        unsafe { stack.commands.check_chain_timeout(now_frame) };

        if stack.device.poll(&mut [&mut stack.transport.hid]) {
            if poll_counter == 0 {
                ns_debug_log("[NS] first poll() returned true");
            }
            poll_counter = poll_counter.saturating_add(1);
            if !stack.transport.is_tx_active() {
                if let Some((channel, apdu)) = stack.transport.try_receive(now_frame) {
                    let resp = unsafe { stack.commands.dispatch(channel, apdu) };
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
        let mut sender = [0u8; 20];
        let address_status = nsc_api::get_wallet_address(&mut sender, 0, 0);
        assert_eq!(address_status, NscStatus::Ok as u32);
        let payload_len = build_value_transfer_payload(payload, &sender);
        let status = nsc_api::sign_userop(&payload[..payload_len], sig);
        hprintln!("[NS] sign_userop: {:?}", NscStatus::from(status));
        if status == NscStatus::Ok as u32 {
            // Unified-sign response starts with the durable 8-byte off-chain
            // count, followed by the three length-prefixed blobs.
            let header = 8usize;
            let ic_len = u32::from_be_bytes([
                sig[header],
                sig[header + 1],
                sig[header + 2],
                sig[header + 3],
            ]);
            let t1_off = header + 4 + ic_len as usize;
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
fn build_value_transfer_payload(buf: &mut [u8], sender: &[u8; 20]) -> usize {
    // Sepolia chain_id, account 0, slot 0 with INCLUDE_INIT_CODE: the factory
    // atomically deploys the deterministic wallet and seeds slot 0, while the
    // Type-2 signature authorizes this first transfer.
    use sphincs_tz_shared::FLAG_INCLUDE_INIT_CODE;
    let chain_id: u64 = 11_155_111;
    let entry_point: [u8; 20] = [
        0x5F, 0xF1, 0x37, 0xD4, 0xb0, 0xFD, 0xCD, 0x49, 0xDc, 0xA3, 0x0c, 0x7C, 0xF5, 0x7E, 0x57,
        0x8a, 0x02, 0x6d, 0x27, 0x89,
    ];
    let nonce = [0u8; 32];

    fn u128_be_slot(v: u128) -> [u8; 32] {
        let mut out = [0u8; 32];
        out[16..].copy_from_slice(&v.to_be_bytes());
        out
    }

    let call_gas = u128_be_slot(50_000);
    let verification_gas = u128_be_slot(800_000);
    let pre_verification_gas = u128_be_slot(150_000);
    let max_fee = u128_be_slot(1_000_000_000);
    let max_priority_fee = u128_be_slot(100_000_000);
    const SHA256_EMPTY: [u8; 32] = [
        0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f, 0xb9,
        0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b, 0x78, 0x52,
        0xb8, 0x55,
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
    // flags: account_index=0, slot_index=0, deploy through initCode.
    buf[off..off + 4].copy_from_slice(&FLAG_INCLUDE_INIT_CODE.to_be_bytes());
    off += 4;
    buf[off..off + 20].copy_from_slice(sender);
    off += 20;
    buf[off..off + 20].copy_from_slice(&entry_point);
    off += 20;
    buf[off..off + 32].copy_from_slice(&nonce);
    off += 32;
    buf[off..off + 32].copy_from_slice(&call_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&verification_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&pre_verification_gas);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_fee);
    off += 32;
    buf[off..off + 32].copy_from_slice(&max_priority_fee);
    off += 32;
    buf[off..off + 32].copy_from_slice(&SHA256_EMPTY);
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
