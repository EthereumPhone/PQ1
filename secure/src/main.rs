// In test mode (#[cfg(test)]), the test harness provides std and main.
// The ARM-specific crate attributes are disabled so pure-logic modules
// (aa, tx) can be unit-tested on the host with `cargo test --lib`.
#![cfg_attr(not(test), no_std)]
#![cfg_attr(not(test), no_main)]
#![cfg_attr(not(test), feature(cmse_nonsecure_entry))]
// The `e2e-test` build intentionally bypasses the interactive UI paths
// (wizard, pin entry confirm, interactive main()). Silence the resulting
// dead-code noise ONLY in that build so production builds still surface
// genuinely unused symbols.
#![cfg_attr(feature = "e2e-test", allow(dead_code))]

/// Conditional debug logging macro. Compiles to no-op without the `debug-log` feature
/// and in host-side test builds (where cortex-m-semihosting is unavailable),
/// ensuring no semihosting output in production builds.
///
/// When `debug-log` IS enabled, the macro checks the DHCSR.C_DEBUGEN bit at
/// runtime before issuing the semihosting BKPT. This makes `debug-log` builds
/// safe to run **without** a debugger attached — the output is silently skipped
/// instead of HardFaulting.
#[cfg(all(feature = "debug-log", not(test)))]
macro_rules! secure_log {
    ($($arg:tt)*) => {
        // On real STM32U585: check DHCSR.C_DEBUGEN before semihosting BKPT.
        // Without a debugger, BKPT would HardFault — this makes debug-log
        // builds safe to run standalone (USB-only, no probe attached).
        //
        // On QEMU: semihosting works via BKPT interception regardless of
        // DHCSR, so always emit.
        #[cfg(feature = "stm32u585")]
        {
            if $crate::ARCH.dhcsr.read() & 1 != 0 {
                cortex_m_semihosting::hprintln!($($arg)*);
            }
        }
        #[cfg(not(feature = "stm32u585"))]
        {
            cortex_m_semihosting::hprintln!($($arg)*);
        }
    };
}
#[cfg(any(not(feature = "debug-log"), test))]
macro_rules! secure_log {
    ($($arg:tt)*) => {};
}

// Pure-logic modules: no hardware dependencies, testable on the host.
mod aa;
mod tx;
// Generic CMAC-AES core (RFC 4493). Always compiled — the firmware
// pulls it in via the SAES-DHUK backend in `hw::saes_cmac`, and host
// tests exercise the same function against the NIST SP 800-38B
// AES-256 vectors. No hardware deps.
mod cmac;
// Pure-logic SE050 SCP03 primitives (AES-128 ECB/CBC, CMAC-AES-128, the
// GP `PUT KEY` APDU builder, KCV, OEF-`0xA921` factory key constants).
// Always compiled — `se050::scp03` (which is `feature="se050"` /
// `not(test)`-gated) imports from here, and the host test build runs the
// NIST FIPS 197 / SP 800-38B vectors + the GP layout assertions.
mod scp03_logic;
// ISO 7816-4 BER-TLV decoder + UPCTR PIN-counter parser. Pure
// functions, no hardware deps — always-on so the fuzz_props proptest
// harness can hammer them on host. The hardware-gated `se050::apdu`
// and `optiga::apdu` modules import these for the production path.
mod iso7816;

// Hardware-dependent modules: gated out in test builds so `cargo test`
// compiles only the pure logic on x86_64.
#[cfg(not(test))]
mod boot_ns;
mod crypto;
mod fi;
mod fih;
mod sign_rate;
#[cfg(test)]
mod fuzz_props;
// Pure-logic modules: no hardware deps. Available under `cargo test`
// so the proptest harnesses in `fuzz_props` can exercise them on the
// host.
mod db_roots;
mod erc20;
mod names;
mod selectors;
#[cfg(all(not(feature = "stm32u585"), not(test)))]
mod host_rng;
// `hw` is compiled for any non-test build so `sau` (used on both QEMU and
// STM32U585) can pull in `hw::mmio`. Each peripheral submodule inside
// `hw` retains its own feature gate, so QEMU still only sees `mmio`.
#[cfg(not(test))]
mod hw;
#[cfg(not(test))]
mod reset_cause;
/// Firmware-update state machine. Built on the STM32U585 hardware path
/// because it uses the bank-2 flash primitives in `hw::flash` that only
/// exist on real silicon. QEMU builds omit the module — the mailbox
/// transport doesn't expose the update commands either.
#[cfg(all(feature = "stm32u585", not(test)))]
mod fw_update;
#[cfg(not(test))]
mod offchain_state;
#[cfg(not(test))]
mod nsc;
#[cfg(not(test))]
mod rng;
#[cfg(not(test))]
mod rng_strong;
mod pin;
#[cfg(all(feature = "stm32u585", feature = "optiga-trust-m", not(test)))]
mod pin_diag;
#[cfg(not(test))]
mod sau;
mod secure_element;
#[cfg(all(feature = "se050", not(test)))]
mod se050;
#[cfg(all(feature = "tropic01-se", not(feature = "stm32u585"), not(test)))]
mod semihosting_spi;
#[cfg(not(test))]
mod timeout;
#[cfg(all(feature = "tropic01-se", not(test)))]
mod tropic01_se;
#[cfg(all(feature = "optiga-trust-m", not(test)))]
mod optiga;
#[cfg(all(feature = "dual-se", not(test)))]
mod dual_se;
#[cfg(not(test))]
mod measured_boot;
#[cfg(not(test))]
mod ui;
#[cfg(not(test))]
mod zk;

/// Factory provisioning state machine (`factory-provisioning`
/// feature). One-shot ceremony the factory operator flashes and
/// runs once per device — sets up dual-SE infrastructure and halts
/// on success / structured failure. See module docs.
#[cfg(feature = "factory-provisioning")]
mod factory_provisioning;

/// Masked-SHA-256 overhead bench (`bench-masked-sha` feature). Runs
/// once at boot, measures the first-order-masked gate cost vs the HASH
/// peripheral, prints the projected slowdown, halts. See module docs
/// + work-todo §18 (SHAKE-vs-SHA2 #2 measurement).
#[cfg(feature = "bench-masked-sha")]
mod bench_masked_sha;

// ── Test-only re-includes for the `secure-nsc-sign-userop` slice ──
//
// `nsc` itself is `#[cfg(not(test))]` because most of its files pull in
// hardware-only crates. The two helper files (`nsc/sig_wrapper.rs`,
// `nsc/trailer.rs`) are pure logic, so we re-include them at the crate
// root under `cfg(test)` to make them reachable from `cargo test`.
//
// `trailer.rs` calls `crate::ui::show_status(...)`; under test we
// provide a no-op stub so the file compiles without dragging in the
// real OLED stack.
#[cfg(test)]
mod ui {
    pub fn show_status(_title: &str, _sub: &str) {}

    // Mirrors the production constants in `crate::ui` so the
    // `display_under_test` scaffold can re-mount the per-renderer
    // source files under host test builds (see
    // `crate::display_under_test`).
    pub const DISPLAY_COLS: usize = 16;
    pub const DISPLAY_ROWS: usize = 4;
    pub mod confirm {
        pub type Page = [[u8; super::DISPLAY_COLS]; super::DISPLAY_ROWS];
    }

    /// Mirrors the production `crate::ui::ascii_str`. Required by the
    /// ERC-7730 formatter when mounted under `display_under_test`.
    /// Tests enforce ASCII-by-construction via `assert_all_pages_printable`,
    /// so non-UTF-8 here would surface as a panic — matching the
    /// production contract.
    pub(crate) fn ascii_str(buf: &[u8]) -> &str {
        core::str::from_utf8(buf).expect("ascii_str: non-ASCII bytes in render buffer")
    }
}

#[cfg(test)]
#[path = "ui/secret_text.rs"]
mod ui_secret_text_under_test;

#[cfg(test)]
#[path = "nsc/sig_wrapper.rs"]
mod nsc_sig_wrapper_under_test;

#[cfg(test)]
#[path = "nsc/trailer.rs"]
mod nsc_trailer_under_test;

#[cfg(test)]
#[path = "nsc/batch_trailers.rs"]
mod nsc_batch_trailers_under_test;

#[cfg(test)]
mod nsc_sign_userop_pure_tests;

#[cfg(test)]
mod nsc_batch_offchain_pure_tests;

#[cfg(test)]
mod nsc_small_cmds_pure_tests;

#[cfg(test)]
mod nsc_fw_update_pure_tests;

#[cfg(test)]
mod nsc_erc7730_unattested_pure_tests;

#[cfg(test)]
mod nsc_erc7730_binding_fi_pure_tests;

// ── Host-side test suite for the `secure-fw-update-boot` slice ──
//
// Covers `fw_update/mod.rs` (state-machine types + `verify_manifest`
// + `check_chunk`), `fw_update/staging.rs` (QW-aligned writes),
// `fw_update/verify.rs` (COMMIT-time defence in depth),
// `fw_update/vendor_pubkey.rs`, `measured_boot.rs` (OS Fingerprint),
// and `boot_ns.rs` (S→NS handover). All production files are
// `#[cfg(not(test))]` or `stm32u585`-gated, so the suite is
// dominated by `include_str!` source-text invariants plus
// pure-logic mirrors of decision trees. See
// `reports/tests/secure-fw-update-boot.md` for the inventory.
#[cfg(test)]
mod fw_update_boot_pure_tests;

// ── Host-side test suite for the `secure-main-sau` slice ──
//
// Covers `main.rs` (secure-world entry, SysTick/PendSV/DefaultHandler/
// panic_handler trampolines, ARCH MMIO bindings, reset-cause
// integration), `sau.rs` (SAU regions + GTZC1 MPCBB/TZSC config) and
// `reset_cause.rs` (RCC_CSR classification). All three are
// `#[cfg(not(test))]`-gated at the crate root because of
// hardware-only deps; the suite is dominated by `include_str!` source-
// text invariants plus a pure-logic mirror of `classify_bits`. See
// `reports/tests/secure-main-sau.md` for the inventory.
#[cfg(test)]
mod main_sau_pure_tests;

// ── Host-side test suite for the `secure-fi-pin-rng` slice ──
//
// Covers `fi.rs`, `fih.rs`, `fuzz_props.rs`, `host_rng.rs`,
// `iso7816.rs`, `pin.rs`, `pin_diag.rs`, `rng.rs`, `rng_strong.rs`,
// `sign_rate.rs`, `timeout.rs`. The slice mixes always-on host-
// compileable modules (`fi`, `fih`, `iso7816`, `pin`, `sign_rate`,
// `fuzz_props`) with `#[cfg(not(test))]`-excluded modules (`rng`,
// `rng_strong`, `host_rng`, `pin_diag`, `timeout`). The suite
// exercises the first group directly and pins the second via
// `include_str!` source-text invariants, with a local re-mount of
// `timeout.rs` so its pure logic is exercisable on host. See
// `reports/tests/secure-fi-pin-rng.md` for the inventory.
#[cfg(test)]
mod secure_fi_pin_rng_pure_tests;

// ── Test-only re-includes for the `secure-nsc-core` slice ──
//
// `nsc/ptr_validate.rs`, `nsc/ns_ptr.rs`, and `nsc/state.rs` are
// pure-logic enough to exercise on host, but they live under the
// production `nsc` module which is `#[cfg(not(test))]`. Mount them
// under a per-test scaffold module so the `super::ptr_validate::*`
// imports inside `ns_ptr.rs` continue to resolve, and so the
// `pub(super)` items in `state.rs` are reachable from the sibling
// test file `nsc_core_pure_tests.rs`.
#[cfg(test)]
pub(crate) mod nsc_core_under_test;

// ── Test-only scaffold for the `secure-crypto-glue` slice ──
//
// `crypto.rs`, `dual_se.rs`, and `offchain_state.rs` are
// `#[cfg(not(test))]` because they import hardware-only peers
// (`crate::optiga`, `crate::se050`, `crate::rng_strong`,
// `crate::sign_rate`, …) that cannot link on host. The scaffold
// re-includes `offchain_state.rs` via `#[path]` so its mock SRAM
// backend is reachable, and hosts source-text invariant pins for
// the FI hardening / KDF tags / zeroization sites in `crypto.rs` +
// `dual_se.rs`, alongside runtime tests for the four `db_roots`-
// bound bundle wrappers (`erc20`, `names`, `selectors`) and the
// `aa` re-export shim. See `reports/tests/secure-crypto-glue.md`
// for the inventory.
#[cfg(test)]
mod secure_crypto_glue_under_test;

// ── Test-only scaffold for the `secure-hw-crypto` slice ──
//
// The `hw` module is `#[cfg(not(test))]` because most of its files
// import cortex_m / MMIO and cannot link on host. This scaffold hosts
// the host-runnable source-text + reference-algorithm pinning suite
// for the slice's KDF labels, register addresses, FI guards and
// zeroization sites. See the module's docstring + the test file's
// header for what is and isn't covered.
#[cfg(test)]
mod hw_crypto_under_test;

// ── Test-only scaffold for the `secure-hw-platform` slice ──
//
// Same shape as `hw_crypto_under_test`: hosts the host-runnable
// source-text + reference-encoding pinning suite for the platform
// peripheral layer (flash geometry, RCC clock target, RNG/PKA/TAMP
// register layout, dev-only production fences). See the module's
// docstring + the pure_tests.rs header for what is and isn't covered.
#[cfg(test)]
mod hw_platform_under_test;

// ── Test-only scaffold for the `secure-hw-io` slice ──
//
// Same shape as `hw_crypto_under_test` / `hw_platform_under_test`:
// hosts the host-runnable source-text + reference-encoding pinning
// suite for the bus / I/O peripheral layer (I2C1 OLED + SE050,
// I2C2 STSAFE probe, SPI TROPIC01, USB OTG FS, USART1 RDP1 diag,
// GPIO buttons). See the module's docstring + the pure_tests.rs
// header for what is and isn't covered.
#[cfg(test)]
mod hw_io_under_test;

// ── Test-only scaffold for the `secure-tx-display` slice ──
//
// The production `tx::display` module is gated `#[cfg(not(test))]` (see
// `secure/src/tx/mod.rs`) because several of its sibling files pull in
// hardware-only code via `crate::ui`. This scaffold re-mounts the
// per-renderer source files under a parallel module tree, alongside a
// hand-supplied `Pages` container that mirrors the production
// `tx::display::Pages` byte-for-byte, so the renderers' page output can
// be unit-tested on the host. See
// `reports/tests/secure-tx-display.md` for the inventory.
#[cfg(test)]
mod display_under_test;

// ── Test-only scaffold for the `secure-optiga` slice ──
//
// The production `optiga` module is `#[cfg(not(test))]` because the
// transceive layer pulls in `cortex_m` for the delay loops and
// `crate::hw::i2c_hw` for the I²C1 MMIO addresses — neither links on
// host. This scaffold path-includes `apdu.rs` and `shield.rs` under
// stub `ifx_i2c` types so the byte-exact wire-format and crypto
// primitives can be exercised against reference vectors, alongside the
// `include_str!`-based source-text pins for the files that genuinely
// cannot be host-compiled (`ifx_i2c.rs`, `i2c.rs`, `mod.rs`). See
// `reports/tests/secure-optiga.md`.
#[cfg(test)]
mod optiga_under_test;

// ── Test-only scaffold for the `secure-se050` slice ──
//
// The production `se050` module is `#[cfg(all(feature = "se050",
// not(test)))]` because `t1oi2c.rs` calls `cortex_m::asm::nop()` (the
// `cortex-m` crate is target-gated to `cfg(target_arch = "arm")` in
// `secure/Cargo.toml` and does not link on x86_64) and `i2c.rs` binds
// `hw::i2c_hw::I2C1` MMIO addresses that don't exist on host. This
// scaffold pins the slice through `include_str!` source-text invariants
// + reference-vector cross-checks of the GP 1.0 CRC-16 and the SCP03
// wrap framing, alongside cross-checks against the always-on
// `scp03_logic` / `iso7816` modules. See `reports/tests/secure-se050.md`.
#[cfg(test)]
mod se050_under_test;

// ── Host-side test suite for the `secure-se-misc` slice ──
//
// Covers `secure/src/scp03_logic.rs`, `secure/src/cmac.rs`,
// `secure/src/secure_element.rs` (each via inline `#[cfg(test)] mod
// tests` blocks), and the firmware-only `secure/src/tropic01_se.rs` +
// `secure/src/semihosting_spi.rs` (via `include_str!` source-text
// invariant pins in this module, because both files depend on
// `cortex_m_semihosting` / `tropic01` / `x25519-dalek` and cannot
// link on host). See `reports/tests/secure-se-misc.md` for the
// inventory.
#[cfg(test)]
mod secure_se_misc_pure_tests;

// ── Test-only scaffold for the `secure-zk` slice ──
//
// The production `zk` module is `#[cfg(not(test))]` because the
// `render_clear_sign_pages` renderer pulls `crate::tx::display` (itself
// `cfg(not(test))`) and `crate::ui::*`. The pure-logic verifier files
// (`groth16.rs`, `poseidon.rs`, `vk_bundle.rs`) compile fine on host;
// this scaffold re-mounts them under a parallel module tree so the
// secure-side BLS12-381 Groth16 verifier + Poseidon hash + VK-bundle
// Merkle decoder can be exercised against the committed
// `test_vectors.rs` / `vk_data.rs` fixtures and adversarial inputs.
// See `reports/tests/secure-zk.md`.
#[cfg(test)]
mod zk_under_test;

// ── Test-only scaffold for the `secure-ui` slice ──
//
// The production `ui` module is `#[cfg(not(test))]` because every
// file in it depends on hardware-only peers (`cortex_m_semihosting`,
// `embedded_graphics`, `ssd1306`, `rtt-target`, the GPIO button
// driver, `crate::timeout`, `crate::rng_strong`, the
// `static mut DISPLAY` / `static mut INPUT` singletons). The slice
// is pinned host-side through `include_str!` source-text invariants
// plus reference-algorithm checks; see `reports/tests/secure-ui.md`.
#[cfg(test)]
mod ui_under_test;

// Everything below this point is firmware infrastructure — gated out in
// host test builds where only the pure aa/tx logic is exercised.
#[cfg(all(feature = "mock-se", not(test)))]
use secure_element::MockSecureElement;
#[cfg(not(test))]
use secure_element::WalletStore;

#[cfg(all(not(feature = "stm32u585"), not(test)))]
const NS_FLASH_BASE: u32 = 0x0020_0000; // QEMU mps2-an505: NS alias of SSRAM-0
#[cfg(all(feature = "stm32u585", not(test)))]
const NS_FLASH_BASE: u32 = 0x0810_0000; // STM32U585: flash bank 2 NS alias

// ARMv8-M architectural registers used directly from `main.rs`:
//   SysTick (SYST_*), DWT cycle counter, DEMCR, ICSR, DHCSR.
// All bound once below via `hw::mmio::{Reg32, RoReg32}` so the rest of
// the file only sees safe `.read()` / `.write()` calls.
#[cfg(not(test))]
struct ArchRegs {
    syst_csr: hw::mmio::Reg32,
    syst_rvr: hw::mmio::Reg32,
    syst_cvr: hw::mmio::Reg32,
    icsr: hw::mmio::Reg32,
    demcr: hw::mmio::Reg32,
    dwt_lar: hw::mmio::Reg32,
    dwt_ctrl: hw::mmio::Reg32,
    dwt_cyccnt: hw::mmio::Reg32,
    /// DHCSR.C_DEBUGEN — read-only from our point of view; we never write
    /// it (writes require an unlock key the firmware doesn't possess).
    dhcsr: hw::mmio::RoReg32,
}

// SAFETY: each address is a real, 4-byte-aligned ARMv8-M architectural
// register exclusively touched from the secure-world boot path / handlers
// below. Non-preemptive single-threaded secure world — nothing races.
#[cfg(not(test))]
const ARCH: ArchRegs = unsafe {
    ArchRegs {
        syst_csr: hw::mmio::Reg32::new(0xE000_E010),
        syst_rvr: hw::mmio::Reg32::new(0xE000_E014),
        syst_cvr: hw::mmio::Reg32::new(0xE000_E018),
        icsr: hw::mmio::Reg32::new(0xE000_ED04),
        demcr: hw::mmio::Reg32::new(0xE000_EDFC),
        dwt_lar: hw::mmio::Reg32::new(0xE000_1FB0),
        dwt_ctrl: hw::mmio::Reg32::new(0xE000_1000),
        dwt_cyccnt: hw::mmio::Reg32::new(0xE000_1004),
        dhcsr: hw::mmio::RoReg32::new(0xE000_EDF0),
    }
};

// Global mock SE (used when mock-se feature is active, no real SE)
#[cfg(all(feature = "mock-se", not(feature = "se050"), not(feature = "tropic01-se"), not(feature = "optiga-trust-m"), not(test)))]
static mut SE: MockSecureElement = MockSecureElement::new();

// Global TROPIC01 SE (standalone, without dual-se)
#[cfg(all(feature = "tropic01-se", not(feature = "dual-se"), not(test)))]
static mut SE: tropic01_se::Tropic01SecureElement = tropic01_se::Tropic01SecureElement::new();

// Global SE050 SE (standalone, without dual-se)
#[cfg(all(feature = "se050", not(feature = "dual-se"), not(test)))]
static mut SE: se050::Se050 = se050::Se050::new();

// Global OPTIGA Trust M SE (standalone, without dual-se)
#[cfg(all(feature = "optiga-trust-m", not(feature = "dual-se"), not(test)))]
static mut SE: optiga::OptigaTrustM = optiga::OptigaTrustM::new();

// Global dual-SE (OPTIGA Trust M + SE050 with XOR entropy split)
#[cfg(all(feature = "dual-se", not(test)))]
static mut SE: dual_se::DualSecureElement = dual_se::DualSecureElement::new();

/// Strong-RNG accessor for `hw::rng_strong::fill`. Returns
/// `Err(SeError)` when the active backend has no TRNG (`mock-se`),
/// which the caller treats as "skip the SE-side XOR layer".
///
/// SAFETY: must be called only after the SE has been initialised —
/// i.e. from a code path that runs after `init`/`unlock`. The sign
/// path (the only consumer) is gated on `pin_verified`, which only
/// becomes true after a successful unlock that has touched the SE.
#[cfg(not(test))]
pub unsafe fn se_random(
    buf: &mut [u8],
) -> Result<(), crate::secure_element::SeError> {
    use crate::secure_element::WalletStore;
    let se = &mut *core::ptr::addr_of_mut!(SE);
    // Fully-qualified to dispatch through the WalletStore trait
    // (the standalone Se050/OptigaTrustM types have inherent
    // `random` methods returning their backend-specific error
    // type; the trait method returns `Result<_, SeError>`).
    <_ as WalletStore>::random(se, buf)
}

/// SAES Tier-1 bring-up self-test — runs under `saes-self-test` only.
/// Initialises the SAES peripheral, executes the in-driver self-tests
/// (software-key round-trip + DHUK vs SW domain separation + DHUK
/// round-trip), logs PASS/FAIL and a short DHUK fingerprint, then exits
/// cleanly via `SYS_EXIT` so `probe-rs run` returns. Never returns.
#[cfg(feature = "saes-self-test")]
fn saes_self_test_and_halt() -> ! {
    // Stage 6: entered self-test entry; uart::init has not run yet.
    #[cfg(feature = "boot-pulse")]
    unsafe { hw::boot_pulse::pulse(6); }
    // RDP1 boot diagnostic — bring the OLED up the moment we enter the
    // self-test so even at RDP ≥ 1 (UART silent, SWD halt denied) the
    // screen retains a visible state of how far the firmware got.
    #[cfg(feature = "ui-oled")]
    {
        ui::init();
        let d = ui::display();
        d.clear();
        d.draw_line(0, "BOOT 6 saes-st");
        d.flush();
    }
    // Bring UART up first so anything that follows (PASS/FAIL line +
    // fingerprint) reaches the ST-LINK VCP even at RDP ≥ 1, where
    // semihosting is dead. No-op when `uart-console` isn't in the
    // feature set (RDP0 runs still pass via probe-rs + semihosting).
    #[cfg(feature = "uart-console")]
    {
        hw::uart::init();
        hw::uart::write_str("[S][saes] UART up, starting self-test\r\n");
    }
    // Stage 7: uart::init returned (relevant only if uart-console is on).
    #[cfg(feature = "boot-pulse")]
    unsafe { hw::boot_pulse::pulse(7); }
    #[cfg(feature = "ui-oled")]
    {
        let d = ui::display();
        d.draw_line(1, "BOOT 7 uart up");
        d.flush();
    }

    match hw::saes::init() {
        Ok(()) => {
            secure_log!("[S][saes] init OK");
            #[cfg(feature = "ui-oled")]
            {
                let d = ui::display();
                d.draw_line(2, "saes init OK");
                d.flush();
            }
        }
        Err(e) => {
            secure_log!("[S][saes] init FAIL: {:?} — halting", e);
            #[cfg(feature = "uart-console")]
            {
                hw::uart::write_str("[S][saes] init FAIL\r\n");
                hw::uart::flush();
            }
            #[cfg(feature = "ui-oled")]
            {
                let d = ui::display();
                d.draw_line(2, "saes init FAIL");
                d.flush();
            }
            loop {
                cortex_m::asm::wfe();
            }
        }
    }
    match hw::saes::self_test() {
        Ok(()) => {
            // NOTE: do NOT overwrite line 3 here — saes::self_test()
            // already wrote the DHUK fingerprint there.
            secure_log!("[S][saes] === self_test PASS ===");
        }
        Err(e) => {
            secure_log!("[S][saes] === self_test FAIL === {:?}", e);
            #[cfg(feature = "uart-console")]
            {
                hw::uart::write_str("[S][saes] === self_test FAIL ===\r\n");
                hw::uart::flush();
            }
            #[cfg(feature = "ui-oled")]
            {
                let d = ui::display();
                d.draw_line(3, "self_test FAIL");
                d.flush();
            }
        }
    }

    // Tier-2 BHK lifecycle self-test (only when the `bhk` feature is
    // also on). Provisions the BHK if blank (writes the DHUK-wrapped
    // bytes to flash page 126 — erasable), loads it into the TAMP
    // backup registers + sets BHKLOCK, then runs a KeySel::Bhk
    // encrypt/decrypt round-trip and reports an 8-byte per-die BHK
    // fingerprint. At RDP0 the fingerprint is NOT per-die (the DHUK
    // that wrapped the BHK is the ST-substituted constant); at RDP ≥ 1
    // it would be per-die — but per-die BHK validation needs the BHK
    // provisioned WHILE at RDP1, which this RDP0-bench path does not do.
    #[cfg(feature = "bhk")]
    match hw::bhk::self_test() {
        Ok(fp) => {
            secure_log!(
                "[S][bhk] self_test PASS  BHK(fp)={:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]
            );
            #[cfg(feature = "uart-console")]
            {
                hw::uart::write_str("[S][bhk] self_test PASS  BHK(fp)=");
                hw::uart::write_hex_8(&fp);
                hw::uart::write_str("\r\n");
                hw::uart::flush();
            }
            #[cfg(feature = "ui-oled")]
            {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let mut buf = [0u8; 16];
                for (i, &b) in fp.iter().enumerate() {
                    buf[i * 2] = HEX[(b >> 4) as usize];
                    buf[i * 2 + 1] = HEX[(b & 0xF) as usize];
                }
                // SAFETY: hex chars are valid UTF-8.
                let s = unsafe { core::str::from_utf8_unchecked(&buf) };
                let d = ui::display();
                d.draw_line(0, s); // overwrite the "BOOT 6" marker — boot is done
                d.flush();
            }
        }
        Err(e) => {
            secure_log!("[S][bhk] self_test FAIL: {:?}", e);
            #[cfg(feature = "uart-console")]
            {
                hw::uart::write_str("[S][bhk] self_test FAIL: ");
                // No core::fmt over UART (would pull in fmt machinery);
                // hand-encode the BhkError variant as a short tag.
                let tag: &str = match e {
                    hw::bhk::BhkError::NotProvisioned => "NotProvisioned",
                    hw::bhk::BhkError::AlreadyProvisioned => "AlreadyProvisioned",
                    hw::bhk::BhkError::Flash => "Flash",
                    hw::bhk::BhkError::Saes(se) => match se {
                        hw::saes::SaesError::ShsiTimeout => "Saes(ShsiTimeout)",
                        hw::saes::SaesError::RngSeedError => "Saes(RngSeedError)",
                        hw::saes::SaesError::BusyTimeout => "Saes(BusyTimeout)",
                        hw::saes::SaesError::CcfTimeout => "Saes(CcfTimeout)",
                        hw::saes::SaesError::BusError => "Saes(BusError)",
                        hw::saes::SaesError::KeyInvalid => "Saes(KeyInvalid)",
                        hw::saes::SaesError::KeyConfigMismatch => "Saes(KeyConfigMismatch)",
                        hw::saes::SaesError::SelfTestRoundTrip => "Saes(SelfTestRoundTrip)",
                        hw::saes::SaesError::SelfTestDomainCollision => "Saes(SelfTestDomainCollision)",
                    },
                    hw::bhk::BhkError::Rng => "Rng",
                };
                hw::uart::write_str(tag);
                hw::uart::write_str("\r\n");
                hw::uart::flush();
            }
            #[cfg(feature = "ui-oled")]
            {
                let d = ui::display();
                d.draw_line(0, "BHK self_test FAIL");
                d.flush();
            }
        }
    }

    secure_log!("[S][saes] self-test complete — halting");
    // Under `saes-self-test` alone (with probe-rs / debugger), SYS_EXIT
    // cleanly returns so probe-rs sees the test PASS and exits.
    #[cfg(not(feature = "boot-pulse"))]
    cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
    // Under `boot-pulse`, fire a continuous pulse(8) "tail" pattern so
    // the LA1010 trace can distinguish "firmware reached end of boot"
    // (continuous 8-pulse groups forever) from "firmware hung at stage
    // K" (one-shot 1..K train then silence).
    #[cfg(feature = "boot-pulse")]
    loop {
        unsafe { hw::boot_pulse::pulse(8); }
    }
    #[cfg(not(feature = "boot-pulse"))]
    loop {
        cortex_m::asm::wfe();
    }
}

/// SysTick reload value for ~1 ms tick.
/// QEMU mps2-an505: 25 MHz → 25_000.  STM32U585: set dynamically from rcc::init().
#[cfg(all(not(feature = "stm32u585"), not(test)))]
const SYSTICK_RELOAD: u32 = 25_000;
#[cfg(all(feature = "stm32u585", not(test)))]
static mut SYSTICK_RELOAD: u32 = 16_000; // overwritten by rcc::init() result

#[cfg(not(test))]
fn setup_systick() {
    // SAFETY: `SYSTICK_RELOAD` is a `static mut` on `stm32u585` (written
    // once at boot from `rcc::init()` before SysTick is enabled). The
    // `const` non-stm32u585 path doesn't need unsafe — `read` is wrapping
    // an immutable global.
    #[cfg(feature = "stm32u585")]
    // SAFETY: single-writer at boot before this read; no races.
    let reload = unsafe { SYSTICK_RELOAD };
    #[cfg(not(feature = "stm32u585"))]
    let reload = SYSTICK_RELOAD;
    ARCH.syst_rvr.write(reload);
    ARCH.syst_cvr.write(0);
    ARCH.syst_csr.write(0x07);
}

/// Returns true if the SE backend has been provisioned.
/// Each backend (Mock, SE050, Tropic01) checks via its WalletStore impl.
#[cfg(not(test))]
fn is_provisioned(se: &mut impl WalletStore) -> bool {
    se.is_provisioned()
}

/// Run the first-boot interactive wizard. Loops until the user successfully:
/// 1. Picks (and confirms) a PIN
/// 2. Either generates a fresh BIP-39 mnemonic or restores one
/// 3. (For new wallets) writes down the displayed phrase and passes the
///    3-word spot check
///
/// Returns `(Mnemonic, pin)` to the caller, which is responsible for
/// provisioning the secure element. The mnemonic only ever lives on the
/// stack and is zeroed on drop. The caller must wipe the returned PIN.
///
/// On any cancel/idle-wipe/mismatch the wizard restarts from PIN entry —
/// there is no other recovery from a bricked first boot.
#[cfg(not(test))]
fn run_first_boot_wizard() -> (sphincs_tz_bip39::Mnemonic, [u8; 8]) {
    use ui::pin_entry::{enter_pin_with_confirm, PinEntryResult};
    use ui::seed_wizard::{
        choose_setup_mode, enter_mnemonic, show_mnemonic, verify_mnemonic, WizardChoice,
        WizardError, WizardResult,
    };
    use zeroize::Zeroize;

    loop {
        // ---- 1. Choose PIN (twice) ----
        secure_log!("[S] wizard: enter_pin_with_confirm");
        let pin = match enter_pin_with_confirm() {
            PinEntryResult::Pin(p) => {
                secure_log!("[S] wizard: PIN confirmed");
                p
            }
            PinEntryResult::Mismatch => {
                secure_log!("[S] wizard: PIN mismatch — retry");
                ui::show_status("PINs differ", "retry...");
                continue;
            }
            PinEntryResult::Cancelled => {
                secure_log!("[S] wizard: PIN entry cancelled — retry");
                ui::show_status("Cancelled", "retry...");
                continue;
            }
            PinEntryResult::IdleWipe => {
                secure_log!("[S] wizard: PIN entry idle wipe — retry");
                ui::show_status("Idle", "retry...");
                continue;
            }
        };

        // ---- 2. New or restore? ----
        secure_log!("[S] wizard: choose_setup_mode");
        let mnemonic = match choose_setup_mode() {
            WizardChoice::NewWallet => {
                secure_log!("[S] wizard: NewWallet — generating entropy");
                // Pull 32 bytes of entropy via the multi-source strong
                // RNG (STM32 hardware TRNG ⊕ OPTIGA GetRandom ⊕ SE050
                // GetRandom — Trezor-parity 3-source XOR). The wallet
                // master seed is the single most critical RNG output
                // in the firmware: if it's predictable, every key
                // derived from it (bootstrap, all slots, all chains)
                // is forgeable. rng_strong preserves entropy from any
                // unbroken source — defends against any single biased
                // / compromised TRNG (the STM32U5 silicon TRNG glitch
                // class, an OPTIGA chip-RNG fault, etc.).
                let mut entropy = [0u8; 32];
                if rng_strong::fill(&mut entropy).is_err() {
                    secure_log!("[S] wizard: rng_strong::fill FAILED");
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("RNG failed", "retry...");
                    continue;
                }
                secure_log!("[S] wizard: entropy ok, showing mnemonic");
                let m = sphincs_tz_bip39::Mnemonic::from_entropy(&entropy);
                entropy.zeroize();
                crate::fi::zeroize_barrier();

                // Show the 24 words paginated; require the user to walk to
                // the last page before they can confirm.
                let sm = show_mnemonic(&m);
                if sm != WizardResult::Confirmed {
                    secure_log!("[S] wizard: show_mnemonic returned {:?} — retry", sm);
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Cancelled", "retry...");
                    continue;
                }
                // Spot-check 3 random words against what they wrote down.
                let vm = verify_mnemonic(&m);
                if vm != WizardResult::Confirmed {
                    secure_log!("[S] wizard: verify_mnemonic returned {:?} — retry", vm);
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Verify fail", "retry...");
                    continue;
                }
                m
            }
            WizardChoice::Restore => {
                secure_log!("[S] wizard: Restore — entering mnemonic");
                match enter_mnemonic() {
                    Ok(m) => m,
                    Err(WizardError::Cancelled) => {
                        secure_log!("[S] wizard: enter_mnemonic cancelled — retry");
                        let mut p = pin;
                        p.zeroize();
                        ui::show_status("Cancelled", "retry...");
                        continue;
                    }
                    Err(WizardError::IdleWipe) => {
                        secure_log!("[S] wizard: enter_mnemonic idle wipe — retry");
                        let mut p = pin;
                        p.zeroize();
                        ui::show_status("Idle", "retry...");
                        continue;
                    }
                }
            }
            WizardChoice::Cancelled | WizardChoice::IdleWipe => {
                secure_log!("[S] wizard: choose_setup_mode cancelled/idle — retry");
                let mut p = pin;
                p.zeroize();
                ui::show_status("Cancelled", "retry...");
                continue;
            }
        };

        return (mnemonic, pin);
    }
}

#[cfg(not(test))]
#[cortex_m_rt::entry]
fn main() -> ! {
    // RDP1 boot bisection: pulse PE13 (Arduino D13) before any other
    // init so we see at least one pulse if the CPU made it into `main`
    // at all. Stage encoding documented in `hw::boot_pulse`.
    #[cfg(feature = "boot-pulse")]
    unsafe { hw::boot_pulse::init(); hw::boot_pulse::pulse(1); }

    // Classify the reset cause FIRST — before any peripheral init,
    // before any RCC_CSR modification. The sticky flags tell us why the
    // chip just came up. Abnormal causes (watchdog / low-power /
    // unknown) trigger defensive SRAM zeroization below, on the theory
    // that whatever was in SRAM belongs to an aborted operation that
    // never ran its normal cleanup path.
    let (reset_cause, reset_csr_raw) = unsafe { reset_cause::classify_and_clear() };

    // STM32U585: configure clocks BEFORE any semihosting output.
    // Semihosting BKPT halts the CPU when no debugger is attached, so
    // clock/RNG init must happen first to allow standalone boot testing.
    #[cfg(feature = "stm32u585")]
    unsafe {
        let mhz = hw::rcc::init();
        SYSTICK_RELOAD = mhz * 1_000;
        #[cfg(feature = "boot-pulse")]
        hw::boot_pulse::pulse(2);
        // RNG init is deferred until AFTER sau::init() / GTZC config —
        // accessing RNG_S (0x520C_0800) before the TZSC has assigned the
        // peripheral's security attribute can stall the AHB2 fabric on
        // STM32U5.
        #[cfg(feature = "hw-sha256")]
        hw::hash::init_clock();
        #[cfg(feature = "boot-pulse")]
        hw::boot_pulse::pulse(3);
        // When SE050 is also active, its i2c_hw::init() configures I2C1 at
        // 400 kHz after SAU init — skip the OLED's 100 kHz init to avoid
        // a redundant peripheral reset.  SSD1306 supports 400 kHz.
        #[cfg(all(feature = "ui-oled", not(feature = "se050")))]
        {
            hw::i2c::init(mhz);
            // RDP1 boot diagnostic — OLED visible from this point onward.
            ui::init();
            let d = ui::display();
            d.clear();
            d.draw_line(0, "BOOT 3 i2c+oled");
            d.flush();
        }
        secure_log!("[S] RCC: {} MHz + HSI48 + TRNG configured", mhz);
    }

    secure_log!("[S] Secure world starting...");
    secure_log!(
        "[S] Reset cause: {} (RCC_CSR=0x{:08x})",
        reset_cause.tag(), reset_csr_raw
    );

    // Defensive SRAM zeroization on abnormal reset. Complements the
    // panic handler's zeroize_sensitive_state() — if the chip reset
    // before the panic handler could run (watchdog bite, brownout,
    // glitch-induced fault), this is our last chance to wipe SRAM
    // secrets before any subsequent unlock logic touches them.
    //
    // Skipped for Cold / Software / OptionByte causes: Cold boots have
    // been off long enough for SRAM retention to decay; Software resets
    // always originate from code that zeroized first; OptionByte
    // reloads are triggered by the external provisioner, not the user.
    if reset_cause.is_abnormal() {
        secure_log!("[S] Abnormal reset — zeroizing sensitive SRAM");
        nsc::zeroize_sensitive_state();
    }

    // ---- STSAFE-A110 I2C2 bus probe ----
    // Scans I2C2 (PH4/PH5) for on-board peripherals, then halts.
    // Triggered by: make stsafe-probe
    #[cfg(feature = "stsafe-probe")]
    unsafe {
        hw::i2c2_probe::run_probe();
    }

    // ---- GPIO button test ----
    // Scans Arduino header GPIOs, then tests debounced button events.
    // Triggered by: make button-test
    #[cfg(feature = "button-test")]
    unsafe {
        hw::buttons::run_test();
    }

    sau::init();
    #[cfg(feature = "boot-pulse")]
    unsafe { hw::boot_pulse::pulse(4); }
    #[cfg(all(feature = "ui-oled", not(feature = "se050")))]
    {
        let d = ui::display();
        d.draw_line(1, "BOOT 4 sau OK");
        d.flush();
    }
    secure_log!("[S] SAU + MPC configured");

    // D6 pin identification diagnostic: pulse the candidate pins in a
    // known pattern, then park the CPU so the LA can capture cleanly.
    // Read `pin_diag::run`'s docstring for the pulse-width table — the
    // width that shows up on CH3 (hooked to the D6 header) identifies
    // the STM32 pin electrically wired to D6.
    #[cfg(feature = "pin-diag-boot")]
    {
        secure_log!("[S][pin-diag] running Arduino-header sweep");
        // Run twice with a gap so the LA has two chances to catch it.
        crate::pin_diag::header_sweep();
        cortex_m::asm::delay(160_000 * 500);
        crate::pin_diag::header_sweep();
        secure_log!("[S][pin-diag] done — halting; inspect LA on target header");
        loop {
            cortex_m::asm::wfe();
        }
    }

    // RNG init now that GTZC/TZSC has assigned RNG as a secure peripheral
    // and the SAU is live. Safe to touch 0x520C_0800 from the secure world.
    #[cfg(feature = "stm32u585")]
    unsafe {
        hw::rng::init();
        #[cfg(feature = "boot-pulse")]
        hw::boot_pulse::pulse(5);
        secure_log!("[S] TRNG initialised");
    }

    // Tamper monitoring (feature `tamp`). Polled — `init()` arms the
    // detection registers (CR1) but leaves IER masked so no IRQ fires;
    // `tamp::poll()` from SysTick drains TAMP_SR. Log-only; never halts
    // and never wipes (see `hw::tamp` module header §1). Reversible:
    // register-state only. Without the feature, this compiles to no-op.
    #[cfg(all(feature = "stm32u585", feature = "tamp"))]
    {
        hw::tamp::init();
        #[cfg(feature = "tamp-irq")]
        secure_log!("[S] TAMP initialised (IRQ, log-only)");
        #[cfg(not(feature = "tamp-irq"))]
        secure_log!("[S] TAMP initialised (polled, log-only)");
    }

    // Power-consumption side-channel mask (feature `consumption-mask`).
    // TIM2 CH1 PWM on PA5 with a randomised duty cycle. `init()` configures
    // the TIM2/GPIO + writes a first random duty; `randomize()` runs from
    // SysTick to keep the mask jittering across signing windows. Reversible:
    // TIM2/GPIO/RCC clock-enable bits; revert by reflashing without the
    // feature. See `hw::consumption_mask` module header.
    #[cfg(all(feature = "stm32u585", feature = "consumption-mask"))]
    {
        hw::consumption_mask::init();
        secure_log!("[S] Consumption mask initialised (TIM2 CH1 PWM on PA5)");
    }
    #[cfg(all(feature = "ui-oled", not(feature = "se050")))]
    {
        let d = ui::display();
        d.draw_line(2, "BOOT 5 rng OK");
        d.flush();
    }

    // Masked-SHA-256 overhead bench (work-todo §18). Runs once at boot
    // after the HASH peripheral clock + TRNG are up, times the masked
    // gates vs the HASH peripheral, prints the projection, SYS_EXITs.
    // Never returns. Does nothing unless `bench-masked-sha` is enabled.
    #[cfg(feature = "bench-masked-sha")]
    bench_masked_sha::run_and_halt();

    // SAES self-test (Tier 1 of work-todo #7). Runs once at boot,
    // halts on PASS/FAIL. Does nothing unless `saes-self-test` is
    // enabled — the driver module itself is gated on `saes-dhuk`.
    #[cfg(feature = "saes-self-test")]
    saes_self_test_and_halt();

    // SAES init for the Tier-1 derivation path. Only needed when we're
    // actually going to call `SAES-CMAC(DHUK, ...)` — i.e., `saes-dhuk`
    // is ON and the `otp-hardcoded-master-key` dev shortcut is OFF.
    // Under `otp-hardcoded-master-key` the derivation stays on the
    // HKDF-over-constant fallback and SAES is never touched by
    // `secret_keys`, so skipping the init keeps dev-path builds
    // unaffected.
    #[cfg(all(feature = "saes-dhuk", not(feature = "otp-hardcoded-master-key"), not(feature = "saes-self-test")))]
    {
        match hw::saes::init() {
            Ok(()) => {
                secure_log!("[S] SAES initialised (Tier-1 DHUK path)");
            }
            Err(e) => {
                secure_log!("[S] SAES init FAIL: {:?} — derivations will error", e);
            }
        }
    }

    // Tier-2 BHK boot-time load + lock. Only when the `bhk` production
    // feature is on (and the dev/self-test shortcuts are off). First
    // boot of an unprovisioned device generates + wraps + stores the
    // BHK; every subsequent boot unwraps it into the TAMP backup
    // registers and sets `BHKLOCK` so only SAES can read it. Must run
    // after `saes::init()` (the wrap/unwrap uses DHUK-ECB) and before
    // any `KeySel::Bhk` derivation. Under `otp-hardcoded-master-key` /
    // `bhk-hardcoded-master-key` / `saes-self-test` the BHK path stays
    // on the software fallback and this is skipped.
    #[cfg(all(feature = "bhk", not(feature = "otp-hardcoded-master-key"), not(feature = "bhk-hardcoded-master-key"), not(feature = "saes-self-test")))]
    unsafe {
        if !hw::bhk::is_provisioned() {
            match hw::bhk::provision() {
                Ok(()) => {
                    secure_log!("[S] BHK provisioned (first boot)");
                }
                Err(e) => {
                    secure_log!("[S] BHK provision FAIL: {:?}", e);
                }
            }
        }
        match hw::bhk::load_and_lock() {
            Ok(()) => {
                secure_log!("[S] BHK loaded + BHKLOCK set");
            }
            Err(e) => {
                secure_log!("[S] BHK load FAIL: {:?} — BHK derivations will error", e);
            }
        }
    }

    // Initialize I2C1 for SE050 and/or OPTIGA Trust M BEFORE any SE operations.
    // Both chips share I2C1 (SE050 at 0x48, OPTIGA at 0x30). No address conflict.
    // Must come after rcc::init() (clocks) and sau::init() (peripherals).
    #[cfg(all(feature = "stm32u585", any(feature = "se050", feature = "optiga-trust-m")))]
    unsafe {
        hw::i2c_hw::init();
        secure_log!("[S] I2C1 initialized (PB8/PB9, 400 kHz)");
    }

    // Initialize SPI2 for TROPIC01 secure element.
    // Must come after rcc::init() (clocks) and sau::init() (peripherals).
    #[cfg(all(feature = "stm32u585", feature = "tropic01-se"))]
    unsafe {
        hw::spi_hw::init();
        #[cfg(feature = "spi1-arduino")]
        secure_log!("[S] SPI1 initialized for TROPIC01 (PE12-15 Arduino, 5 MHz)");
        #[cfg(not(feature = "spi1-arduino"))]
        secure_log!("[S] SPI2 initialized for TROPIC01 (PB12-15, 5 MHz)");
    }

    ui::init();
    secure_log!("[S] UI initialized");
    ui::splash();

    // Start SysTick early on real hardware so measured_boot can use
    // timeout::now() for its 4-second auto-dismiss timer. On QEMU the
    // mailbox gateway must be initialised before SysTick starts polling,
    // so SysTick stays late there (and the semihosting UI blocks on
    // READC anyway — no timer needed).
    #[cfg(feature = "stm32u585")]
    setup_systick();

    // F-24 stage E Phase 1 — hardware flicker validation harness.
    // When this feature is on, short-circuit straight into the decoy-
    // frame render loop. No measured_boot, no wizard, no SE access —
    // just OLED rendering forever so a bench observer can judge the
    // 5:1 (200 ms:40 ms) real:decoy cadence.
    #[cfg(feature = "decoy-flicker-test")]
    ui::seed_wizard::decoy_flicker_test_loop();

    // §32 P4/P5 interactive UI harness. Short-circuits into a loop that
    // drives JUST the duress-PIN setup dialogs on the real OLED — no SE,
    // no wizard, no provisioning. Lets a bench operator validate the
    // dialog rendering + button nav + the distinct-PIN reject + the
    // wipe-mode chooser. Run: `make play-hw-duress-ui` (keyboard buttons
    // forwarded via wallet_run_hw.py). The "main PIN" is fixed to
    // 12345678 so the operator can verify the distinct-check rejects it.
    #[cfg(feature = "duress-ui-test")]
    unsafe {
        // NB: use `secure_log!` (DHCSR.C_DEBUGEN-gated), NOT raw
        // `hprintln!` — an ungated semihosting BKPT HardFaults when no
        // debugger is attached (e.g. straight after a probe-rs download
        // resets the board), hanging the device before the OLED renders.
        use zeroize::Zeroize;
        let main_pin: [u8; sphincs_tz_shared::PIN_LEN] = *b"12345678";
        secure_log!("[DURESS-UI] harness ready. Main PIN = 12345678.");
        secure_log!("[DURESS-UI] Try setting a duress PIN; enter 12345678 once to see the reject.");
        loop {
            ui::show_status("Duress UI test", "LR=start");
            // Wait for any button to (re)start a pass.
            let mut idle = || false;
            let _ = ui::input().wait_button(&mut idle);

            match ui::seed_wizard::collect_duress_pin(&main_pin) {
                Some(mut p) => {
                    secure_log!("[DURESS-UI] duress PIN accepted (distinct from main)");
                    let wipe = ui::seed_wizard::choose_duress_wipe_mode();
                    secure_log!("[DURESS-UI] wipe-on-duress = {}", wipe);
                    ui::show_status(
                        "Duress set",
                        if wipe { "mode: WIPE" } else { "mode: DECOY" },
                    );
                    p.zeroize();
                }
                None => {
                    secure_log!("[DURESS-UI] duress declined / exhausted -> random decoy");
                    ui::show_status("Declined", "random decoy");
                }
            }
            // Hold the result on screen ~2.5 s (readable), then loop.
            let start = timeout::now();
            while timeout::now().wrapping_sub(start) < 2500 {
                cortex_m::asm::nop();
            }
        }
    }

    // Firmware measurement: hash flash, display 8 BIP-39 words for
    // visual comparison with the companion tool's reproducible build.
    // Skipped in automated e2e tests which need non-interactive boot.
    #[cfg(not(feature = "e2e-test"))]
    measured_boot::run();

    // ---- QR-code screen test ----
    // Renders the companion-app QR + URL, then halts. Used to iterate on
    // the QR layout in isolation without going through the rest of boot.
    // Triggered by: make qr-screen
    #[cfg(feature = "qr-screen-test")]
    {
        ui::display().qr_splash();
        secure_log!("[S] QR screen rendered — halting");
        loop {
            cortex_m::asm::wfi();
        }
    }

    // Try to load a previously saved per-device pairing key for the
    // Tropic01. If found, sessions use pairing slot 1 (per-device)
    // instead of slot 0 (shared devkit keys).
    //
    #[cfg(all(feature = "tropic01-se", not(feature = "dual-se"), not(test)))]
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SE)).load_pairing_key();
    }

    // Load the Platform Binding Secret for OPTIGA Trust M from secure flash.
    // If blank (first boot), PBS will be provisioned during the seed wizard.
    #[cfg(all(feature = "optiga-trust-m", not(feature = "dual-se"), not(test)))]
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SE)).load_pbs();
    }
    #[cfg(all(feature = "dual-se", not(test)))]
    unsafe {
        (&mut *core::ptr::addr_of_mut!(SE)).load_pbs();
    }

    // §4 PIN-counter reconciliation. Cross-checks the MCU page-124
    // attempt counter against BOTH SE-side counters (OPTIGA F1E1 +
    // SE050 USERID `auth_attempts` via ReadObjectAttributes), AND
    // checks intra-SE divergence. Any disagreement = unambiguous
    // tamper signal (≥1 counter was reset without the others) →
    // wipe immediately rather than waiting for the next unlock to
    // expose it. See `nsc::reconcile_pin_attempts` for the full
    // design + limitation notes (incl. the correction to the earlier
    // "SE050 can't be peeked" claim).
    #[cfg(all(feature = "stm32u585", any(feature = "optiga-trust-m", feature = "dual-se"), not(test)))]
    unsafe {
        nsc::reconcile_pin_attempts(&mut *core::ptr::addr_of_mut!(SE));
    }

    // ---- Factory provisioning short-circuit ----
    //
    // When `factory-provisioning` is on, run the one-shot factory
    // ceremony here and halt. Never falls through to the wizard /
    // unlock paths. The ceremony assumes both SEs are alive (the
    // boot path above has already initialized them) and that the
    // device is fresh-from-manufacturer (no user state).
    //
    // See `secure/src/factory_provisioning.rs` module docs for the
    // step list + error code table + operator manual reference.
    #[cfg(feature = "factory-provisioning")]
    unsafe {
        let se = &mut *core::ptr::addr_of_mut!(SE);
        factory_provisioning::run_and_halt(se);
    }

    // ---- Prodtest short-circuit ----
    //
    // When `prodtest` is on, skip the wizard / unlock paths and
    // show the "PRODTEST READY" panel. The CMSE veneers (declared
    // under `#[cfg(feature = "prodtest")]` in `secure/src/nsc/mod.rs`)
    // handle every prodtest command from the NS-world USB-HID ISR;
    // main() just sits in WFI. The factory fixture drives the test
    // sequence via USB and decides per-component pass/fail.
    //
    // See `docs/factory-prodtest.md` for the command reference +
    // fixture integration guide.
    #[cfg(feature = "prodtest")]
    unsafe {
        // Initialize button GPIOs so `CMD_PRODTEST_BUTTON_TEST` (109)
        // can drive them. Safe to call before NS boot — the buttons
        // module only configures GPIOA/GPIOC bits via RMW on disjoint
        // pins, leaving SWDIO/SWCLK / I²C / SPI lines untouched.
        #[cfg(feature = "gpio-buttons")]
        hw::buttons::init();

        // USB OTG FS hardware init — must run before NS boot so the
        // NS USB stack comes up against a configured controller.
        // Mirrors the call at the tail of main() in the non-prodtest
        // path, but we have to run it ourselves because the prodtest
        // short-circuit jumps straight to `boot_ns::boot` and skips
        // the wizard / unlock / pre-boot init that the production
        // flow does down there.
        hw::usb_hw::init();
        secure_log!("[S] USB OTG FS hardware initialized (prodtest)");

        // SysTick + DWT cycle counter — same final-stage init the
        // production main() does between unlock and `boot_ns::boot`.
        setup_systick();
        ARCH.demcr.set_bits(1 << 24);       // TRCENA — enable trace unit
        ARCH.dwt_lar.write(0xC5AC_CE55);    // unlock DWT for writes
        ARCH.dwt_cyccnt.write(0);           // reset cycle counter
        ARCH.dwt_ctrl.set_bits(1);          // CYCCNTENA — start counter

        ui::show_status(" PRODTEST READY", " USB cmds wait ");
        secure_log!("[S] prodtest firmware ready — booting NS world for USB");

        // SAFETY: `boot_ns::boot` performs the irreducibly-unsafe
        // TrustZone branch to the NS reset vector via BLXNS. Same
        // primitive used at the tail of main(); no S-world state
        // survives past it. The NS USB stack runs in NS world and
        // routes `INS_V2_PRODTEST_*` codes to the CMSE veneers
        // declared under `#[cfg(feature = "prodtest")]` in
        // `secure/src/nsc/mod.rs::nsc_prodtest_*`.
        boot_ns::boot(NS_FLASH_BASE);
    }

    // ---- One-shot OPTIGA OID recovery (optiga-reset-oids) ----
    // Runs before any wallet provisioning. Provisions a Trust Anchor cert
    // at 0xE0E3 and sends SetObjectProtected reset manifests to the burned
    // AUTHREF OID range so subsequent SetDataObject writes succeed again.
    // Dev-only — disabled by `make prod-check`. Drop the feature once the
    // chip is back to a writable state.
    #[cfg(all(feature = "optiga-reset-oids", feature = "dual-se", not(test)))]
    unsafe {
        secure_log!("[S] optiga-reset-oids: running one-shot OID recovery");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        if let Err(e) = se.optiga.recover_burned_oids() {
            secure_log!("[S] optiga-reset-oids: recovery failed: {:?}", e);
        } else {
            secure_log!("[S] optiga-reset-oids: recovery pass complete");
        }
    }
    #[cfg(all(
        feature = "optiga-reset-oids",
        feature = "optiga-trust-m",
        not(feature = "dual-se"),
        not(test),
    ))]
    unsafe {
        secure_log!("[S] optiga-reset-oids: running one-shot OID recovery");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        if let Err(e) = se.recover_burned_oids() {
            secure_log!("[S] optiga-reset-oids: recovery failed: {:?}", e);
        } else {
            secure_log!("[S] optiga-reset-oids: recovery pass complete");
        }
    }

    // ---- Boot-time wipe resume ----
    // If a factory reset was armed but interrupted (power loss mid-wipe),
    // the wipe flag in page 125 QW 1 survives the reboot. Finish the wipe
    // now before any unlock attempt, so we never leave the chip in a
    // half-wiped state that an attacker could leverage for partial secret
    // extraction.
    //
    // Applies to both SE050-standalone and dual-SE builds — the flag and
    // admin PIN live on the STM32 side, independent of which SE backends
    // are active. Skipped under `se050-crash-safety-e2e` because that
    // test owns the page 125 lifecycle itself (stores a test admin PIN
    // and runs its own resume routine against test OIDs; letting
    // factory_reset_admin fire here would erase the test state before
    // the test's phase 2 runs).
    #[cfg(all(
        feature = "stm32u585",
        any(feature = "se050", feature = "dual-se"),
        not(feature = "se050-crash-safety-e2e"),
        not(test),
    ))]
    unsafe {
        use secure_element::WalletStore;

        // Two triggers for boot-time wipe:
        //   (a) page-125 wipe-in-progress flag is armed — a prior
        //       `factory_reset_admin` was interrupted mid-flight.
        //   (b) page-126 MCU attempt counter is at MAX_ATTEMPTS — a
        //       prior session burned the last attempt but crashed
        //       before `trigger_lockout_wipe` could complete. Without
        //       this check, the device would boot and let the user
        //       try a PIN they've already been locked out of.
        let wipe_armed = hw::flash::is_wipe_armed();
        let attempts_exhausted =
            hw::flash::pin_attempts_read() >= sphincs_tz_shared::MAX_ATTEMPTS;

        if wipe_armed || attempts_exhausted {
            if wipe_armed {
                secure_log!("[S] Wipe-in-progress flag set — resuming factory reset");
            }
            if attempts_exhausted {
                secure_log!("[S] MCU attempt counter at MAX — triggering wipe");
            }
            ui::show_status("WIPING", "resuming from interrupt");
            let _ = (&mut *core::ptr::addr_of_mut!(SE)).factory_reset_admin();
            // factory_reset_admin ends with erase_admin_page() which clears
            // both the page-125 PIN and the wipe flag. Also reset page 126
            // (MCU attempt counter) so next boot sees unprovisioned state +
            // blank counter → first-boot wizard, not another lockout loop.
            let _ = hw::flash::pin_attempts_reset();
            ui::show_status("WALLET WIPED", "restore from seed");
        }

        // Post-wipe-check, pre-unlock: sync the SE drivers' in-RAM
        // remaining-attempts mirrors against the MCU page-124 counter.
        // The `SE.*.remaining` fields are `const fn new()`-initialised
        // to `MAX_ATTEMPTS` on every boot, but MCU flash retains the
        // real count across power-cycles. Without this ratchet-down,
        // `remaining_attempts()` / `cmd_get_remaining` would over-
        // report after a mid-lockout reboot until the next successful
        // unlock resynced the cache. `sync_remaining_with_mcu` only
        // lowers the cache (min-of-two), never raises it, so calling
        // it here is safe regardless of prior state.
        {
            use crate::secure_element::WalletStore;
            let used = hw::flash::pin_attempts_read();
            (&mut *core::ptr::addr_of_mut!(SE)).sync_remaining_with_mcu(used);
        }
    }

    // ---- SE050 factory reset (iterative wipe) ----
    // Actually wipes user objects via ReadIDList + DeleteSecureObject.
    // Authentication attempts against every UserID this firmware
    // lineage has ever provisioned:
    //   - 0x7B10_0000 : current dual-SE / standalone SE050 UserID (v6)
    //   - 0x7B0E_0000 : retired v5 range (2026-04-22, bench chip stuck
    //                   admin with unrecoverable random PIN)
    //   - 0x7B06_0000 : retired v3 range (2026-04-21, bench chips only)
    //   - 0x7B00_2000 : legacy UserID from early f44fd92-era builds
    // PIN is `b"00000000"` — the PIN baked into the e2e-test fast-path
    // and entered by a user typing "0" eight times in the wizard.
    //
    // Triggered by: make se050-reset
    #[cfg(feature = "se050-factory-reset")]
    unsafe {
        ui::show_status("SE050 wipe", "...");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        // Try the known dev UserIDs against the dev PIN candidates. Each
        // wrong PIN consumes one SE050 attempt against that UserID
        // (10-attempt budget); a correct PIN auto-resets the counter.
        // PIN order is best-guess to minimise consumed attempts.
        const USERIDS: &[u32] = &[0x7B10_0000, 0x7B0E_0000, 0x7B06_0000, 0x7B00_2000];
        const PIN_CANDIDATES: &[&[u8]] = &[
            b"00000000", // e2e default + most common dev PIN
            b"12345678",
            b"11111111",
        ];

        let mut total_deleted: u32 = 0;
        let mut last_failed: u16 = u16::MAX;
        let mut any_auth_ok = false;

        'outer: for &uid in USERIDS {
            for &pin in PIN_CANDIDATES {
                let (d, f, auth_ok) = match se.iterative_wipe(Some(uid), Some(pin)) {
                    Ok(r) => r,
                    Err(_e) => {
                        secure_log!(
                            "[S] iterative_wipe(UID=0x{:08x}) ERROR: {:?}",
                            uid, _e
                        );
                        (0, u16::MAX, false)
                    }
                };
                secure_log!(
                    "[S] wipe UID=0x{:08x} pin={:?}: deleted={}, left={}, auth_ok={}",
                    uid,
                    core::str::from_utf8(pin).unwrap_or("?"),
                    d, f, auth_ok
                );
                total_deleted = total_deleted.saturating_add(d as u32);
                last_failed = f;
                if auth_ok {
                    any_auth_ok = true;
                }
                if f == 0 {
                    break 'outer;
                }
            }
        }

        // Tri-state outcome:
        //   clean      — no survivors
        //   wrong-PIN  — survivors AND no PIN ever authed (UserID likely
        //                provisioned with a different PIN, or UserID OID
        //                guess is wrong)
        //   blocked    — survivors AND some PIN did auth, so the leftover
        //                objects were created with a non-self-deletable
        //                policy (older firmware) and are stuck on-chip
        let status = if last_failed == 0 {
            "clean"
        } else if !any_auth_ok {
            "wrong-PIN"
        } else {
            "blocked"
        };
        secure_log!(
            "[S] SE050 wipe DONE: {} deleted total, {} survivors, status={}",
            total_deleted, last_failed, status
        );
        ui::show_status("SE050 wipe", status);
        loop { cortex_m::asm::wfi(); }
    }

    // ---- SE050 crash-safety (power-loss mid-wipe) e2e ----
    // Two-phase test. Same firmware both runs; phase auto-detected from
    // the wipe flag at page 125 QW 1.
    //   Phase 1 (flag blank): provision test objects at 0x7B0A_xxxx,
    //   persist a test admin PIN to flash, arm the flag, delete ONLY
    //   the data object, halt → simulates power cut mid-wipe.
    //   Phase 2 (flag armed, after manual board reset): verify pre-
    //   resume state, read PIN from flash, finish the wipe, erase
    //   page 125, report PASS.
    // Triggered by: make se050-crash-safety-e2e
    #[cfg(feature = "se050-crash-safety-e2e")]
    unsafe {
        let se = &mut *core::ptr::addr_of_mut!(SE);
        let flag_armed_at_start = hw::flash::is_wipe_armed();
        if flag_armed_at_start {
            ui::show_status("Crash safety", "phase 2 (resume)");
        } else {
            ui::show_status("Crash safety", "phase 1 (partial)");
        }
        match se.run_crash_safety_roundtrip() {
            Ok(msg) => {
                secure_log!("[S] [E2E-CRASH] {}", msg);
                if flag_armed_at_start {
                    ui::show_status("Crash safety", "PASS");
                } else {
                    ui::show_status("RESET BOARD", "to run phase 2");
                }
            }
            Err(_e) => {
                secure_log!("[S] [E2E-CRASH] FAIL ({:?})", _e);
                ui::show_status("Crash safety", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- SE050 admin-auth wipe e2e ----
    // Exercises the exact delete path used by the PIN-lockout factory
    // reset: provision admin + user UserIDs + a data object with the
    // two-entry TAG_POLICY, then delete everything under admin auth
    // WITHOUT verifying the user PIN. Proves admin can wipe even when
    // the user's credential is blocked.
    // Uses test OID range 0x7B09_xxxx so it never touches production
    // provisioning. Repeatable on the same chip.
    // Triggered by: make se050-admin-wipe-e2e
    #[cfg(feature = "se050-admin-wipe-e2e")]
    unsafe {
        ui::show_status("Admin wipe", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.run_admin_wipe_roundtrip() {
            Ok(()) => {
                secure_log!("[S] [E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS");
                ui::show_status("Admin wipe", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [E2E-ADMIN] ADMIN-WIPE ROUNDTRIP: FAIL ({:?})", _e);
                ui::show_status("Admin wipe", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- SE050 SCP03 key-rotation ceremony (IRREVERSIBLE — production only) ----
    // One-shot GP PUT KEY: replace SCP03 keyset 0x0B in place with this
    // device's derived keys (secret_keys::se050_scp03_*_key, BHK-rooted in
    // a `bhk` build), then halt. The published factory keys are gone after
    // this — the chip only opens with firmware that re-derives the matching
    // keys (establish() probes derived-first, falls back to factory).
    // PRE-CONDITIONS (see work-todo #20 Stage B + docs/production-todo.md):
    // RDP already stepped to ≥1 (so the BHK is its final per-die-DHUK value),
    // BHK provisioned, chip is factory-fresh. NEVER run on a board that still
    // moves RDP around. The PUT KEY framing is best-effort from GP 2.3 /
    // AN12436 — validate on sacrificial parts before any real provisioning run.
    // Triggered by: make flash-hw-se050-rotate-scp03
    #[cfg(feature = "se050-rotate-scp03")]
    unsafe {
        ui::show_status("SCP03 rotate", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.rotate_scp03_keys() {
            Ok(()) => {
                secure_log!("[S] [SCP03-ROTATE] PUT KEY OK — keyset 0x0B replaced with derived keys");
                ui::show_status("SCP03 rotate", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [SCP03-ROTATE] FAIL ({:?})", _e);
                ui::show_status("SCP03 rotate", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- SE050 admin-extract-attempt e2e ----
    // Negative security test: prove the admin PIN cannot extract user-PIN-
    // gated secrets. Provisions a sentinel under user-PIN gating with
    // admin-DELETE in the policy, then asserts admin-auth READ is refused
    // while admin-auth DELETE succeeds. PASS = silicon enforced the two-
    // entry TAG_POLICY (admin → DELETE only). FAIL = security regression.
    // Uses test OID range 0x7B0B_xxxx; never touches production provisioning.
    // Triggered by: make se050-admin-extract-attempt-e2e
    #[cfg(feature = "se050-admin-extract-attempt-e2e")]
    unsafe {
        ui::show_status("Admin extract", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.run_admin_extract_attempt() {
            Ok(()) => {
                secure_log!("[S] [E2E-EXTRACT] ADMIN-EXTRACT ATTEMPT: PASS (admin cannot read user-PIN-gated secrets)");
                ui::show_status("Admin extract", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [E2E-EXTRACT] ADMIN-EXTRACT ATTEMPT: FAIL ({:?})", _e);
                ui::show_status("Admin extract", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- Dual-SE (OPTIGA + SE050) admin-wipe roundtrip e2e ----
    // Exercises `DualSecureElement::provision` + `DualSecureElement::
    // unlock` end-to-end on real silicon: pre-clean → provision →
    // unlock (XOR-reconstruct) → verify master_secret. Destroys any
    // existing wallet state on both chips during pre-clean.
    //
    // Scope: the XOR entropy reconstruction + master_secret cross-
    // verify across OPTIGA and SE050 — the unique dual-SE value-add
    // not covered by either single-SE test. The admin-wipe dispatch
    // is NOT exercised here; see `optiga-admin-wipe-e2e` and
    // `se050-admin-wipe-e2e` for those primitives individually.
    //
    // LcsO safety: does NOT imply `optiga-lock-operational`. SE050 has
    // no LcsO concept. Uses current production object ranges on both
    // chips (OPTIGA F1D0..F1D4 + F1E1; SE050 0x7B10_xxxx — v6, the
    // latest bumped range past every legacy stuck region).
    //
    // Triggered by: make dual-se-admin-wipe-e2e
    #[cfg(feature = "dual-se-admin-wipe-e2e")]
    unsafe {
        ui::show_status("Dual wipe", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.run_admin_wipe_roundtrip() {
            Ok(()) => {
                secure_log!("[S] [E2E-DUAL-ADMIN] DUAL-WIPE ROUNDTRIP: PASS");
                ui::show_status("Dual wipe", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [E2E-DUAL-ADMIN] DUAL-WIPE ROUNDTRIP: FAIL ({:?})", _e);
                ui::show_status("Dual wipe", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // Multi-unlock / cross-reboot test: provisions on first boot,
    // re-uses state on subsequent boots, runs 5 unlock+verify cycles
    // each boot. Pair with `make dual-se-multi-unlock-e2e` which
    // invokes probe-rs run 3× to force 3 cold reboots = 15 unlocks
    // across 3 boot sessions.
    #[cfg(feature = "dual-se-multi-unlock-e2e")]
    unsafe {
        ui::show_status("Dual multi-unlock", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        let rc = match se.run_multi_unlock_roundtrip(5) {
            Ok(()) => {
                secure_log!("[S] [E2E-DUAL-MULTI] MULTI-UNLOCK ROUNDTRIP: PASS");
                ui::show_status("Dual multi-unlock", "PASS");
                cortex_m_semihosting::debug::EXIT_SUCCESS
            }
            Err(_e) => {
                secure_log!("[S] [E2E-DUAL-MULTI] MULTI-UNLOCK ROUNDTRIP: FAIL ({:?})", _e);
                ui::show_status("Dual multi-unlock", "FAIL");
                cortex_m_semihosting::debug::EXIT_FAILURE
            }
        };
        // SYS_EXIT: probe-rs sees ADP_Stopped_ApplicationExit and detaches
        // cleanly. Without this, probe-rs stays attached on `wfi` and the
        // USB interface isn't released for the next `probe-rs run` cycle.
        cortex_m_semihosting::debug::exit(rc);
        loop { cortex_m::asm::wfi(); }
    }

    // ---- PIN-gate roundtrip (MCU flash counter + gated_unlock) ----
    // Direct validation of the work-todo #4 Phase 1 dual-SE PIN lockout
    // sync fix. No buttons or USB UI required — hardcoded right/wrong
    // PINs drive `nsc::gated_unlock` through its happy and sad paths
    // while reading page 126 directly to verify the counter state.
    //
    // Flow:
    //   0. factory_reset_admin + pin_attempts_reset → known blank state.
    //      Verify pin_attempts_read() == 0.
    //   1. provision(entropy, master, vk, bvk, CORRECT_PIN) via
    //      WalletStore. Counter stays at 0 (provision doesn't gate).
    //   2. gated_unlock(WRONG_PIN) × 3. Each returns PinIncorrect.
    //      After each, assert pin_attempts_read() == 1, 2, 3.
    //   3. gated_unlock(CORRECT_PIN). Returns Ok(master_secret).
    //      Assert pin_attempts_read() == 0 (page erased on success).
    //   4. Repeat bump (× 2) + reset (correct PIN) to prove the
    //      counter cycle is repeatable, not a one-shot.
    //   5. Log PASS. Halts in WFI.
    //
    // Does NOT exhaust all 10 attempts — that would burn the SE050
    // user UserID's silicon retry budget (can't reset without
    // admin-auth deleting the UserID). Counter max + PinLocked path
    // is provable by inspection: the check in gated_unlock is a
    // simple `pre_count >= MAX_ATTEMPTS` comparison.
    //
    // Triggered by: make pin-gate-e2e
    #[cfg(feature = "pin-gate-e2e")]
    unsafe {
        use crate::secure_element::{UnlockError, WalletStore};

        ui::show_status("PIN gate", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        // ── Step 0: known blank state ─────────────────────────────
        // Deliberately NO `factory_reset_admin` here — the production
        // wrapper erases page 125 as part of cleanup, and calling it
        // followed by `pin_attempts_reset` (page 126) triggered a flash-
        // timing window on this bench chip where a subsequent program
        // to page 125 QW0 returned PROGERR silently. The test just needs
        // the MCU counter cleared; SE cleanup is the provision path's job.
        let _ = hw::flash::pin_attempts_reset();
        let count0 = hw::flash::pin_attempts_read();
        if count0 != 0 {
            secure_log!("[PIN-GATE] step 0 FAILED: count after reset = {} (expected 0)", count0);
            ui::show_status("PIN gate", "FAIL: setup");
            loop { cortex_m::asm::wfi(); }
        }
        secure_log!("[PIN-GATE] step 0: blank state OK");

        // ── Step 1: provision with known-correct PIN ─────────────
        let test_entropy: [u8; 32] = [0x42; 32];
        let test_master = crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xCC; 32];
        let test_bvk: [u8; 32] = [0xDD; 32];
        let correct_pin: [u8; 8] = *b"00000000";
        let wrong_pin: [u8; 8] = *b"99999999";

        if let Err(_e) = se.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &correct_pin) {
            secure_log!("[PIN-GATE] step 1 FAILED: provision returned error");
            ui::show_status("PIN gate", "FAIL: prov");
            loop { cortex_m::asm::wfi(); }
        }
        secure_log!("[PIN-GATE] step 1: provision OK");

        // ── Step 2: 3× wrong-PIN, counter 0→1→2→3 ────────────────
        for expected in 1u8..=3 {
            match nsc::gated_unlock(se, &wrong_pin) {
                Err(UnlockError::PinIncorrect) => {}
                other => {
                    secure_log!(
                        "[PIN-GATE] step 2.{}: expected PinIncorrect, got {:?}",
                        expected, other.as_ref().err()
                    );
                    ui::show_status("PIN gate", "FAIL: bad-pin");
                    loop { cortex_m::asm::wfi(); }
                }
            }
            let c = hw::flash::pin_attempts_read();
            if c != expected {
                secure_log!("[PIN-GATE] step 2.{} FAILED: count={} expected {}", expected, c, expected);
                ui::show_status("PIN gate", "FAIL: counter");
                loop { cortex_m::asm::wfi(); }
            }
            secure_log!("[PIN-GATE] step 2.{}: wrong PIN → count={} OK", expected, c);
        }

        // ── Step 3: correct PIN resets counter to 0 ──────────────
        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_master) => {}
            other => {
                secure_log!(
                    "[PIN-GATE] step 3 FAILED: expected Ok, got {:?}",
                    other.as_ref().err()
                );
                ui::show_status("PIN gate", "FAIL: good-pin");
                loop { cortex_m::asm::wfi(); }
            }
        }
        let c3 = hw::flash::pin_attempts_read();
        if c3 != 0 {
            secure_log!("[PIN-GATE] step 3 FAILED: count after success={} (expected 0)", c3);
            ui::show_status("PIN gate", "FAIL: reset");
            loop { cortex_m::asm::wfi(); }
        }
        secure_log!("[PIN-GATE] step 3: correct PIN → counter reset OK");

        // ── Step 4: another bump+reset cycle to prove repeatability ──
        for expected in 1u8..=2 {
            if !matches!(nsc::gated_unlock(se, &wrong_pin), Err(UnlockError::PinIncorrect)) {
                secure_log!("[PIN-GATE] step 4.{} FAILED: wrong PIN not rejected", expected);
                ui::show_status("PIN gate", "FAIL: cycle");
                loop { cortex_m::asm::wfi(); }
            }
            let c = hw::flash::pin_attempts_read();
            if c != expected {
                secure_log!("[PIN-GATE] step 4.{} FAILED: count={} expected {}", expected, c, expected);
                ui::show_status("PIN gate", "FAIL: cycle");
                loop { cortex_m::asm::wfi(); }
            }
        }
        if !matches!(nsc::gated_unlock(se, &correct_pin), Ok(_)) {
            secure_log!("[PIN-GATE] step 4 FAILED: second correct PIN rejected");
            ui::show_status("PIN gate", "FAIL: cycle");
            loop { cortex_m::asm::wfi(); }
        }
        let c4 = hw::flash::pin_attempts_read();
        if c4 != 0 {
            secure_log!("[PIN-GATE] step 4 FAILED: count after 2nd reset={} (expected 0)", c4);
            ui::show_status("PIN gate", "FAIL: cycle");
            loop { cortex_m::asm::wfi(); }
        }
        secure_log!("[PIN-GATE] step 4: second cycle OK");

        secure_log!("[S] [E2E-PIN-GATE] PIN-GATE ROUNDTRIP: PASS");
        ui::show_status("PIN gate", "PASS");
        loop { cortex_m::asm::wfi(); }
    }

    // ---- OPTIGA Trust M factory_reset roundtrip e2e ----
    // Exercises the `factory_reset` primitive end-to-end on real silicon:
    // provision F1D0..F1D4 + F1E1 with known test vectors, verify the
    // unlock path works, call `factory_reset`, then verify the counter
    // sentinel + `NotProvisioned` error + `check_provisioned() == false`
    // post-wipe contract.
    //
    // Scope: the factory_reset PRIMITIVE only — NOT the PIN-lockout
    // integration path that calls it (deferred to a later test).
    //
    // Destroys any wallet state on the chip because it uses the real
    // production OIDs (`factory_reset` hardcodes them). Re-run the real
    // first-boot wizard or `make flash-hw-optiga-unlock-test` afterwards
    // to restore. Idempotent across repeated runs on the same chip.
    //
    // Does NOT imply `optiga-lock-operational` → no LcsO ratcheting.
    //
    // Triggered by: make optiga-admin-wipe-e2e
    // ---- OPTIGA hardware PIN counter e2e test ----
    // Exercises the E120 LUC binding on F1D0. DESTRUCTIVE — rewrites
    // F1D0 metadata to the LUC variant on first run.
    //
    // Flow:
    //  1. Provision via WalletStore (runs store_objects which now
    //     provisions E120 before F1D0 with Exec=LUC(E120)).
    //  2. Read E120 — expect (0, HW_PIN_CTR_LIMIT).
    //  3. Wrong PIN → expect UnlockError::PinIncorrect AND E120.current == 1.
    //  4. Correct PIN → expect Ok(...) AND E120.current == 0 (reset on success).
    //  5. Two more wrong PINs → E120.current == 2.
    //  6. Correct PIN → E120.current == 0.
    //
    // On any unexpected state, loops wfi() with FAIL displayed.
    // Triggered by: make optiga-hw-counter-e2e
    #[cfg(feature = "optiga-hw-counter-e2e")]
    unsafe {
        use crate::secure_element::{UnlockError, WalletStore};

        ui::show_status("HW-CTR", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        let test_entropy: [u8; 32] = [0x42; 32];
        let test_master = crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xCC; 32];
        let test_bvk: [u8; 32] = [0xDD; 32];
        let correct_pin: [u8; 8] = *b"00000000";
        let wrong_pin: [u8; 8] = *b"99999999";

        macro_rules! fail { ($msg:expr) => {{
            secure_log!("[S] [E2E-OPTIGA-HW-CTR] FAIL: {}", $msg);
            ui::show_status("HW-CTR", "FAIL");
            loop { cortex_m::asm::wfi(); }
        }}}

        // ── Step 1: provision ────────────────────────────────────
        if let Err(_e) = se.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &correct_pin) {
            fail!("provision returned error (chip likely at LcsO=Op with non-LUC F1D0 — run optiga-reset-oids first)");
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 1: provision OK");

        // ── Step 2: E120 initial state = (0, HW_PIN_CTR_LIMIT) ───
        let (c0, limit) = match se.read_hw_pin_counter() {
            Some(p) => p,
            None => fail!("read_hw_pin_counter returned None"),
        };
        if c0 != 0 || limit != optiga::OptigaTrustM::HW_PIN_CTR_LIMIT {
            secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 2: E120 = ({},{}) expected (0,{})", c0, limit, optiga::OptigaTrustM::HW_PIN_CTR_LIMIT);
            fail!("initial E120 state wrong");
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 2: E120 initial = (0,{}) OK", limit);

        // ── Step 3: wrong PIN bumps E120 ─────────────────────────
        match se.unlock(&wrong_pin) {
            Err(UnlockError::PinIncorrect) => {}
            other => { secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 3: wrong PIN got {:?}", other.as_ref().err()); fail!("wrong PIN not rejected"); }
        }
        let (c1, _) = se.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if c1 != 1 {
            secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 3: E120.current={} expected 1", c1);
            fail!("E120 did not bump after wrong PIN");
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 3: wrong PIN → E120.current=1 OK");

        // ── Step 4: correct PIN resets E120 ──────────────────────
        match se.unlock(&correct_pin) {
            Ok(_) => {}
            other => { secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 4: correct PIN got {:?}", other.as_ref().err()); fail!("correct PIN rejected"); }
        }
        let (c4, _) = se.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if c4 != 0 {
            secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 4: E120.current={} expected 0", c4);
            fail!("E120 not reset after correct PIN");
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 4: correct PIN → E120 reset to 0 OK");

        // ── Step 5: two wrong PINs in a row ──────────────────────
        for i in 1u32..=2 {
            if !matches!(se.unlock(&wrong_pin), Err(UnlockError::PinIncorrect)) {
                fail!("wrong PIN not rejected in burst");
            }
            let (c, _) = se.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
            if c != i {
                secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 5.{}: E120.current={} expected {}", i, c, i);
                fail!("E120 mismatch during burst");
            }
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 5: burst 2 wrong PINs → E120.current=2 OK");

        // ── Step 6: second correct PIN resets again ──────────────
        if !matches!(se.unlock(&correct_pin), Ok(_)) {
            fail!("second correct PIN rejected");
        }
        let (c6, _) = se.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if c6 != 0 {
            fail!("E120 not reset on repeat correct PIN");
        }
        secure_log!("[S] [E2E-OPTIGA-HW-CTR] step 6: repeat correct PIN → E120 reset OK");

        secure_log!("[S] [E2E-OPTIGA-HW-CTR] HW-COUNTER ROUNDTRIP: PASS");
        ui::show_status("HW-CTR", "PASS");
        loop { cortex_m::asm::wfi(); }
    }

    // ---- §32 duress-PIN feasibility probe ----
    // Validates the load-bearing on-silicon assumptions for the duress
    // PIN → decoy wallet design (work-todo §32) BEFORE committing the
    // multi-session build:
    //   * OPTIGA: a SECOND AuthRef at a free OID (F1D8) with Execute=ALW
    //     (no E120/LUC binding) coexists with the real F1D0, auths
    //     independently, and crucially leaves E120 UNTOUCHED (so the
    //     duress credential never bumps the silicon lockout counter).
    //     Then confirms the real F1D0 still bumps/resets E120 — i.e.
    //     adding F1D8 didn't break the real lockout.
    //   * SE050: a SECOND UserID (max_attempts=0, unlimited) provisions
    //     + auths — i.e. an unlimited duress credential coexists with
    //     the real user UserID (the production admin UserID already
    //     proves this shape; this is a direct confirmation).
    //
    // STAYS LcsO=Creation throughout — never locks an OID, every
    // credential remains re-writable / recoverable. Reprovisions the
    // bench chips with test data (like optiga-hw-counter-e2e). Does NOT
    // touch the real F1D0..F1D5 contents beyond the normal provision.
    //
    // Triggered by: make duress-probe-hw
    #[cfg(feature = "duress-probe-e2e")]
    unsafe {
        use crate::secure_element::{UnlockError, WalletStore};

        ui::show_status("DURESS-PROBE", "running");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        let test_entropy: [u8; 32] = [0x42; 32];
        let test_master = crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xCC; 32];
        let test_bvk: [u8; 32] = [0xDD; 32];
        let real_pin: [u8; 8] = *b"00000000";
        let wrong_pin: [u8; 8] = *b"99999999";
        let duress_pin: [u8; 8] = *b"11111111";

        // F1D8: free type-3 OID (F1D0..F1D5 used, F1D6..F1DB free) —
        // mirrors apdu::OID_DURESS_AUTH_REF_PROBE.
        const DURESS_AUTHREF_OID: u16 = 0xF1D8;
        // Fresh SE050 OID range for the probe's duress UserID.
        const DURESS_USERID_OBJ: u32 = 0x7B0D_0000;

        macro_rules! fail {
            ($msg:expr) => {{
                secure_log!("[S] [DURESS-PROBE] FAIL: {}", $msg);
                ui::show_status("DURESS", "FAIL");
                // Clean SYS_EXIT so probe-rs detaches + flushes (the run
                // is piped; without this it block-buffers + wfi-loops).
                cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_FAILURE);
                loop {
                    cortex_m::asm::wfi();
                }
            }};
        }

        // Step 1: provision the real wallet (F1D0 + E120 + SE050 user UserID).
        if se
            .provision(&test_entropy, &test_master, &test_vk, &test_bvk, &real_pin)
            .is_err()
        {
            fail!("real provision failed (chip may be LcsO=Op — run optiga-reset-oids)");
        }
        secure_log!("[S] [DURESS-PROBE] step 1: real provision OK");

        // ===== OPTIGA: second AuthRef at F1D8, no E120 binding =====
        let (e0, _) = match se.optiga.read_hw_pin_counter() {
            Some(p) => p,
            None => fail!("E120 read returned None"),
        };
        secure_log!("[S] [DURESS-PROBE] step 2: E120 baseline = {}", e0);

        if se
            .optiga
            .probe_provision_duress_authref(DURESS_AUTHREF_OID, &duress_pin)
            .is_err()
        {
            fail!("OPTIGA duress AuthRef provision at F1D8 failed (F1D8 may be locked)");
        }
        secure_log!("[S] [DURESS-PROBE] step 3: OPTIGA F1D8 duress AuthRef provisioned (Execute=ALW, no lock) OK");

        let (e1, _) = se.optiga.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if e1 != e0 {
            secure_log!("[S] [DURESS-PROBE] step 4: E120 {}→{} during F1D8 provision", e0, e1);
            fail!("E120 moved while provisioning F1D8");
        }
        secure_log!("[S] [DURESS-PROBE] step 4: E120 unchanged ({}) by F1D8 provision OK", e1);

        if se
            .optiga
            .probe_hmac_auth_at(DURESS_AUTHREF_OID, &duress_pin)
            .is_err()
        {
            fail!("OPTIGA F1D8 duress HMAC auth failed");
        }
        secure_log!("[S] [DURESS-PROBE] step 5: OPTIGA F1D8 duress auth OK");

        let (e2, _) = se.optiga.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if e2 != e0 {
            secure_log!("[S] [DURESS-PROBE] step 6: E120={} expected {} — F1D8 auth BUMPED E120", e2, e0);
            fail!("F1D8 auth touched E120 (unexpected LUC coupling)");
        }
        secure_log!("[S] [DURESS-PROBE] step 6: E120 STILL unchanged ({}) after F1D8 auth — no LUC coupling OK", e2);

        // Real F1D0 still bumps E120 on wrong PIN (coexistence intact).
        match se.optiga.unlock(&wrong_pin) {
            Err(UnlockError::PinIncorrect) => {}
            other => {
                secure_log!("[S] [DURESS-PROBE] step 7: real wrong PIN got {:?}", other.as_ref().err());
                fail!("real F1D0 wrong-PIN not rejected after F1D8 added");
            }
        }
        let (e3, _) = se.optiga.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if e3 != e0 + 1 {
            secure_log!("[S] [DURESS-PROBE] step 7: E120={} expected {}", e3, e0 + 1);
            fail!("real F1D0 wrong PIN didn't bump E120 with F1D8 present");
        }
        secure_log!("[S] [DURESS-PROBE] step 7: real F1D0 wrong PIN → E120 {}→{} (coexistence intact) OK", e0, e3);

        // Real F1D0 correct PIN resets E120.
        if se.optiga.unlock(&real_pin).is_err() {
            fail!("real F1D0 correct PIN rejected after F1D8 added");
        }
        let (e4, _) = se.optiga.read_hw_pin_counter().unwrap_or((0xFFFF_FFFF, 0));
        if e4 != 0 {
            fail!("E120 not reset after real correct PIN");
        }
        secure_log!("[S] [DURESS-PROBE] step 8: real F1D0 correct PIN → E120 reset to 0 OK");

        // ===== SE050: second unlimited UserID =====
        if se
            .se050
            .probe_provision_and_auth_duress_userid(DURESS_USERID_OBJ, &duress_pin)
            .is_err()
        {
            fail!("SE050 duress UserID (unlimited) provision+auth failed");
        }
        secure_log!("[S] [DURESS-PROBE] step 9: SE050 duress UserID (max_attempts=0) provisioned + auth'd, coexists with real UserID OK");

        // ===== Timing-channel measurement (§32 P3 decision) =====
        // The drift problem only exists IF we must run BOTH SE verifies
        // on every unlock for timing uniformity. Measure the latency of
        // the "extra real verify" (one OPTIGA HMAC verify + one SE050
        // UserID verify) — the maximum timing signal an attacker gets
        // from skip-vs-run on a duress entry. Compare to the
        // keygen-dominated total unlock (~1-3 s). If it's a tiny
        // fraction + below keygen jitter, timing uniformity is NOT
        // load-bearing → skip the real verify on a duress match → the
        // counter drift dissolves entirely (no E120 reset needed).
        //
        // hprintln! (not secure_log!) so the numbers print even with
        // debug-log OFF — run `make duress-timing-hw` for clean,
        // production-speed numbers (no per-I²C-transaction logging).
        {
            use cortex_m_semihosting::hprintln;
            // Enable the DWT cycle counter (not yet armed this early in boot).
            core::ptr::write_volatile(
                0xE000_EDFC as *mut u32,
                core::ptr::read_volatile(0xE000_EDFC as *const u32) | (1 << 24),
            );
            core::ptr::write_volatile(0xE000_1FB0 as *mut u32, 0xC5AC_CE55);
            core::ptr::write_volatile(0xE000_1004 as *mut u32, 0);
            core::ptr::write_volatile(
                0xE000_1000 as *mut u32,
                core::ptr::read_volatile(0xE000_1000 as *const u32) | 1,
            );
            let cyc = || core::ptr::read_volatile(0xE000_1004 as *const u32);
            const NT: u32 = 15;
            const HZ_PER_US: u32 = 160; // 160 MHz

            // OPTIGA single HMAC verify (F1D8 auth — same APDU shape as
            // the real F1D0 verify a duress entry would run).
            let (mut o_sum, mut o_min, mut o_max) = (0u32, u32::MAX, 0u32);
            for _ in 0..NT {
                let t0 = cyc();
                let _ = se.optiga.probe_hmac_auth_at(DURESS_AUTHREF_OID, &duress_pin);
                let d = cyc().wrapping_sub(t0);
                o_sum += d;
                if d < o_min { o_min = d; }
                if d > o_max { o_max = d; }
            }
            let o_mean_us = (o_sum / NT) / HZ_PER_US;
            hprintln!(
                "[DURESS-TIMING] OPTIGA verify (F1D8 PLAIN): mean {} us / min {} us / max {} us (n={})",
                o_mean_us, o_min / HZ_PER_US, o_max / HZ_PER_US, NT
            );

            // OPTIGA real F1D0 verify via the LUC AUTO-STATE path (the
            // production real-verify, the thing a duress entry skips).
            // Compare to the F1D8 PLAIN verify above: if they match, the
            // option-B "second duress verify" pad is a clean stand-in;
            // if they differ materially, the duress credential needs its
            // own LUC counter so its verify uses the same auto-state path.
            // (Each call fires the E120 LUC; NT=15 < HW_PIN_CTR_LIMIT=32.)
            let (mut a_sum, mut a_min, mut a_max) = (0u32, u32::MAX, 0u32);
            for _ in 0..NT {
                let t0 = cyc();
                let _ = se
                    .optiga
                    .probe_hmac_auth_luc_at(optiga::apdu::OID_AUTH_REF, &real_pin);
                let d = cyc().wrapping_sub(t0);
                a_sum += d;
                if d < a_min { a_min = d; }
                if d > a_max { a_max = d; }
            }
            let a_mean_us = (a_sum / NT) / HZ_PER_US;
            hprintln!(
                "[DURESS-TIMING] OPTIGA verify (F1D0 AUTO-STATE/LUC): mean {} us / min {} us / max {} us (n={})",
                a_mean_us, a_min / HZ_PER_US, a_max / HZ_PER_US, NT
            );
            let delta = if a_mean_us > o_mean_us { a_mean_us - o_mean_us } else { o_mean_us - a_mean_us };
            hprintln!(
                "[DURESS-TIMING] plain-vs-auto-state DELTA: {} us — if <~20000 us (20 ms) the plain F1D8 pad is clean; else use a matched-LUC duress credential",
                delta
            );

            // SE050 single UserID verify (create_session + verify + close).
            let (mut s_sum, mut s_min, mut s_max) = (0u32, u32::MAX, 0u32);
            for _ in 0..NT {
                let t0 = cyc();
                let _ = se
                    .se050
                    .probe_auth_existing_userid(DURESS_USERID_OBJ, &duress_pin);
                let d = cyc().wrapping_sub(t0);
                s_sum += d;
                if d < s_min { s_min = d; }
                if d > s_max { s_max = d; }
            }
            let s_mean_us = (s_sum / NT) / HZ_PER_US;
            hprintln!(
                "[DURESS-TIMING] SE050 verify: mean {} us / min {} us / max {} us (n={})",
                s_mean_us, s_min / HZ_PER_US, s_max / HZ_PER_US, NT
            );

            let extra_us = o_mean_us + s_mean_us;
            hprintln!(
                "[DURESS-TIMING] EXTRA real-verify cost (skip vs run on duress): ~{} us total",
                extra_us
            );
            hprintln!(
                "[DURESS-TIMING] => ~{} % of a 2,000,000 us (2 s) keygen-dominated unlock",
                (extra_us.saturating_mul(100)) / 2_000_000
            );
            hprintln!("[DURESS-TIMING] verdict input: if this %% is tiny + below keygen jitter, timing uniformity is NOT load-bearing → skip real verify on duress → no drift");
        }

        // ===== Step 10: matched-LUC dual-counter coexistence =====
        // §32 DECIDED 2026-05-20: null the ~11 ms plain-vs-auto-state
        // residual by binding the duress AuthRef (F1D8) to its OWN LUC
        // counter (E121). This RE-PROVISIONS F1D8 with Execute=LUC(E121),
        // overwriting the plain (Execute=ALW) variant from steps 3–6 +
        // the timing block above — allowed because F1D8 Change=ALW (still
        // LcsO=Creation). Runs AFTER the timing block so the plain-F1D8
        // measurement above stays valid. The delta to validate vs the
        // already-proven single-LUC + plain-F1D8 coexistence: (a) two
        // LUC-bound AuthRefs (F1D0→E120, F1D8→E121) coexist; (b) a duress
        // auto-state verify bumps ONLY E121, leaving the real E120
        // untouched (no drift); (c) F1D8 auto-state timing is a twin of
        // F1D0 auto-state (~0 residual).
        const DURESS_CTR_OID: u16 = 0xE121;
        const DURESS_CTR_LIMIT: u32 = 0xFFFF; // unenforced; high so the probe never trips it
        if se
            .optiga
            .probe_provision_duress_authref_luc(
                DURESS_AUTHREF_OID, DURESS_CTR_OID, DURESS_CTR_LIMIT, &duress_pin,
            )
            .is_err()
        {
            fail!("matched-LUC duress provision (F1D8→E121) failed (dual-LUC coexistence broken?)");
        }
        secure_log!("[S] [DURESS-PROBE] step 10: F1D8 re-provisioned Execute=LUC(E121) + E121 counter OK");

        // Read both counters pre-verify (a correct real PIN in step 8
        // already reset E120 to 0; the timing block then bumped it by NT).
        let e120_pre = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let e121_pre = se.optiga.probe_read_counter(DURESS_CTR_OID).map(|(c, _)| c).unwrap_or(u32::MAX);
        secure_log!("[S] [DURESS-PROBE] step 10: pre-verify E120={} E121={}", e120_pre, e121_pre);
        if e120_pre == u32::MAX || e121_pre == u32::MAX {
            fail!("could not read E120/E121 counters before duress auto-state verify");
        }

        // One auto-state verify against the matched-LUC duress credential.
        if se
            .optiga
            .probe_hmac_auth_luc_at(DURESS_AUTHREF_OID, &duress_pin)
            .is_err()
        {
            fail!("matched-LUC duress auto-state verify (F1D8) failed");
        }

        let e120_post = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let e121_post = se.optiga.probe_read_counter(DURESS_CTR_OID).map(|(c, _)| c).unwrap_or(u32::MAX);
        secure_log!("[S] [DURESS-PROBE] step 10: post-verify E120={} E121={}", e120_post, e121_post);
        if e120_post != e120_pre {
            secure_log!("[S] [DURESS-PROBE] step 10: E120 {}→{} — duress verify DRIFTED the real counter", e120_pre, e120_post);
            fail!("duress auto-state verify bumped real E120 (matched-LUC isolation broken)");
        }
        if e121_post != e121_pre + 1 {
            secure_log!("[S] [DURESS-PROBE] step 10: E121 {}→{} expected {}", e121_pre, e121_post, e121_pre + 1);
            fail!("duress auto-state verify did not bump E121 by exactly 1 (LUC not firing on F1D8)");
        }
        secure_log!("[S] [DURESS-PROBE] step 10: matched-LUC OK — duress verify bumped ONLY E121 ({}→{}), E120 untouched ({}) — no drift", e121_pre, e121_post, e120_post);

        // ===== Timing twin: F1D8 AUTO-STATE (matched-LUC) =====
        // Confirm the duress verify via its OWN LUC counter is a timing
        // twin of the real F1D0 auto-state verify (the thing the duress
        // path pads/skips). If they match, the residual is nulled.
        {
            use cortex_m_semihosting::hprintln;
            let cyc = || core::ptr::read_volatile(0xE000_1004 as *const u32);
            const NT: u32 = 15;
            const HZ_PER_US: u32 = 160;
            let (mut d_sum, mut d_min, mut d_max) = (0u32, u32::MAX, 0u32);
            for _ in 0..NT {
                let t0 = cyc();
                let _ = se.optiga.probe_hmac_auth_luc_at(DURESS_AUTHREF_OID, &duress_pin);
                let d = cyc().wrapping_sub(t0);
                d_sum += d;
                if d < d_min { d_min = d; }
                if d > d_max { d_max = d; }
            }
            hprintln!(
                "[DURESS-TIMING] OPTIGA verify (F1D8 AUTO-STATE/matched-LUC): mean {} us / min {} us / max {} us (n={}) — compare to F1D0 AUTO-STATE above; ~0 delta = residual nulled",
                (d_sum / NT) / HZ_PER_US, d_min / HZ_PER_US, d_max / HZ_PER_US, NT
            );
        }

        secure_log!("[S] [DURESS-PROBE] === DURESS COEXISTENCE PROBE: PASS ===");
        secure_log!("[S] [DURESS-PROBE] verdict: OPTIGA 2nd AuthRef (no-LUC) + SE050 2nd unlimited UserID both coexist — §32 design feasible");
        ui::show_status("DURESS", "PASS");
        cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
        loop {
            cortex_m::asm::wfi();
        }
    }

    // ---- §32 P2: full production provision_duress silicon validation ----
    // Provisions a real wallet + an independent decoy via the PRODUCTION
    // store.provision / store.provision_duress path (KNOWN decoy entropy),
    // then proves the decoy is recoverable + correctly gated + isolated:
    //   - duress_is_provisioned() && is_provisioned() both true
    //   - read OPTIGA decoy half (auth F1D8 auto-state, bumps E121) and
    //     SE050 decoy half (auth duress UserID); half_o XOR half_e MUST
    //     equal the known decoy entropy (mirrors the real unlock cross-check)
    //   - the OPTIGA decoy read bumped ONLY E121, left real E120 untouched
    //   - the real wallet still unlocks with the real PIN (coexistence)
    // Everything stays LcsO=Creation. Run: make duress-provision-hw
    #[cfg(feature = "duress-provision-e2e")]
    unsafe {
        use crate::secure_element::WalletStore;
        let se = &mut *core::ptr::addr_of_mut!(SE);
        se.load_pbs();
        ui::show_status("DURESS-PROV", "running");

        macro_rules! fail {
            ($msg:expr) => {{
                secure_log!("[S] [DURESS-PROV] FAIL: {}", $msg);
                ui::show_status("DURESS-PROV", "FAIL");
                cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_FAILURE);
                loop { cortex_m::asm::wfi(); }
            }};
        }

        // Fixtures.
        let real_entropy: [u8; 32] = [0x42; 32];
        let real_pin: [u8; 8] = *b"00000000";
        let decoy_entropy: [u8; 32] = [0x7e; 32];
        let duress_pin: [u8; 8] = *b"99999999";

        let real_master = crypto::kdf(b"sphincs-master", &real_entropy, 0);
        let (rsk, real_vk) = crypto::derive_keypair_from_entropy(&real_entropy);
        drop(rsk);
        let real_bvk = crypto::derive_bootstrap_vk_from_entropy(&real_entropy);

        let decoy_master = crypto::kdf(b"sphincs-master", &decoy_entropy, 0);
        let (dsk, decoy_vk) = crypto::derive_keypair_from_entropy(&decoy_entropy);
        drop(dsk);
        let decoy_bvk = crypto::derive_bootstrap_vk_from_entropy(&decoy_entropy);

        // 1. Provision the real wallet (production path).
        if se.provision(&real_entropy, &real_master, &real_vk, &real_bvk, &real_pin).is_err() {
            fail!("real wallet provision failed");
        }
        secure_log!("[S] [DURESS-PROV] step 1: real wallet provisioned OK");

        // 2. Provision the decoy (production path; DualSE XOR-splits it).
        if se.provision_duress(&decoy_entropy, &decoy_master, &decoy_vk, &decoy_bvk, &duress_pin).is_err() {
            fail!("provision_duress failed");
        }
        secure_log!("[S] [DURESS-PROV] step 2: decoy wallet provisioned OK");

        // 3. Both provisioned.
        if !se.is_provisioned() { fail!("is_provisioned() false after provision"); }
        if !se.duress_is_provisioned() { fail!("duress_is_provisioned() false after provision_duress"); }
        secure_log!("[S] [DURESS-PROV] step 3: is_provisioned + duress_is_provisioned both true OK");

        // 4. Counter baselines before the OPTIGA decoy read.
        let e120_pre = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let e121_pre = se.optiga.probe_read_counter(optiga::apdu::OID_PIN_CTR_DURESS).map(|(c, _)| c).unwrap_or(u32::MAX);
        if e120_pre == u32::MAX || e121_pre == u32::MAX { fail!("counter read failed pre decoy-read"); }
        secure_log!("[S] [DURESS-PROV] step 4: pre-read E120={} E121={}", e120_pre, e121_pre);

        // 5. Read the OPTIGA decoy half (auths F1D8, fires LUC(E121)).
        let half_o = match se.optiga.duress_read_half(&duress_pin) {
            Ok((h, _stored_master)) => h,
            Err(e) => { secure_log!("[S] [DURESS-PROV] optiga.duress_read_half err {:?}", e); fail!("OPTIGA decoy read/auth failed"); }
        };

        // 6. Isolation: E120 untouched, E121 bumped by exactly 1.
        let e120_post = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let e121_post = se.optiga.probe_read_counter(optiga::apdu::OID_PIN_CTR_DURESS).map(|(c, _)| c).unwrap_or(u32::MAX);
        secure_log!("[S] [DURESS-PROV] step 6: post-read E120={} E121={}", e120_post, e121_post);
        if e120_post != e120_pre { fail!("decoy read drifted real E120"); }
        // duress_read_half fires LUC(E121) then RESETS it to 0 (F1D8
        // auth-state active) — so post-read E121 must be 0, proving both
        // the LUC fired AND the duress-side reset works.
        if e121_post != 0 { fail!("decoy read did not reset E121 to 0"); }
        let _ = e121_pre;
        secure_log!("[S] [DURESS-PROV] step 6: isolation OK (E121 reset to 0, E120 untouched)");

        // 7. Read the SE050 decoy half.
        let half_e = match se.se050.duress_read_half(&duress_pin) {
            Ok(h) => h,
            Err(e) => { secure_log!("[S] [DURESS-PROV] se050.duress_read_half err {:?}", e); fail!("SE050 decoy read/auth failed"); }
        };

        // 8. Reconstruct: half_o XOR half_e == known decoy entropy.
        let mut recon = [0u8; 32];
        for i in 0..32 { recon[i] = half_o[i] ^ half_e[i]; }
        if recon != decoy_entropy { fail!("decoy half_o XOR half_e != known decoy entropy"); }
        secure_log!("[S] [DURESS-PROV] step 8: decoy entropy reconstructs from both halves OK");

        // 9. Coexistence: the real wallet still unlocks with the real PIN.
        match se.unlock(&real_pin) {
            Ok(m) if m == real_master => {
                secure_log!("[S] [DURESS-PROV] step 9: real wallet unlock OK (master matches)");
            }
            Ok(_) => fail!("real unlock returned wrong master after decoy provisioning"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] real unlock err {:?}", e); fail!("real wallet unlock failed after decoy provisioning"); }
        }

        // ===== P3: gated_unlock dispatch validation (real / duress / wrong) =====
        // Exercises the production timing-uniform dispatch end-to-end.
        // Reset page-124 first so the MCU lockout gate starts clean.
        let _ = crate::hw::flash::pin_attempts_reset();

        // 10. Duress PIN through the dispatch → decoy master, E120 untouched.
        let e120_before_duress = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        match crate::nsc::gated_unlock(se, &duress_pin) {
            Ok(m) if m == decoy_master => {
                secure_log!("[S] [DURESS-PROV] step 10: gated_unlock(duress) → decoy master OK");
            }
            Ok(_) => fail!("gated_unlock(duress) returned wrong master (not decoy)"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] gated_unlock(duress) err {:?}", e); fail!("gated_unlock(duress) failed"); }
        }
        let e120_after_duress = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        if e120_after_duress != e120_before_duress {
            secure_log!("[S] [DURESS-PROV] step 11: E120 {}→{} on duress dispatch", e120_before_duress, e120_after_duress);
            fail!("duress dispatch drifted real E120 (no-skip of real verify?)");
        }
        secure_log!("[S] [DURESS-PROV] step 11: E120 untouched ({}) by duress dispatch OK", e120_after_duress);

        // 12. Real PIN through the dispatch → real master.
        match crate::nsc::gated_unlock(se, &real_pin) {
            Ok(m) if m == real_master => {
                secure_log!("[S] [DURESS-PROV] step 12: gated_unlock(real) → real master OK");
            }
            Ok(_) => fail!("gated_unlock(real) returned wrong master (not real)"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] gated_unlock(real) err {:?}", e); fail!("gated_unlock(real) failed"); }
        }

        // 13. Wrong PIN through the dispatch → rejected.
        let wrong_pin: [u8; 8] = *b"55555555";
        match crate::nsc::gated_unlock(se, &wrong_pin) {
            Err(_) => { secure_log!("[S] [DURESS-PROV] step 13: gated_unlock(wrong) rejected OK"); }
            Ok(_) => fail!("gated_unlock(wrong) unexpectedly succeeded"),
        }

        // 14. Recovery: real PIN still works after a wrong + a duress unlock.
        let _ = crate::hw::flash::pin_attempts_reset();
        match crate::nsc::gated_unlock(se, &real_pin) {
            Ok(m) if m == real_master => { secure_log!("[S] [DURESS-PROV] step 14: real unlock recovers after wrong+duress OK"); }
            Ok(_) => fail!("step 14 real unlock wrong master"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] step 14 err {:?}", e); fail!("step 14 real unlock failed"); }
        }

        // ===== P2(b): post-wipe re-provision recoverability =====
        // The recovery path a coerced/locked-out user hits: a wipe
        // (factory_reset_admin) followed by a fresh setup. Re-provision
        // with a DIFFERENT decoy entropy + duress PIN (the mnemonic-change
        // case) and prove the decoy is fully recoverable — i.e. the
        // surviving OPTIGA duress-OID metadata + the Conf(E140) rewrite
        // path don't brick re-provisioning.
        secure_log!("[S] [DURESS-PROV] step 15: factory_reset_admin (wipe both chips)");
        if se.factory_reset_admin().is_err() {
            fail!("factory_reset_admin (P2b wipe) failed");
        }
        if se.is_provisioned() { fail!("real wallet still provisioned after wipe"); }
        secure_log!("[S] [DURESS-PROV] step 15: wipe OK, real wallet gone");

        // Re-provision real (same fixtures) + decoy (NEW fixtures).
        let decoy_entropy2: [u8; 32] = [0x3c; 32];
        let duress_pin2: [u8; 8] = *b"77777777";
        let decoy_master2 = crypto::kdf(b"sphincs-master", &decoy_entropy2, 0);
        let (dsk2, decoy_vk2) = crypto::derive_keypair_from_entropy(&decoy_entropy2);
        drop(dsk2);
        let decoy_bvk2 = crypto::derive_bootstrap_vk_from_entropy(&decoy_entropy2);

        if se.provision(&real_entropy, &real_master, &real_vk, &real_bvk, &real_pin).is_err() {
            fail!("real re-provision after wipe failed");
        }
        if se.provision_duress(&decoy_entropy2, &decoy_master2, &decoy_vk2, &decoy_bvk2, &duress_pin2).is_err() {
            fail!("decoy re-provision after wipe failed (P2b brick — duress OIDs not recoverable)");
        }
        secure_log!("[S] [DURESS-PROV] step 16: re-provisioned real + NEW decoy after wipe OK");

        // 17. Both provisioned again.
        if !se.is_provisioned() { fail!("real not provisioned after re-provision"); }
        if !se.duress_is_provisioned() { fail!("duress not provisioned after re-provision"); }
        secure_log!("[S] [DURESS-PROV] step 17: both provisioned again OK");

        // 18. Decoy recoverable with the NEW duress PIN → reconstructs to NEW entropy.
        let half_o2 = match se.optiga.duress_read_half(&duress_pin2) {
            Ok((h, _)) => h,
            Err(e) => { secure_log!("[S] [DURESS-PROV] re-read optiga err {:?}", e); fail!("OPTIGA decoy re-read after wipe failed"); }
        };
        let half_e2 = match se.se050.duress_read_half(&duress_pin2) {
            Ok(h) => h,
            Err(e) => { secure_log!("[S] [DURESS-PROV] re-read se050 err {:?}", e); fail!("SE050 decoy re-read after wipe failed"); }
        };
        let mut recon2 = [0u8; 32];
        for i in 0..32 { recon2[i] = half_o2[i] ^ half_e2[i]; }
        if recon2 != decoy_entropy2 { fail!("re-provisioned decoy reconstructs to wrong entropy"); }
        secure_log!("[S] [DURESS-PROV] step 18: re-provisioned decoy reconstructs (NEW entropy) OK");

        // 19. gated_unlock dispatch works on the re-provisioned wallets.
        let _ = crate::hw::flash::pin_attempts_reset();
        match crate::nsc::gated_unlock(se, &duress_pin2) {
            Ok(m) if m == decoy_master2 => { secure_log!("[S] [DURESS-PROV] step 19: gated_unlock(new duress) → new decoy OK"); }
            Ok(_) => fail!("step 19 duress wrong master"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] step 19 duress err {:?}", e); fail!("step 19 gated_unlock(duress) failed"); }
        }
        match crate::nsc::gated_unlock(se, &real_pin) {
            Ok(m) if m == real_master => { secure_log!("[S] [DURESS-PROV] step 19: gated_unlock(real) → real OK"); }
            Ok(_) => fail!("step 19 real wrong master"),
            Err(e) => { secure_log!("[S] [DURESS-PROV] step 19 real err {:?}", e); fail!("step 19 gated_unlock(real) failed"); }
        }
        secure_log!("[S] [DURESS-PROV] step 19: post-wipe re-provision FULLY recoverable OK");

        // ===== P5: wipe-on-duress dispatch (non-interactive) =====
        // Bypass the wizard, program the wipe-mode flag directly, then
        // prove gated_unlock(duress) WIPES both chips + returns PinLocked
        // (instead of opening the decoy). This is the security-critical
        // half of P5; the dialog that sets the flag is interactive-only.
        if hw::flash::arm_duress_wipe_mode().is_err() { fail!("arm_duress_wipe_mode failed"); }
        if !hw::flash::is_duress_wipe_mode() { fail!("is_duress_wipe_mode false after arm"); }
        secure_log!("[S] [DURESS-PROV] step 20: wipe-on-duress flag armed OK");

        let _ = crate::hw::flash::pin_attempts_reset();
        match crate::nsc::gated_unlock(se, &duress_pin2) {
            Err(crate::secure_element::UnlockError::PinLocked) => {
                secure_log!("[S] [DURESS-PROV] step 21: gated_unlock(duress) in wipe mode → PinLocked OK");
            }
            Err(e) => { secure_log!("[S] [DURESS-PROV] step 21 wrong err {:?}", e); fail!("wipe-mode duress should return PinLocked"); }
            Ok(_) => fail!("wipe-mode duress unexpectedly returned a master (no wipe!)"),
        }
        // The duress-wipe must have wiped the real wallet too.
        if se.is_provisioned() { fail!("device still provisioned after wipe-on-duress"); }
        secure_log!("[S] [DURESS-PROV] step 22: device wiped by wipe-on-duress OK");

        secure_log!("[S] [DURESS-PROV] === DURESS PROVISION VALIDATION: PASS ===");
        ui::show_status("DURESS-PROV", "PASS");
        cortex_m_semihosting::debug::exit(cortex_m_semihosting::debug::EXIT_SUCCESS);
        loop { cortex_m::asm::wfi(); }
    }

    // ---- Combined MCU + OPTIGA E120 + SE050 sync + desync recovery ----
    // Exercises the full PIN lockout pipeline under `dual-se +
    // optiga-hw-counter` and asserts MCU page-124 stays in lockstep
    // with OPTIGA E120.current at every step. Also drives the system
    // into two deliberate desync states — MCU-ahead and OPTIGA-ahead —
    // and verifies a correct-PIN `gated_unlock` recovers both counters
    // back to (0, 0).
    //
    // Phases:
    //   0. pin_attempts_reset → fresh MCU counter. Provision via
    //      DualSecureElement::provision (idempotent: hw-counter skip
    //      fires if E120 already correctly provisioned from a prior
    //      run of this test on the same chip).
    //   1. Normal sync: gated_unlock(wrong) → MCU=1, E120=1;
    //      gated_unlock(correct) → MCU=0, E120=0.
    //   2. MCU-ahead desync: direct pin_attempts_bump() × 2 → MCU=2
    //      without touching OPTIGA. Correct PIN recovers (bump to 3,
    //      SE.unlock succeeds, reset to 0). Assert MCU=0, E120=0.
    //   3. OPTIGA-ahead desync: direct se.optiga.unlock(wrong) bumps
    //      E120 via LUC without incrementing MCU (bypasses gated_unlock).
    //      Correct PIN recovers identically.
    //
    // Uses the real production OIDs on both chips — destroys any
    // existing wallet state. Does NOT imply optiga-lock-operational.
    //
    // Triggered by: make pin-gate-hw-counter-e2e
    #[cfg(feature = "pin-gate-hw-counter-e2e")]
    unsafe {
        use crate::secure_element::{UnlockError, WalletStore};

        ui::show_status("SYNC", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        let test_entropy: [u8; 32] = [0x42; 32];
        let test_master = crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xCC; 32];
        let test_bvk: [u8; 32] = [0xDD; 32];
        let correct_pin: [u8; 8] = *b"00000000";
        let wrong_pin: [u8; 8] = *b"99999999";

        macro_rules! fail { ($msg:expr) => {{
            secure_log!("[S] [E2E-SYNC] FAIL: {}", $msg);
            ui::show_status("SYNC", "FAIL");
            loop { cortex_m::asm::wfi(); }
        }}}

        // Read MCU + E120 + SE050 cached remaining and assert they match
        // expected values. Macro (not closure) so the borrow of `se`
        // ends at each expansion site — we need `se` free for the
        // `gated_unlock` and `provision` calls that follow.
        //
        // SE050 cache semantics: the `remaining` field is a display
        // mirror of the chip's UserID counter (see `se050/mod.rs`
        // doc comment on the field). Within a single boot it advances
        // in lockstep with the chip, so asserting its value here is a
        // valid regression guard against accidental skip-SE050
        // refactors. Across reboots the cache resets to `MAX_ATTEMPTS`
        // while the chip retains state — not exercised by this test.
        macro_rules! check_sync {
            ($phase:expr, $mcu_exp:expr, $e120_exp:expr, $se050_rem_exp:expr) => {{
                let mcu = hw::flash::pin_attempts_read();
                let e120_curr = se.optiga.read_hw_pin_counter()
                    .map(|(c, _)| c)
                    .unwrap_or(u32::MAX);
                let se050_rem = {
                    use crate::secure_element::WalletStore;
                    se.se050.remaining_attempts()
                };
                secure_log!(
                    "[SYNC] {}: MCU={} E120.curr={} SE050.rem={} (expected MCU={} E120={} SE050.rem={})",
                    $phase, mcu, e120_curr, se050_rem,
                    $mcu_exp, $e120_exp, $se050_rem_exp
                );
                (mcu == $mcu_exp)
                    && (e120_curr == $e120_exp)
                    && (se050_rem == $se050_rem_exp)
            }};
        }

        // ── Phase 0: known blank state + provision ─────────────────
        // `pin_attempts_reset` clears the MCU page-124 counter. We
        // DON'T call `check_sync!` pre-provision because
        // `read_hw_pin_counter` needs an initialised OPTIGA app
        // session, which `provision` installs via `store_objects`.
        let _ = hw::flash::pin_attempts_reset();
        let pre = hw::flash::pin_attempts_read();
        if pre != 0 {
            secure_log!("[S] [E2E-SYNC] phase-0 pre-provision: MCU={} expected 0", pre);
            fail!("phase-0 pre-provision MCU counter");
        }
        secure_log!("[S] [E2E-SYNC] phase-0 pre-provision: MCU=0 OK");

        // Pre-clean SE050 user objects — prior test runs in this chip
        // may have left stale ENTROPY/VK/BOOTSTRAP_VK. SE050's
        // `store_objects` is idempotent (skips writes when objects
        // already exist); without the wipe, `half_e` on SE050 from a
        // prior run survives while OPTIGA gets a fresh random
        // `half_o` → `half_o XOR half_e ≠ test_entropy` and
        // DualSecureElement::unlock's consistency check returns
        // InternalError. `factory_reset_admin` is best-effort: if the
        // chip was never admin-provisioned, the unauthenticated
        // iterative_wipe sweep runs instead; if everything is already
        // clean, both paths no-op. OPTIGA's side of factory_reset_admin
        // wipes user data OIDs but preserves F1D0 metadata + E120 LUC
        // binding (those are metadata-level, re-provision overwrites
        // the data only).
        secure_log!("[S] [E2E-SYNC] phase-0: pre-cleaning SE050 user objects");
        let _ = se.factory_reset_admin();

        if let Err(_e) = se.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &correct_pin) {
            fail!("phase-0: provision returned error");
        }
        let max_rem = sphincs_tz_shared::MAX_ATTEMPTS;

        // `provision_hw_pin_counter` is idempotent — if E120's metadata
        // is already Change=Auto(F1D0), Exec=ALW (set by a prior run)
        // it early-returns without rewriting the counter data. So E120
        // may carry forward a non-zero `current` from a previous
        // failed test run. Fire one clean correct-PIN unlock here to
        // force `reset_hw_pin_counter` on the success path: this snaps
        // MCU page-124 (erase on success), E120 (firmware-side reset),
        // and SE050 chip+cache (auto-reset on successful auth) to
        // their full-budget state regardless of prior history.
        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-0 reset-via-unlock: got {:?}", other.as_ref().err());
                fail!("phase-0 reset-via-unlock rejected");
            }
        }
        if !check_sync!("phase-0 post-provision", 0u8, 0u32, max_rem) {
            fail!("phase-0 post-provision: counters not clean after reset-via-unlock");
        }
        secure_log!("[S] [E2E-SYNC] phase-0: provisioned, counters clean");

        // ── Phase 1: normal wrong → correct cycle, all three counters advance ───
        match nsc::gated_unlock(se, &wrong_pin) {
            Err(UnlockError::PinIncorrect) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-1 wrong: expected PinIncorrect, got {:?}", other.as_ref().err());
                fail!("phase-1 wrong PIN not rejected");
            }
        }
        if !check_sync!("phase-1 after wrong", 1u8, 1u32, max_rem - 1) {
            fail!("phase-1: MCU / E120 / SE050 not all +1 after wrong PIN");
        }

        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-1 correct: got {:?}", other.as_ref().err());
                fail!("phase-1 correct PIN rejected");
            }
        }
        if !check_sync!("phase-1 after correct", 0u8, 0u32, max_rem) {
            fail!("phase-1: counters did not reset on correct PIN");
        }
        secure_log!("[S] [E2E-SYNC] phase-1: normal sync OK");

        // ── Phase 2: MCU-ahead desync recovery ─────────────────────
        // Direct MCU bumps leave OPTIGA and SE050 untouched — simulates
        // a flash corruption / partial-write scenario where the MCU
        // counter got ahead of silicon.
        hw::flash::pin_attempts_bump().ok();
        hw::flash::pin_attempts_bump().ok();
        if !check_sync!("phase-2 desync (MCU ahead)", 2u8, 0u32, max_rem) {
            fail!("phase-2 desync setup failed");
        }

        // Correct PIN: MCU pre-check passes, MCU bumps, SE.unlock
        // succeeds, firmware resets E120 to 0, SE050 chip auto-resets
        // on successful auth (cache mirrors), MCU resets to 0.
        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-2 recovery: got {:?}", other.as_ref().err());
                fail!("phase-2 recovery PIN rejected");
            }
        }
        if !check_sync!("phase-2 after recovery", 0u8, 0u32, max_rem) {
            fail!("phase-2: counters not synced after recovery");
        }
        secure_log!("[S] [E2E-SYNC] phase-2: MCU-ahead desync recovered OK");

        // ── Phase 3: OPTIGA-ahead desync recovery ──────────────────
        // Direct call to se.optiga.unlock bypasses gated_unlock, so
        // MCU stays at 0 and SE050 stays untouched while LUC silicon
        // bumps E120. Simulates an attacker with PBS who can replay
        // HMAC-verify APDUs directly against the OPTIGA chip without
        // touching MCU flash or triggering SE050 auth.
        match se.optiga.unlock(&wrong_pin) {
            Err(UnlockError::PinIncorrect) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-3 direct-wrong: got {:?}", other.as_ref().err());
                fail!("phase-3 direct optiga.unlock did not reject");
            }
        }
        if !check_sync!("phase-3 desync (OPTIGA ahead)", 0u8, 1u32, max_rem) {
            fail!("phase-3 desync setup: E120 did not bump");
        }

        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-3 recovery: got {:?}", other.as_ref().err());
                fail!("phase-3 recovery PIN rejected");
            }
        }
        if !check_sync!("phase-3 after recovery", 0u8, 0u32, max_rem) {
            fail!("phase-3: counters not synced after recovery");
        }
        secure_log!("[S] [E2E-SYNC] phase-3: OPTIGA-ahead desync recovered OK");

        // ── Phase 4: SE050-ahead desync recovery ────────────────────
        // Direct call to se.se050.unlock bypasses gated_unlock and
        // never touches OPTIGA — so MCU stays at 0, E120 stays at 0,
        // but SE050's silicon UserID counter decrements by 1 and the
        // driver's `self.remaining` cache mirrors. Simulates an
        // attacker with SCP03 session keys who replays VerifySession
        // UserID APDUs against the SE050 chip directly.
        //
        // Recovery path: gated_unlock(correct_pin) → MCU pre-bump,
        // DualSecureElement::unlock runs OPTIGA first (HMAC succeeds,
        // firmware resets E120 to 0) then SE050 (UserID auth succeeds,
        // chip auto-resets its attempt counter to max_attempts, cache
        // follows). MCU resets to 0 on success. All three back to
        // their full-budget state.
        match se.se050.unlock(&wrong_pin) {
            Err(UnlockError::PinIncorrect) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-4 direct-wrong: got {:?}", other.as_ref().err());
                fail!("phase-4 direct se050.unlock did not reject");
            }
        }
        if !check_sync!("phase-4 desync (SE050 ahead)", 0u8, 0u32, max_rem - 1) {
            fail!("phase-4 desync setup: SE050 remaining did not decrement");
        }

        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-4 recovery: got {:?}", other.as_ref().err());
                fail!("phase-4 recovery PIN rejected");
            }
        }
        if !check_sync!("phase-4 after recovery", 0u8, 0u32, max_rem) {
            fail!("phase-4: counters not synced after recovery");
        }
        secure_log!("[S] [E2E-SYNC] phase-4: SE050-ahead desync recovered OK");

        // ── Phase 5: boot-time SE050 cache re-sync across simulated reboot ──
        // Proves that `sync_remaining_with_mcu` correctly ratchets the
        // SE050 (and OPTIGA) software mirror down to match the MCU
        // page-124 counter after a power cycle, so a post-lockout-window
        // reboot doesn't over-report remaining attempts. Real reboot is
        // simulated by manually writing `MAX_ATTEMPTS` back into the
        // drivers' cache fields after 3 failed unlocks — the same
        // stale-high state a genuine boot would produce via
        // `const fn new()` initialisation.
        for _ in 0..3 {
            match nsc::gated_unlock(se, &wrong_pin) {
                Err(UnlockError::PinIncorrect) => {}
                other => {
                    secure_log!("[S] [E2E-SYNC] phase-5 wrong: got {:?}", other.as_ref().err());
                    fail!("phase-5 wrong PIN not rejected");
                }
            }
        }
        if !check_sync!("phase-5 pre-reboot-sim", 3u8, 3u32, max_rem - 3) {
            fail!("phase-5 pre-reboot-sim: counters not at (3,3,7)");
        }

        // Simulate reboot: force both SE driver caches back to MAX,
        // which is exactly what `const fn new()` yields on power-on.
        // MCU page-124 counter (durable) still reads 3.
        se.optiga._e2e_force_remaining_to_max();
        se.se050._e2e_force_remaining_to_max();
        {
            use crate::secure_element::WalletStore;
            let rem_before_sync = se.remaining_attempts();
            secure_log!(
                "[SYNC] phase-5 post-reboot-sim (caches stale): SE-pair min={} (expected {})",
                rem_before_sync, max_rem
            );
            if rem_before_sync != max_rem {
                fail!("phase-5: cache reset simulation failed — min should be MAX");
            }

            let used = hw::flash::pin_attempts_read();
            se.sync_remaining_with_mcu(used);

            let rem_after_sync = se.remaining_attempts();
            secure_log!(
                "[SYNC] phase-5 after sync(used={}): SE-pair min={} (expected {})",
                used, rem_after_sync, max_rem - 3
            );
            if rem_after_sync != max_rem - 3 {
                fail!("phase-5: sync_remaining_with_mcu did not ratchet down to 7");
            }
        }

        // Recover to clean state for any subsequent run.
        match nsc::gated_unlock(se, &correct_pin) {
            Ok(_) => {}
            other => {
                secure_log!("[S] [E2E-SYNC] phase-5 recovery: got {:?}", other.as_ref().err());
                fail!("phase-5 recovery PIN rejected");
            }
        }
        if !check_sync!("phase-5 after recovery", 0u8, 0u32, max_rem) {
            fail!("phase-5: counters not synced after recovery");
        }
        secure_log!("[S] [E2E-SYNC] phase-5: post-reboot cache re-sync OK");

        secure_log!("[S] [E2E-SYNC] SYNC+DESYNC ROUNDTRIP: PASS");
        ui::show_status("SYNC", "PASS");
        loop { cortex_m::asm::wfi(); }
    }

    // ==================== pin-gate-wipe-e2e ====================
    //
    // End-to-end validation of the MCU-MAX-ATTEMPTS → lockout-wipe
    // dispatch path under real dual-SE silicon. Burns 10 wrong PINs
    // through `gated_unlock` until all three counters saturate
    // (MCU=10, E120=10, SE050 UserID chip-locked), then fires
    // `factory_reset_admin` + `pin_attempts_reset` — the same steps
    // `trigger_lockout_wipe` in `cmd_request_unlock` performs — and
    // verifies the device is back to an unprovisioned state that a
    // fresh first-boot wizard could re-provision.
    //
    // What this proves that `pin-gate-e2e` and `pin-gate-hw-counter-e2e`
    // do not:
    //   - MCU counter reaching MAX_ATTEMPTS in a combined flow where
    //     the SE050 UserID silicon-lock fires on the same attempt.
    //   - `factory_reset_admin` successfully deletes a silicon-locked
    //     user UserID via the admin UserID (max_attempts=0 unlimited).
    //   - Post-wipe MCU counter erase works.
    //   - Re-provision after wipe succeeds (recovery proven).
    //
    // Destructive but recoverable:
    //   - SE050 user UserID locks at attempt 10, then gets deleted by
    //     `factory_reset_admin` and re-created with a fresh attempt
    //     budget during re-provision.
    //   - OPTIGA E120 goes from 0 → 10. Still inside the 32 limit, so
    //     no lockout at the E120 layer. Reset to 0 by `reset_hw_pin_counter`
    //     on the next correct PIN after re-provision.
    //   - MCU page 124 takes 10 QW-programs + 1 erase per run. Well
    //     inside flash wear budget.
    //
    // Triggered by: make pin-gate-wipe-e2e
    #[cfg(feature = "pin-gate-wipe-e2e")]
    unsafe {
        use crate::secure_element::{UnlockError, WalletStore};

        ui::show_status("WIPE e2e", "start");
        let se = &mut *core::ptr::addr_of_mut!(SE);

        let test_entropy: [u8; 32] = [0x42; 32];
        let test_master = crypto::kdf(b"sphincs-master", &test_entropy, 0);
        let test_vk: [u8; 32] = [0xCC; 32];
        let test_bvk: [u8; 32] = [0xDD; 32];
        let correct_pin: [u8; 8] = *b"00000000";
        let wrong_pin: [u8; 8] = *b"99999999";

        macro_rules! wfail { ($msg:expr) => {{
            secure_log!("[S] [E2E-WIPE] FAIL: {}", $msg);
            ui::show_status("WIPE", "FAIL");
            loop { cortex_m::asm::wfi(); }
        }}}

        // ── Setup: pre-clean + provision ──
        //
        // We deliberately do NOT do a clean-unlock here to verify the
        // post-provision XOR-consistency. On a chip that survived
        // several prior test runs, SE050's `store_objects` idempotency
        // (skip-if-exists for ENTROPY_OBJ / VK_OBJ / BOOTSTRAP_VK_OBJ)
        // means a partially-failed earlier `factory_reset_admin` can
        // leave stale `half_e` on SE050. Combined with a fresh random
        // `half_o` on OPTIGA, `half_o XOR half_e ≠ test_entropy` and
        // the unlock fails CRITICAL.
        //
        // For the wipe test specifically this doesn't matter: the
        // 10 wrong-PIN iterations below exercise the **failure path**
        // of SE050 auth, which decrements the chip counter without
        // involving the XOR check. What we actually need to prove is
        // (a) counters advance in lockstep on wrong PIN even with
        // stale half_e, (b) the wipe-dispatch path fires at MAX, and
        // (c) post-wipe re-provision + clean-unlock works on a truly
        // clean chip. (c) is where the XOR check must pass, and the
        // post-wipe state guarantees it.
        let _ = hw::flash::pin_attempts_reset();
        secure_log!("[S] [E2E-WIPE] setup: pre-cleaning SE050 user objects");
        let _ = se.factory_reset_admin();

        if let Err(_e) = se.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &correct_pin) {
            wfail!("setup: provision returned error");
        }

        // Capture initial counters — these may not be (0, 0, MAX) if
        // prior runs left non-zero silicon state on E120 / SE050.
        // Iteration deltas below compare relative to these baselines.
        let mcu_init = hw::flash::pin_attempts_read();
        let e120_init = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let se050_init = se.se050.remaining_attempts();
        secure_log!(
            "[SYNC] wipe-e2e setup-init: MCU={} E120.curr={} SE050.rem={} (baseline)",
            mcu_init, e120_init, se050_init
        );
        if mcu_init != 0 {
            wfail!("setup: pin_attempts_reset did not zero MCU counter");
        }

        // ── Burn MAX_ATTEMPTS wrong PINs through gated_unlock ──
        // The 10th failed attempt leaves SE050's UserID silicon-locked
        // (chip decrements from 1 → 0, permalock).
        let max = sphincs_tz_shared::MAX_ATTEMPTS;
        for i in 1..=max {
            match nsc::gated_unlock(se, &wrong_pin) {
                Err(UnlockError::PinIncorrect) => {}
                Err(UnlockError::PinLocked) => {
                    secure_log!("[S] [E2E-WIPE] iter {}: early PinLocked (MCU already at MAX?)", i);
                    wfail!("early PinLocked before full burn");
                }
                other => {
                    secure_log!("[S] [E2E-WIPE] iter {}: unexpected {:?}", i, other.as_ref().err());
                    wfail!("wrong PIN did not return PinIncorrect");
                }
            }
            let mcu = hw::flash::pin_attempts_read();
            let e120 = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
            let se050 = se.se050.remaining_attempts();
            secure_log!(
                "[E2E-WIPE] iter {}/{}: MCU={} E120.curr={} SE050.rem={}",
                i, max, mcu, e120, se050
            );
            // Delta checks: MCU counts up from 0; E120 advances by +1
            // per iter (LUC silicon-side) regardless of starting value;
            // SE050 counts down from its initial, saturating at 0.
            let expected_mcu = i as u8;
            let expected_e120 = e120_init + i as u32;
            let expected_se050 = se050_init.saturating_sub(i as u8);
            if mcu != expected_mcu || e120 != expected_e120 || se050 != expected_se050 {
                secure_log!(
                    "[E2E-WIPE] iter {}: mismatch expected MCU={} E120={} SE050={}",
                    i, expected_mcu, expected_e120, expected_se050
                );
                wfail!("counter delta mismatch during burn");
            }
        }

        // ── Verify counters saturated at expected values ──
        let mcu_end = hw::flash::pin_attempts_read();
        let e120_end = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        let se050_end = se.se050.remaining_attempts();
        let expected_e120_end = e120_init + max as u32;
        secure_log!(
            "[SYNC] wipe-e2e post-burn: MCU={} E120.curr={} SE050.rem={} (expected {}, {}, 0)",
            mcu_end, e120_end, se050_end, max, expected_e120_end
        );
        if mcu_end != max || e120_end != expected_e120_end || se050_end != 0 {
            wfail!("post-burn: counters did not saturate");
        }

        // ── Verify gated_unlock now gates via MCU pre-check ──
        // 11th attempt should short-circuit: pre_count >= MAX → PinLocked
        // without touching either SE.
        match nsc::gated_unlock(se, &correct_pin) {
            Err(UnlockError::PinLocked) => {}
            other => {
                secure_log!("[S] [E2E-WIPE] post-burn gate: got {:?}", other.as_ref().err());
                wfail!("post-burn gate did not return PinLocked");
            }
        }
        secure_log!("[S] [E2E-WIPE] MCU pre-check lockout gate OK");

        // ── Fire the wipe (mirror of cmd_request_unlock::trigger_lockout_wipe) ──
        ui::show_status("WIPING", "do not power off");
        secure_log!("[S] [E2E-WIPE] invoking factory_reset_admin");
        if let Err(e) = se.factory_reset_admin() {
            secure_log!("[S] [E2E-WIPE] factory_reset_admin FAILED: {:?}", e);
            wfail!("factory_reset_admin error");
        }
        let _ = hw::flash::pin_attempts_reset();
        nsc::zeroize_sensitive_state();

        // ── Verify wiped state ──
        let mcu_post = hw::flash::pin_attempts_read();
        if mcu_post != 0 {
            secure_log!("[S] [E2E-WIPE] MCU counter not erased: {}", mcu_post);
            wfail!("MCU counter not zero after wipe");
        }
        secure_log!("[S] [E2E-WIPE] MCU counter erased OK");

        // E120 must also have been reset by the Trezor-parity transient-
        // auth path inside `factory_reset`. Without it, E120 carries over
        // at `expected_e120_end` (baseline + MAX_ATTEMPTS) and multi-wipe
        // cycles eventually saturate the silicon LUC counter at
        // HW_PIN_CTR_LIMIT → soft-brick DoS. A post-wipe value of 0 proves
        // the transient-auth reset ran and succeeded.
        let e120_post = se.optiga.read_hw_pin_counter().map(|(c, _)| c).unwrap_or(u32::MAX);
        secure_log!(
            "[SYNC] wipe-e2e post-wipe E120: {} (expected 0, pre-wipe was {})",
            e120_post, expected_e120_end
        );
        if e120_post != 0 {
            wfail!("E120 not reset by transient-auth path during factory_reset");
        }
        secure_log!("[S] [E2E-WIPE] E120 counter reset via transient-auth OK");

        // ── Recovery proof: re-provision and do one clean unlock ──
        if let Err(_e) = se.provision(&test_entropy, &test_master, &test_vk, &test_bvk, &correct_pin) {
            wfail!("post-wipe re-provision FAILED");
        }
        if nsc::gated_unlock(se, &correct_pin).is_err() {
            wfail!("post-wipe unlock FAILED");
        }
        let se050_recovered = se.se050.remaining_attempts();
        secure_log!(
            "[SYNC] wipe-e2e post-recovery: MCU=0 E120=0 SE050.rem={} (expected {})",
            se050_recovered, max
        );
        if se050_recovered != max {
            wfail!("post-recovery: SE050 UserID budget not restored");
        }

        secure_log!("[S] [E2E-WIPE] WIPE+RECOVERY ROUNDTRIP: PASS");
        ui::show_status("WIPE", "PASS");
        loop { cortex_m::asm::wfi(); }
    }

    // ==================== wipe-for-wizard ====================
    //
    // One-shot developer wipe target. Not a test — just nukes every
    // wallet-side piece of state so the next cold boot lands in the
    // first-boot wizard with a clean slate. Intended for the "change
    // my dev PIN" / "iterate on the provisioning flow" workflow,
    // where `make factory-reset` (which also mass-erases the firmware
    // and forces a re-flash) is heavier than needed.
    //
    // What this wipes:
    //   - OPTIGA user OIDs (F1D0 AuthRef / F1D1 Entropy / F1D2 Master /
    //     F1D3 VK / F1D4 BootstrapVK / F1E1 Counter) via
    //     `factory_reset()` on the Conf(E140) shielded-connection
    //     path. Inherits the Trezor-parity E120 transient-auth reset
    //     so the silicon LUC counter returns to 0.
    //   - SE050 user objects (ENTROPY_OBJ / VK_OBJ / BOOTSTRAP_VK_OBJ
    //     / user UserID) + admin UserID self-delete via
    //     `factory_reset_admin()`. This path also erases page 125
    //     (admin PIN slot) conditionally, i.e. only if the chip
    //     confirms the admin UserID is actually gone post-wipe — so
    //     a partial wipe leaves the flash PIN intact for the next
    //     boot's resume retry.
    //   - MCU page 124 (PIN-attempt counter) via
    //     `hw::flash::pin_attempts_reset()`.
    //   - SRAM secret caches via `nsc::zeroize_sensitive_state()`.
    //
    // What this deliberately preserves (required for re-provisioning):
    //   - STM32 OTP master (one-way by nature, survives any wipe).
    //   - OPTIGA E140 PBS — derived from OTP master, re-established by
    //     the shielded-connection handshake on the next boot. Stays
    //     at LcsO=Creation.
    //   - Every OPTIGA OID's metadata (Change / Read / Execute ACs).
    //     We rewrite the data to zero but leave metadata alone so the
    //     next `provision()` can write fresh data through the same
    //     Conf(E140) AC path.
    //   - LcsO=Creation on every OID — the non-negotiable development
    //     invariant. This target MUST NOT imply
    //     `optiga-lock-operational`; the feature definition in
    //     `Cargo.toml` enforces that.
    //   - The resident firmware image itself. Unlike `make
    //     factory-reset`, we don't mass-erase the STM32, so power-
    //     cycling the board is enough — no re-flash needed.
    //
    // Triggered by: `make wipe-for-wizard`
    //
    // Idempotency: this block checks the provisioned state of both
    // SEs first. Provisioned → wipe + show "WIPED" + halt so the
    // developer can intentionally power-cycle into a clean boot.
    // Unprovisioned → skip wipe entirely and fall through to the
    // normal main() flow, which triggers `run_first_boot_wizard()`
    // at line ~1745 (gated on `not(feature = "e2e-test")` — we use
    // `dev-testkey` here precisely to keep that branch live).
    //
    // The two-boot loop is:
    //   - Boot 1 (chip provisioned from prior state): wipe, halt.
    //     User power-cycles.
    //   - Boot 2 (chip now unprovisioned): skip wipe, fall through
    //     to the interactive wizard, user enters fresh seed + PIN.
    #[cfg(feature = "wipe-for-wizard")]
    unsafe {
        use crate::secure_element::WalletStore;

        let se = &mut *core::ptr::addr_of_mut!(SE);

        // "Needs wipe" = fully-provisioned chip OR chip with stranded
        // admin residue from an aborted prior wipe. The admin-residue
        // case matters because a previous partial wipe / provisioning
        // crash can leave ADMIN_WIPE_OBJ + policy-gated canaries on
        // chip while USERID_OBJ is gone — `is_provisioned()` only
        // checks USERID_OBJ, so a plain `if provisioned` check would
        // skip the wipe and fall through to the wizard, which would
        // then crash on the stranded canaries during
        // `policy_roundtrip_selftest`. Include `admin_exists()` in
        // the predicate so wipe-for-wizard self-heals that state too.
        let user_prov = se.is_provisioned();
        let admin_residue = se.se050.admin_exists();
        let needs_wipe = user_prov || admin_residue;
        secure_log!(
            "[S] [WIPE] predicate: user_provisioned={} admin_residue={} needs_wipe={}",
            user_prov, admin_residue, needs_wipe
        );

        if needs_wipe {
            ui::show_status("WIPE", "running...");
            secure_log!("[S] [WIPE] dispatching factory_reset_admin");

            if let Err(e) = se.factory_reset_admin() {
                secure_log!("[S] [WIPE] factory_reset_admin FAILED: {:?}", e);
                ui::show_status("WIPE FAIL", "see semihosting");
                loop { cortex_m::asm::wfi(); }
            }

            nsc::zeroize_sensitive_state();
        } else {
            secure_log!("[S] [WIPE] nothing to wipe (user + admin both absent)");
        }

        // Unconditional MCU-side flash cleanup. Runs in BOTH branches so
        // that a subsequent flash of the standalone firmware boots into
        // a pristine page-124/125 state — no stale wipe-in-progress flag
        // to trigger the boot-time wipe resume in the standalone build,
        // no stale attempt counter. factory_reset_admin erases page 125
        // conditionally (only if `admin_exists()` is false), which is
        // the right call inside the PIN-lockout recovery path, but
        // `wipe-for-wizard` is a developer target whose whole contract
        // is "leave the chip unambiguously wiped" — unconditional is
        // correct here, and erasing already-blank flash is idempotent.
        #[cfg(feature = "stm32u585")]
        {
            if let Err(e) = hw::flash::pin_attempts_reset() {
                secure_log!("[S] [WIPE] pin_attempts_reset FAILED: {:?}", e);
                ui::show_status("WIPE FAIL", "MCU page 124");
                loop { cortex_m::asm::wfi(); }
            }
            if let Err(e) = hw::flash::erase_admin_page() {
                secure_log!("[S] [WIPE] erase_admin_page FAILED: {:?}", e);
                ui::show_status("WIPE FAIL", "MCU page 125");
                loop { cortex_m::asm::wfi(); }
            }
        }

        secure_log!("[S] [WIPE] complete — halting. Flash the standalone firmware to continue.");
        ui::show_status("WIPED", "flash standalone");
        loop { cortex_m::asm::wfi(); }
    }

    #[cfg(feature = "optiga-admin-wipe-e2e")]
    unsafe {
        ui::show_status("OPTIGA wipe", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.run_admin_wipe_roundtrip() {
            Ok(()) => {
                secure_log!("[S] [E2E-OPTIGA-ADMIN] ADMIN-WIPE ROUNDTRIP: PASS");
                ui::show_status("OPTIGA wipe", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [E2E-OPTIGA-ADMIN] ADMIN-WIPE ROUNDTRIP: FAIL ({:?})", _e);
                ui::show_status("OPTIGA wipe", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- OPTIGA "nuclear" counter wipe (no shield, no OTP) ----
    // Forces F1E1 to RESET_SENTINEL (0xFF) so the next boot reports the
    // chip as unprovisioned. Pure-plaintext path: skips PBS setup and
    // the shielded connection entirely, so it works on boards where
    // OTP programming (and therefore PBS derivation) is blocked.
    //
    // Triggered by: make optiga-factory-reset-hw
    #[cfg(feature = "optiga-nuclear-reset")]
    unsafe {
        ui::show_status("OPTIGA wipe", "nuclear...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.nuclear_reset_counter() {
            Ok(()) => {
                secure_log!("[S] [NUCLEAR-RESET] F1E1 = RESET_SENTINEL — PASS");
                ui::show_status("OPTIGA wipe", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [NUCLEAR-RESET] FAIL ({:?})", _e);
                ui::show_status("OPTIGA wipe", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- SE050 factory-reset roundtrip e2e test ----
    // Provisions a fresh test UserID + 2 gated data objects under a
    // known PIN, then exercises user_factory_reset and verifies all
    // three objects are gone. Reports PASS/FAIL via semihosting.
    // Uses test object IDs (0x7B07_xxxx) so it's repeatable on any chip.
    // Triggered by: make se050-reset-e2e
    #[cfg(feature = "se050-reset-e2e")]
    unsafe {
        ui::show_status("Reset e2e", "running...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        const TEST_PIN: &[u8] = b"e2etest!";
        match se.run_factory_reset_roundtrip(TEST_PIN) {
            Ok(()) => {
                secure_log!("[S] [E2E] FACTORY-RESET ROUNDTRIP: PASS");
                ui::show_status("Reset e2e", "PASS");
            }
            Err(_e) => {
                secure_log!("[S] [E2E] FACTORY-RESET ROUNDTRIP: FAIL ({:?})", _e);
                ui::show_status("Reset e2e", "FAIL");
            }
        }
        loop { cortex_m::asm::wfi(); }
    }

    // ---- e2e-test fast-path ----
    //
    // Skip the entire interactive seed wizard + PIN entry. Provision
    // deterministically with a fixed test mnemonic and PIN, then mark
    // PIN_VERIFIED true so the gateway is callable immediately. Every
    // confirm() / enter_pin() dialog is also short-circuited under
    // the same feature flag.
    #[cfg(feature = "e2e-test")]
    unsafe {
        use sphincs_tz_bip39::Mnemonic;
        secure_log!("[S][e2e] auto-provisioning with fixed test mnemonic");
        ui::show_status("e2e-test", "provisioning");

        // 24 BIP-39 words from a known test vector. Determined entirely
        // by this constant — restore on a clean device with these words
        // gives the same SLH-DSA keypair.
        const TEST_WORDS: [&str; 24] = [
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "abandon",
            "abandon", "abandon", "abandon", "abandon", "abandon", "art",
        ];
        let mnemonic = Mnemonic::from_words(&TEST_WORDS)
            .expect("e2e: fixed test mnemonic must parse");
        let pin: [u8; 8] = *b"00000000";

        // Use `addr_of_mut!` instead of `&mut SE` to avoid materialising a
        // raw mutable reference to a `static mut`. The single-threaded
        // boot sequence makes aliasing impossible by construction; this
        // is the same pattern the `nsc::cmd_*` handlers use.
        //
        // Pre-clean on `dual-se` hardware. SE050's `store_objects` is
        // idempotent (skips writes when objects already exist), so a
        // previous test run's stale admin/user UserID + gated data
        // would survive a bare `factory_reset_admin` if page 125's
        // admin PIN is blank (unauthenticated `iterative_wipe` can't
        // delete policy-gated objects). Mirror the full three-stage
        // cascade from `DualSecureElement::run_admin_wipe_roundtrip`
        // (admin-auth → user-PIN candidates → unauthenticated sweep)
        // so the test survives arbitrary prior-provisioning states.
        #[cfg(all(feature = "dual-se", feature = "stm32u585", not(feature = "e2e-skip-provision")))]
        {
            use zeroize::Zeroize;
            secure_log!("[S][e2e] dual-se pre-clean: cascade start");
            let se = &mut *core::ptr::addr_of_mut!(SE);

            let _ = se.optiga.factory_reset();

            // Admin-auth wipe via the v6 HUK-derived admin PIN
            // (`factory_reset_admin` → `secret_keys::se050_admin_pin`
            // → `derive_into_bhk` — BHK in a `bhk` build / DHUK / OTP-
            // legacy). The pre-v6 page-125 PIN slot is gone (no
            // `write_admin_pin`).
            let r = se.se050.factory_reset_admin();
            secure_log!("[S][e2e] dual-se pre-clean: factory_reset_admin → {:?}", r.as_ref().err());

            if se.se050.is_provisioned() {
                const PIN_CANDIDATES: &[&[u8]] = &[
                    b"00000000", // e2e-test fast-path default
                    b"dualwipe", // dual-se-admin-wipe-e2e
                    b"12345678",
                    b"11111111",
                ];
                for &pin in PIN_CANDIDATES {
                    let r = se.se050.user_factory_reset(pin);
                    secure_log!(
                        "[S][e2e] dual-se pre-clean: user_factory_reset({:?}) → {:?}",
                        core::str::from_utf8(pin).unwrap_or("?"),
                        r.as_ref().err(),
                    );
                    if r.is_ok() {
                        break;
                    }
                }
            }

            let _ = se.se050.iterative_wipe(None, None);

            // Conditional flash-page-125 erase so the next provision
            // generates a fresh admin PIN that matches a blank chip.
            // Safe only once SE050 confirms admin UserID is gone.
            if !se.se050.admin_exists() {
                let _ = crate::hw::flash::erase_admin_page();
            }

            secure_log!(
                "[S][e2e] dual-se pre-clean: OPTIGA.provisioned={} SE050.provisioned={}",
                se.optiga.is_provisioned(),
                se.se050.is_provisioned(),
            );
        }
        #[cfg(not(feature = "e2e-skip-provision"))]
        crypto::provision_from_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin, None);
        #[cfg(feature = "e2e-skip-provision")]
        {
            let _ = &mnemonic; // silence unused warning under this feature
            let _ = &pin;
            secure_log!("[S][e2e] e2e-skip-provision active: skipping provision_from_mnemonic (chip assumed already provisioned)");

            // Bring-up path: load PBS host-side from OTP and run the PRL
            // handshake against the already-provisioned E140 so we can
            // validate `shield::establish` in isolation, without touching
            // any F1Dx metadata.
            #[cfg(all(feature = "optiga-trust-m", not(feature = "dual-se"), feature = "stm32u585"))]
            {
                let se = &mut *core::ptr::addr_of_mut!(SE);
                if let Err(e) = se.init() {
                    secure_log!("[S][e2e] OPTIGA init FAILED: {:?}", e);
                } else if let Err(e) = se.load_pbs_from_otp() {
                    secure_log!("[S][e2e] load_pbs_from_otp FAILED: {:?}", e);
                } else if let Err(e) = se.ensure_shield() {
                    secure_log!("[S][e2e] ensure_shield FAILED: {:?}", e);
                } else {
                    secure_log!("[S][e2e] SHIELD UP — PRL handshake succeeded");
                }
            }
        }

        // `e2e-skip-unlock` halts the boot flow right after provisioning so
        // that `ensure_shield` never runs — which keeps the OPTIGA chip at
        // LcsO=Creation on E140 and rewriteable. Used for the Phase-A
        // hardware-validation target (`flash-hw-optiga-bringup-write-only`)
        // where we want to prove the PBS was written to the chip without
        // committing the irreversible LcsO=Operational bump.
        #[cfg(feature = "e2e-skip-unlock")]
        {
            secure_log!("[S][e2e] e2e-skip-unlock active: halting after provisioning");
            secure_log!("[S][e2e] PBS should now be in E140 at LcsO=Creation (still rewriteable)");
            loop {
                cortex_m::asm::wfi();
            }
        }

        // Normal e2e-test path: run the verify flow so MASTER_SECRET +
        // PIN_VERIFIED end up in the same state as a real unlock.
        //
        // Bypasses `nsc::gated_unlock` for the same reason as the
        // first-boot auto-unlock: PIN was just written to the chip
        // above; this is a test harness, not a user-facing entry
        // point. Going through the gate would burn a flash page
        // cycle per test run with no security benefit.
        #[cfg(not(feature = "e2e-skip-unlock"))]
        {
            ui::show_status("e2e-test", "unlock");
            match (&mut *core::ptr::addr_of_mut!(SE)).unlock(&pin) {
                Ok(master) => nsc::set_e2e_unlocked(master),
                Err(_e) => {
                    secure_log!("[S][e2e] unlock FAILED: {:?}", _e);
                    ui::show_status("e2e unlock", "FAIL");
                    loop { cortex_m::asm::wfi(); }
                }
            }
            secure_log!("[S][e2e] gateway pre-unlocked, ready for tests");
            ui::show_status("PQSigner OS", "Ready");
        }
    }

    // Provision on first boot only.
    #[cfg(not(feature = "e2e-test"))]
    unsafe {
        if !is_provisioned(&mut *core::ptr::addr_of_mut!(SE)) {
            secure_log!("[S] Unprovisioned — running first-boot wizard");
            let (mnemonic, mut pin) = run_first_boot_wizard();

            // §32 P4: optionally collect a duress (decoy) PIN — ONLY on
            // this unprovisioned first-boot path (never on the
            // already-provisioned unlock path below). Declined / exhausted
            // → None → a random decoy PIN is provisioned anyway
            // (always-provision preserves deniability).
            #[cfg(feature = "duress-pin")]
            let mut duress_pin = ui::seed_wizard::collect_duress_pin(&pin);
            #[cfg(not(feature = "duress-pin"))]
            let duress_pin: Option<[u8; sphincs_tz_shared::PIN_LEN]> = None;

            // §32 P5: if a duress PIN was set, ask whether a duress entry
            // should WIPE the device (vs the default: open the decoy).
            // Persist the choice BEFORE provisioning — a crash after
            // provision but before this write would silently downgrade
            // wipe→decoy. Blank flash = decoy (safe default); we only
            // ever 1→0 bit-clear here, so the wizard can only UPGRADE to
            // wipe (stale-decoy is the conservative fallback).
            #[cfg(feature = "duress-pin")]
            {
                if duress_pin.is_some() && ui::seed_wizard::choose_duress_wipe_mode() {
                    if hw::flash::arm_duress_wipe_mode().is_err() {
                        secure_log!("[S] [DURESS] arm_duress_wipe_mode FAILED — defaulting to decoy");
                    }
                }
            }

            // Debug-only: log the mnemonic and the resulting verifying key.
            // This is gated behind `debug-log` so production builds (which
            // omit that feature) leak nothing on the semihosting channel.
            // CT lookup (`Mnemonic::word_bytes` instead of `.words()`) per
            // the F-22 / F-27 hygiene migration — keeps the leaky
            // `WORDLIST[idx]` access pattern out of the source so a future
            // copy-paste can't inherit it.
            #[cfg(feature = "debug-log")]
            {
                use sphincs_tz_bip39::MAX_WORD_BYTES;
                secure_log!("[S] mnemonic (DEBUG):");
                for i in 0..sphincs_tz_bip39::WORD_COUNT {
                    let mut wb = [0u8; MAX_WORD_BYTES];
                    let wlen = mnemonic.word_bytes(i, &mut wb);
                    let s = ui::ascii_str(&wb[..wlen as usize]);
                    secure_log!("  {} {}", i + 1, s);
                }
            }

            ui::show_status("Provisioning", "...");

            crypto::provision_from_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin, duress_pin.as_ref());
            #[cfg(feature = "duress-pin")]
            {
                use zeroize::Zeroize;
                if let Some(ref mut dp) = duress_pin {
                    dp.zeroize();
                    crate::fi::zeroize_barrier();
                }
            }
            // Admin-wipe credential + canary selftest are installed
            // inside SE050's provision() for any stm32u585 build that
            // includes SE050 (standalone or dual-SE). A selftest failure
            // propagates as SeError::InternalError; crypto::
            // provision_from_mnemonic panics on failure, which is the
            // desired "don't ship a wallet that can't recover from PIN
            // lockout" behaviour.

            // Debug-only: log the verifying key the SE just stored.
            #[cfg(feature = "debug-log")]
            {
                let mut vk_buf = [0u8; 64];
                if let Ok(_) =
                    (&mut *core::ptr::addr_of_mut!(SE)).read_vk(&mut vk_buf)
                {
                    secure_log!("[S] vk (DEBUG):");
                    for chunk in vk_buf[..32].chunks(8) {
                        secure_log!(
                            "  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            chunk[0], chunk[1], chunk[2], chunk[3],
                            chunk[4], chunk[5], chunk[6], chunk[7]
                        );
                    }
                }
            }

            // Auto-unlock with the PIN the user just entered so the device
            // is immediately usable (caches entropy blob + VK for signing).
            //
            // Bypasses `nsc::gated_unlock` — the PIN was just written to
            // the SE's auth object a few lines above (store_objects), so
            // verification is guaranteed correct. Going through the
            // MCU-counter gate would cost a flash page erase per
            // provision for no security gain (can't be an attack path:
            // we control both the PIN and the PIN target in the same
            // call).
            match (&mut *core::ptr::addr_of_mut!(SE)).unlock(&pin) {
                Ok(master) => {
                    nsc::unlock_with_master(master);
                    secure_log!("[S] Auto-unlocked after provisioning");
                }
                Err(_) => {
                    secure_log!("[S] WARNING: auto-unlock failed after provision");
                }
            }

            // mnemonic drops here → indices zeroed.
            use zeroize::Zeroize;
            pin.zeroize();
            crate::fi::zeroize_barrier();
            ui::show_status("PQSigner OS", "Ready");
            secure_log!("[S] Provisioned + unlocked");
        } else {
            secure_log!("[S] Device already provisioned — requesting PIN unlock");

            // Prompt for PIN and unlock via the SE / MACD path.
            // Loop until the user enters the correct PIN or the device
            // locks out (SE050: 9 attempts, MACD: 13 attempts).
            use ui::pin_entry::{enter_pin, PinEntryResult};
            use zeroize::Zeroize;

            loop {
                ui::show_status("Enter PIN", "to unlock");
                let mut pin = match enter_pin() {
                    PinEntryResult::Pin(p) => p,
                    PinEntryResult::Cancelled | PinEntryResult::IdleWipe => {
                        ui::show_status("Locked", "");
                        continue;
                    }
                    PinEntryResult::Mismatch => continue,
                };

                ui::show_status("Verifying...", "");

                // Route through the MCU-counter-gated unlock so every
                // user-typed PIN burns the same MCU budget, regardless
                // of entry point (boot-interactive here, PendSV re-
                // unlock, CMD_REQUEST_UNLOCK from NS). See
                // `nsc::gated_unlock` docstring for the full rationale.
                let se_ref = &mut *core::ptr::addr_of_mut!(SE);
                let result = nsc::gated_unlock(se_ref, &pin);

                pin.zeroize();
                crate::fi::zeroize_barrier();

                match result {
                    Ok(master) => {
                        nsc::unlock_with_master(master);
                        ui::show_status("PQSigner OS", "Ready");
                        secure_log!("[S] PIN verified — unlocked");
                        break;
                    }
                    Err(secure_element::UnlockError::PinLocked) => {
                        ui::show_status("PIN locked", "factory reset");
                        secure_log!("[S] PIN locked out");
                        break;
                    }
                    Err(_) => {
                        ui::show_status("Wrong PIN", "try again");
                        secure_log!("[S] Wrong PIN");
                    }
                }
            }
        }
    }

    // Initialize PKA hardware accelerator for BLS12-381 field arithmetic.
    // Preloads the Fp modulus into PKA RAM (stays resident for all operations).
    #[cfg(feature = "pka-accel")]
    unsafe {
        hw::pka::init();
        secure_log!("[S] PKA initialized (BLS12-381 Fp accelerated)");
    }

    // Initialize USB OTG FS hardware (clocks, GPIO, UCPD) when targeting
    // real hardware with USB enabled.  Must run after rcc::init() and
    // sau::init() (GTZC has marked USB OTG as NS by this point).
    #[cfg(all(feature = "stm32u585", feature = "usb"))]
    unsafe {
        hw::usb_hw::init();
        secure_log!("[S] USB OTG FS hardware initialized (GPIO, UCPD, VDDUSB)");
    }

    // The mailbox transport (QEMU) needs its CMD/RESULT/DONE words
    // cleared before SysTick starts polling. On STM32U585 the transport
    // is CMSE veneers — there's nothing to initialise, NS calls land
    // synchronously via the SG stubs.
    #[cfg(not(feature = "stm32u585"))]
    nsc::init_gateway();
    setup_systick();
    secure_log!("[S] Gateway ready");

    ui::show_status("PQSigner OS", "Ready");

    // Enable the DWT cycle counter so the non-secure world can measure
    // timing (e2e benchmarks, companion latency logging).  The counter
    // runs at the CPU core clock (160 MHz on STM32U585, simulated on QEMU).
    //
    // DEMCR.TRCENA enables the DWT unit; DWT_CTRL.CYCCNTENA starts the
    // free-running 32-bit cycle counter; DWT_LAR unlocks write access.
    // DSCSR.CDS=1 is needed for NS to read DWT on TrustZone parts.
    ARCH.demcr.set_bits(1 << 24);       // TRCENA — enable trace unit
    ARCH.dwt_lar.write(0xC5AC_CE55);    // unlock DWT for writes
    ARCH.dwt_cyccnt.write(0);           // reset cycle counter
    ARCH.dwt_ctrl.set_bits(1);          // CYCCNTENA — start counter

    secure_log!("[S] Booting non-secure world...");
    // SAFETY: `boot_ns::boot` performs the irreducibly-unsafe TrustZone
    // branch to the NS reset vector (BLXNS via the linker-provided NS
    // image at `NS_FLASH_BASE`). This is the documented hand-off into
    // the non-secure world; no S-world state survives past it.
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cfg(not(test))]
#[cortex_m_rt::exception]
fn SysTick() {
    timeout::tick();

    // Drain TAMP_SR flags. Cheap fast path (1 MMIO read when no flag
    // set); on a trigger, log the reason and clear. NEVER halts and
    // NEVER wipes — see `hw::tamp` module header §1. Compiles to a
    // no-op without the `tamp` feature.
    //
    // Under `tamp-irq` the IRQ handler does the same work directly,
    // so polling is redundant — but harmless and idempotent. Leave
    // it in as belt-and-suspenders so a future IER mis-mask doesn't
    // silently lose tamper events.
    #[cfg(all(feature = "stm32u585", feature = "tamp"))]
    hw::tamp::poll();

    // Re-randomise the consumption-mask PWM duty so the mask-pin power
    // signature stays uncorrelated with crypto work happening elsewhere
    // on the die. Cost: 2 RNG byte reads + 1 modulo + 1 MMIO write per
    // tick. Compiles to a no-op without the `consumption-mask` feature.
    #[cfg(all(feature = "stm32u585", feature = "consumption-mask"))]
    hw::consumption_mask::randomize();

    // Background idle wipe: if PIN state is unlocked and the inactivity
    // timer has fired with no command in flight, wipe.
    //
    // HIGH-7 fix: don't wipe when a long-running gateway handler is
    // busy — it's holding stack-local copies of master_secret /
    // entropy / slot_master_entropy and they would disagree with
    // the freshly-zeroed BSS copy, leaving the handler to sign a
    // transaction for a session the user no longer is unlocked for.
    // Let the handler observe `timeout::is_idle()` at its own
    // blocking-dialog check points (which `confirm` and `enter_pin`
    // already do via the idle callback to `wait_button`).
    if timeout::is_idle() && nsc::is_unlocked() && !nsc::handler_is_busy() {
        nsc::zeroize_sensitive_state();

        // Trigger PendSV to run the re-unlock flow outside the ISR.
        // PendSV has the lowest priority so it won't block SysTick.
        // PendSV drives the PIN entry screen directly — no intermediate
        // "(idle wipe)" status page, which could otherwise get stuck
        // visible if PendSV is delayed.
        #[cfg(feature = "stm32u585")]
        ARCH.icsr.write(1 << 28); // PENDSVSET
    }

    // QEMU-only: drain the shared-memory mailbox. On STM32U585 the
    // gateway is driven synchronously by CMSE veneers, so SysTick only
    // services the timeout/idle-wipe bookkeeping above.
    #[cfg(not(feature = "stm32u585"))]
    nsc::poll_gateway();
}

/// Catch-all device-IRQ handler.
///
/// `cortex-m-rt` routes every unmasked NVIC IRQ that doesn't have a
/// named `#[interrupt]` handler to `DefaultHandler`, passing the IRQ
/// number as `irqn`. PQSigner has no PAC crate, so this is the only
/// peripheral-IRQ entry point — every `tamp-irq`-style feature that
/// arms an NVIC line MUST land its dispatch arm here.
///
/// Today only TAMP (IRQn=2) is wired up, gated behind `tamp-irq`.
/// Any other IRQ that fires lands in the unmatched arm — that's a
/// bug because PQSigner does not currently `NVIC_EnableIRQ` anything
/// other than TAMP. Logging the offender is more useful than silent
/// drop or HardFault.
///
/// **Safety contract for future contributors:** before unmasking any
/// new NVIC line (`NVIC.ISER0..3` writes), add a matching dispatch
/// arm here. Otherwise the IRQ silently routes to "unexpected" and
/// the handler stalls in WFE — easy to misdiagnose as a hang.
#[cfg(all(not(test), feature = "stm32u585"))]
#[cortex_m_rt::exception]
unsafe fn DefaultHandler(irqn: i16) {
    match irqn {
        #[cfg(feature = "tamp-irq")]
        2 => unsafe { hw::tamp::on_tamp_irq() }, // TAMP_IRQn

        // GTZC1 illegal-access — NS tried to touch a SECURE
        // peripheral. Logs the offender + bumps a counter; the
        // gateway test harness (CMD_TZIC_STATUS) reads the
        // counter to confirm enforcement is working.
        8 => unsafe { hw::tzic::on_violation() }, // GTZC_IRQn

        // Unmatched — log + halt in WFE. NOT a panic so the host
        // semihosting backend gets a chance to flush the log line
        // before the chip stops responding.
        _ => {
            secure_log!("[IRQ] unexpected irqn={} — halting", irqn);
            loop {
                cortex_m::asm::wfe();
            }
        }
    }
}

#[cfg(all(not(test), feature = "stm32u585"))]
static mut PENDSV_IN_FLIGHT: u32 = 0;

/// PendSV handler — runs the PIN re-unlock flow after an idle wipe.
///
/// Triggered by SysTick when it detects idle timeout. Runs at the lowest
/// exception priority so it doesn't block SysTick ticks or CMSE veneers.
/// The blocking PIN entry UI is safe here.
///
/// HIGH-8 partial fix: add a re-entry guard — SysTick can re-pend
/// PendSV while PendSV is already running the PIN loop (e.g. when
/// the user is between button presses and SysTick fires another
/// idle tick). Re-entering this handler is undefined on Cortex-M33,
/// so the guard returns immediately on nested entry.
#[cfg(all(not(test), feature = "stm32u585"))]
#[cortex_m_rt::exception]
fn PendSV() {
    unsafe {
        if core::ptr::read_volatile(core::ptr::addr_of!(PENDSV_IN_FLIGHT)) != 0 {
            return;
        }
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDSV_IN_FLIGHT), 1);
    }

    // Only run if we're actually locked (avoids spurious re-entry)
    if nsc::is_unlocked() {
        unsafe {
            core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDSV_IN_FLIGHT), 0);
        }
        return;
    }

    unsafe {
        use ui::pin_entry::{enter_pin, PinEntryResult};
        use zeroize::Zeroize;

        loop {
            ui::show_status("Enter PIN", "to unlock");

            timeout::reset_activity();

            let mut pin = match enter_pin() {
                PinEntryResult::Pin(p) => p,
                PinEntryResult::Cancelled | PinEntryResult::IdleWipe => {
                    continue;
                }
                PinEntryResult::Mismatch => continue,
            };

            ui::show_status("Verifying...", "");

            // Route through the MCU-counter-gated unlock so re-unlock
            // after idle wipe respects the same lockout budget as a
            // fresh CMD_REQUEST_UNLOCK. Without this, a PendSV-reached
            // re-unlock could brute-force the PIN bypassing page 126.
            let se = &mut *core::ptr::addr_of_mut!(SE);
            let result = nsc::gated_unlock(se, &pin);

            pin.zeroize();
            crate::fi::zeroize_barrier();

            match result {
                Ok(master) => {
                    nsc::unlock_with_master(master);
                    timeout::reset_activity();
                    ui::show_status("PQSigner OS", "Ready");
                    secure_log!("[S] Re-unlocked after idle wipe");
                    break;
                }
                Err(secure_element::UnlockError::PinLocked) => {
                    ui::show_status("PIN locked", "factory reset");
                    secure_log!("[S] PIN locked out");
                    break;
                }
                Err(_) => {
                    ui::show_status("Wrong PIN", "try again");
                    secure_log!("[S] Wrong PIN on re-unlock");
                }
            }
        }

        // Clear the re-entry guard on normal loop exit.
        core::ptr::write_volatile(core::ptr::addr_of_mut!(PENDSV_IN_FLIGHT), 0);
    }
}

/// Custom panic handler: zeroizes all sensitive state before halting.
/// This ensures secrets don't persist in RAM after a crash.
#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    nsc::zeroize_sensitive_state();

    #[cfg(feature = "debug-log")]
    {
        // Best-effort debug output — only if a debugger is actually attached.
        if ARCH.dhcsr.read() & 1 != 0 {
            cortex_m_semihosting::hprintln!("[S] PANIC: {}", _info);
        }
    }

    loop {
        // WFI instead of BKPT — BKPT without a debugger causes HardFault.
        cortex_m::asm::wfi();
    }
}
