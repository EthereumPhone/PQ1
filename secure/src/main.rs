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
            if unsafe { core::ptr::read_volatile(0xE000_EDF0 as *const u32) } & 1 != 0 {
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

// Hardware-dependent modules: gated out in test builds so `cargo test`
// compiles only the pure logic on x86_64.
#[cfg(not(test))]
mod boot_ns;
mod crypto;
#[cfg(not(test))]
mod db_roots;
#[cfg(not(test))]
mod erc20;
#[cfg(all(not(feature = "stm32u585"), not(test)))]
mod host_rng;
#[cfg(all(any(feature = "pka-accel", feature = "stm32u585"), not(test)))]
mod hw;
#[cfg(not(test))]
mod reset_cause;
#[cfg(not(test))]
mod nsc;
#[cfg(not(test))]
mod rng;
mod pin;
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

#[cfg(not(test))]
const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
#[cfg(not(test))]
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
#[cfg(not(test))]
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

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

/// SysTick reload value for ~1 ms tick.
/// QEMU mps2-an505: 25 MHz → 25_000.  STM32U585: set dynamically from rcc::init().
#[cfg(all(not(feature = "stm32u585"), not(test)))]
const SYSTICK_RELOAD: u32 = 25_000;
#[cfg(all(feature = "stm32u585", not(test)))]
static mut SYSTICK_RELOAD: u32 = 16_000; // overwritten by rcc::init() result

#[cfg(not(test))]
fn setup_systick() {
    unsafe {
        core::ptr::write_volatile(SYST_RVR, SYSTICK_RELOAD);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0x07);
    }
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
        let pin = match enter_pin_with_confirm() {
            PinEntryResult::Pin(p) => p,
            PinEntryResult::Mismatch => {
                ui::show_status("PINs differ", "retry...");
                continue;
            }
            PinEntryResult::Cancelled => {
                ui::show_status("Cancelled", "retry...");
                continue;
            }
            PinEntryResult::IdleWipe => {
                ui::show_status("Idle", "retry...");
                continue;
            }
        };

        // ---- 2. New or restore? ----
        let mnemonic = match choose_setup_mode() {
            WizardChoice::NewWallet => {
                // Pull 32 bytes of entropy from the host CSPRNG (semihosting
                // /dev/urandom on QEMU; will be the on-board hardware RNG on
                // STM32U585 — see docs/architecture.md "Porting to STM32U585").
                let mut entropy = [0u8; 32];
                if rng::fill(&mut entropy).is_err() {
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("RNG failed", "retry...");
                    continue;
                }
                let m = sphincs_tz_bip39::Mnemonic::from_entropy(&entropy);
                entropy.zeroize();

                // Show the 24 words paginated; require the user to walk to
                // the last page before they can confirm.
                if show_mnemonic(&m) != WizardResult::Confirmed {
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Cancelled", "retry...");
                    continue;
                }
                // Spot-check 3 random words against what they wrote down.
                if verify_mnemonic(&m) != WizardResult::Confirmed {
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Verify fail", "retry...");
                    continue;
                }
                m
            }
            WizardChoice::Restore => match enter_mnemonic() {
                Ok(m) => m,
                Err(WizardError::Cancelled) => {
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Cancelled", "retry...");
                    continue;
                }
                Err(WizardError::IdleWipe) => {
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("Idle", "retry...");
                    continue;
                }
            },
            WizardChoice::Cancelled | WizardChoice::IdleWipe => {
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
        hw::rng::init();
        // When SE050 is also active, its i2c_hw::init() configures I2C1 at
        // 400 kHz after SAU init — skip the OLED's 100 kHz init to avoid
        // a redundant peripheral reset.  SSD1306 supports 400 kHz.
        #[cfg(all(feature = "ui-oled", not(feature = "se050")))]
        hw::i2c::init(mhz);
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
        unsafe { nsc::zeroize_sensitive_state(); }
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
    secure_log!("[S] SAU + MPC configured");

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
        if hw::flash::is_wipe_armed() {
            secure_log!("[S] Wipe-in-progress flag set — resuming factory reset");
            ui::show_status("WIPING", "resuming from interrupt");
            let _ = (&mut *core::ptr::addr_of_mut!(SE)).factory_reset_admin();
            // factory_reset_admin ends with erase_admin_page() which clears
            // both the PIN and the flag, so next boot sees an unprovisioned
            // state and falls through to the first-boot wizard.
            ui::show_status("WALLET WIPED", "restore from seed");
        }
    }

    // ---- SE050 factory reset (iterative wipe) ----
    // Actually wipes user objects via ReadIDList + DeleteSecureObject.
    // Two authentication attempts to catch objects gated by either of
    // the two UserIDs this firmware has ever provisioned:
    //   - 0x7B06_0000 : current dual-SE / standalone SE050 UserID
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
        const USERIDS: &[u32] = &[0x7B06_0000, 0x7B00_2000];
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
        crypto::provision_from_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);

        // Run the verify path so MASTER_SECRET + PIN_VERIFIED end up
        // in the same state as a real unlock.
        match (&mut *core::ptr::addr_of_mut!(SE)).unlock(&pin) {
            Ok(master) => nsc::set_e2e_unlocked(master),
            Err(_) => panic!("e2e: verify_pin failed after provision"),
        }
        secure_log!("[S][e2e] gateway pre-unlocked, ready for tests");
    }

    // Provision on first boot only.
    #[cfg(not(feature = "e2e-test"))]
    unsafe {
        if !is_provisioned(&mut *core::ptr::addr_of_mut!(SE)) {
            secure_log!("[S] Unprovisioned — running first-boot wizard");
            let (mnemonic, mut pin) = run_first_boot_wizard();

            // Debug-only: log the mnemonic and the resulting verifying key.
            // This is gated behind `debug-log` so production builds (which
            // omit that feature) leak nothing on the semihosting channel.
            #[cfg(feature = "debug-log")]
            {
                secure_log!("[S] mnemonic (DEBUG):");
                for (i, w) in mnemonic.words().enumerate() {
                    secure_log!("  {} {}", i + 1, w);
                }
            }

            ui::show_status("Provisioning", "...");

            crypto::provision_from_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);
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

                let result = (&mut *core::ptr::addr_of_mut!(SE)).unlock(&pin);

                pin.zeroize();

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
    unsafe {
        const DEMCR: *mut u32 = 0xE000_EDFC as *mut u32;
        const DWT_LAR: *mut u32 = 0xE000_1FB0 as *mut u32;
        const DWT_CTRL: *mut u32 = 0xE000_1000 as *mut u32;
        const DWT_CYCCNT: *mut u32 = 0xE000_1004 as *mut u32;
        // Enable trace unit
        core::ptr::write_volatile(DEMCR, core::ptr::read_volatile(DEMCR) | (1 << 24));
        // Unlock DWT for writes
        core::ptr::write_volatile(DWT_LAR, 0xC5AC_CE55);
        // Reset and start cycle counter
        core::ptr::write_volatile(DWT_CYCCNT, 0);
        core::ptr::write_volatile(DWT_CTRL, core::ptr::read_volatile(DWT_CTRL) | 1);
    }

    secure_log!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cfg(not(test))]
#[cortex_m_rt::exception]
fn SysTick() {
    timeout::tick();

    // Background idle wipe: if PIN state is unlocked and the inactivity
    // timer has fired with no command in flight, wipe.
    //
    // HIGH-7 fix: don't wipe when a long-running gateway handler is
    // busy — it's holding stack-local copies of master_secret /
    // entropy / jardin_master_entropy and they would disagree with
    // the freshly-zeroed BSS copy, leaving the handler to sign a
    // transaction for a session the user no longer is unlocked for.
    // Let the handler observe `timeout::is_idle()` at its own
    // blocking-dialog check points (which `confirm` and `enter_pin`
    // already do via the idle callback to `wait_button`).
    if timeout::is_idle() && nsc::is_unlocked() && !nsc::handler_is_busy() {
        nsc::zeroize_sensitive_state();
        ui::show_status("Locked", "(idle wipe)");

        // Trigger PendSV to run the re-unlock flow outside the ISR.
        // PendSV has the lowest priority so it won't block SysTick.
        #[cfg(feature = "stm32u585")]
        unsafe {
            const ICSR: *mut u32 = 0xE000_ED04 as *mut u32;
            core::ptr::write_volatile(ICSR, 1 << 28); // PENDSVSET
        }
    }

    // QEMU-only: drain the shared-memory mailbox. On STM32U585 the
    // gateway is driven synchronously by CMSE veneers, so SysTick only
    // services the timeout/idle-wipe bookkeeping above.
    #[cfg(not(feature = "stm32u585"))]
    nsc::poll_gateway();
}

/// PendSV re-entry guard. Lives at module scope so `addr_of_mut!`
/// returns the raw pointer LLVM expects; declaring it inside
/// PendSV() gives a function-local binding whose address syntax is
/// different.
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
            ui::show_status("Press button", "to unlock");

            // Wait for any button press before showing PIN entry
            let _ = ui::input().wait_button(&mut timeout::idle_check);

            timeout::reset_activity();

            let mut pin = match enter_pin() {
                PinEntryResult::Pin(p) => p,
                PinEntryResult::Cancelled | PinEntryResult::IdleWipe => {
                    ui::show_status("Locked", "");
                    continue;
                }
                PinEntryResult::Mismatch => continue,
            };

            ui::show_status("Verifying...", "");

            let result = (&mut *core::ptr::addr_of_mut!(SE)).unlock(&pin);

            pin.zeroize();

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
        if unsafe { core::ptr::read_volatile(0xE000_EDF0 as *const u32) } & 1 != 0 {
            cortex_m_semihosting::hprintln!("[S] PANIC: {}", _info);
        }
    }

    loop {
        // WFI instead of BKPT — BKPT without a debugger causes HardFault.
        cortex_m::asm::wfi();
    }
}
