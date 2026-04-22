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
#[cfg(not(test))]
mod names;
#[cfg(all(not(feature = "stm32u585"), not(test)))]
mod host_rng;
#[cfg(all(any(feature = "pka-accel", feature = "stm32u585"), not(test)))]
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
mod nsc;
#[cfg(not(test))]
mod rng;
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
                // Pull 32 bytes of entropy from the host CSPRNG (semihosting
                // /dev/urandom on QEMU; will be the on-board hardware RNG on
                // STM32U585 — see docs/architecture.md "Porting to STM32U585").
                let mut entropy = [0u8; 32];
                if rng::fill(&mut entropy).is_err() {
                    secure_log!("[S] wizard: rng::fill FAILED");
                    let mut p = pin;
                    p.zeroize();
                    ui::show_status("RNG failed", "retry...");
                    continue;
                }
                secure_log!("[S] wizard: entropy ok, showing mnemonic");
                let m = sphincs_tz_bip39::Mnemonic::from_entropy(&entropy);
                entropy.zeroize();

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
        // RNG init is deferred until AFTER sau::init() / GTZC config —
        // accessing RNG_S (0x520C_0800) before the TZSC has assigned the
        // peripheral's security attribute can stall the AHB2 fabric on
        // STM32U5.
        #[cfg(feature = "hw-sha256")]
        hw::hash::init_clock();
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

    // RNG init now that GTZC/TZSC has assigned RNG as a secure peripheral
    // and the SAU is live. Safe to touch 0x520C_0800 from the secure world.
    #[cfg(feature = "stm32u585")]
    unsafe {
        hw::rng::init();
        secure_log!("[S] TRNG initialised");
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
    // Three authentication attempts to catch objects gated by every
    // UserID this firmware lineage has ever provisioned:
    //   - 0x7B0E_0000 : current dual-SE / standalone SE050 UserID (v5)
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
        const USERIDS: &[u32] = &[0x7B0E_0000, 0x7B06_0000, 0x7B00_2000];
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
    // chips (OPTIGA F1D0..F1D4 + F1E1; SE050 0x7B0E_xxxx — v5, the
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
        // to page 125 QW0 inside `write_admin_pin` (during provision)
        // returned PROGERR silently. The test just needs the MCU
        // counter cleared; SE cleanup is the provision path's job.
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

        if se.is_provisioned() {
            ui::show_status("WIPE", "running...");
            secure_log!("[S] [WIPE] chip provisioned — dispatching factory_reset_admin");

            if let Err(e) = se.factory_reset_admin() {
                secure_log!("[S] [WIPE] factory_reset_admin FAILED: {:?}", e);
                ui::show_status("WIPE FAIL", "see semihosting");
                loop { cortex_m::asm::wfi(); }
            }

            // MCU-side PIN counter erase. SE050 side owns page 125 via
            // its conditional erase inside factory_reset_admin; we only
            // touch page 124 here.
            #[cfg(feature = "stm32u585")]
            if let Err(e) = hw::flash::pin_attempts_reset() {
                secure_log!("[S] [WIPE] pin_attempts_reset FAILED: {:?}", e);
                ui::show_status("WIPE FAIL", "MCU page 124");
                loop { cortex_m::asm::wfi(); }
            }

            nsc::zeroize_sensitive_state();

            secure_log!("[S] [WIPE] complete — power-cycle to start wizard");
            ui::show_status("WIPED", "power-cycle me");
            loop { cortex_m::asm::wfi(); }
        } else {
            secure_log!("[S] [WIPE] chip already unprovisioned — skipping wipe, falling through to wizard");
            // Fall through to the normal main() flow. The first-boot
            // wizard block at line ~1745 will run because the chip
            // reports unprovisioned.
        }
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
        #[cfg(not(feature = "e2e-skip-provision"))]
        crypto::provision_from_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);
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

        // Trigger PendSV to run the re-unlock flow outside the ISR.
        // PendSV has the lowest priority so it won't block SysTick.
        // PendSV drives the PIN entry screen directly — no intermediate
        // "(idle wipe)" status page, which could otherwise get stuck
        // visible if PendSV is delayed.
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
