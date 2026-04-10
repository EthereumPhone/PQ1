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
#[cfg(all(feature = "debug-log", not(test)))]
macro_rules! secure_log {
    ($($arg:tt)*) => { cortex_m_semihosting::hprintln!($($arg)*) };
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
#[cfg(not(test))]
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
mod nsc;
#[cfg(not(test))]
mod rng;
#[cfg(not(test))]
mod pin;
#[cfg(not(test))]
mod sau;
#[cfg(not(test))]
mod secure_element;
#[cfg(all(feature = "se050", not(test)))]
mod se050;
#[cfg(all(feature = "tropic01-se", not(test)))]
mod semihosting_spi;
#[cfg(not(test))]
mod timeout;
#[cfg(all(feature = "tropic01-se", not(test)))]
mod tropic01_se;
#[cfg(not(test))]
mod ui;
#[cfg(not(test))]
mod zk;

// Everything below this point is firmware infrastructure — gated out in
// host test builds where only the pure aa/tx logic is exercised.
#[cfg(all(not(test), not(feature = "se050")))]
use crypto::{RMEM_BOOTSTRAP_VK, RMEM_ENCRYPTED_ENTROPY, RMEM_PIN_STATE, RMEM_VERIFYING_KEY};
#[cfg(all(not(test), not(feature = "se050")))]
use secure_element::{MockSecureElement, SecureElement};

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

// Global mock SE (used when mock-se feature is active)
#[cfg(all(feature = "mock-se", not(test)))]
static mut SE: MockSecureElement = MockSecureElement::new();

// Global TROPIC01 SE (used when tropic01-se feature is active)
#[cfg(all(feature = "tropic01-se", not(test)))]
static mut SE: tropic01_se::Tropic01SecureElement = tropic01_se::Tropic01SecureElement::new();

// Global SE050 SE (used when se050 feature is active)
#[cfg(all(feature = "se050", not(test)))]
static mut SE: se050::Se050 = se050::Se050::new();

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

/// Returns true if the secure element already holds an encrypted seed,
/// PIN state, and verifying key. Used to skip re-provisioning on every boot.
#[cfg(all(not(test), not(feature = "se050")))]
fn is_provisioned(se: &mut impl SecureElement) -> bool {
    let mut buf = [0u8; 128];
    se.r_mem_read(RMEM_ENCRYPTED_ENTROPY, &mut buf).is_ok()
        && se.r_mem_read(RMEM_PIN_STATE, &mut buf).is_ok()
        && se.r_mem_read(RMEM_VERIFYING_KEY, &mut buf).is_ok()
        // Bootstrap VK may not exist on older provisioned devices;
        // don't require it for backward compat. New provisions always
        // write it (see crypto::provision_with_mnemonic).
}

/// SE050 provisioning check: UserID object existence means provisioned.
#[cfg(all(not(test), feature = "se050"))]
fn is_provisioned(_se: &mut se050::Se050) -> bool {
    unsafe {
        let se = &mut *core::ptr::addr_of_mut!(SE);
        se.is_provisioned()
    }
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

    sau::init();
    secure_log!("[S] SAU + MPC configured");

    // Initialize I2C1 for SE050 secure element BEFORE any SE operations.
    // Must come after rcc::init() (clocks) and sau::init() (peripherals).
    #[cfg(all(feature = "stm32u585", feature = "se050"))]
    unsafe {
        hw::i2c_hw::init();
        secure_log!("[S] I2C1 initialized for SE050 (PB8/PB9, 400 kHz)");
    }

    ui::init();
    secure_log!("[S] UI initialized");

    // ---- SE050 factory reset ----
    // Wipes all user objects (UserID, entropy, VKs) then halts.
    // Triggered by: make se050-reset
    #[cfg(feature = "se050-factory-reset")]
    unsafe {
        ui::show_status("SE050 reset", "...");
        let se = &mut *core::ptr::addr_of_mut!(SE);
        match se.factory_reset() {
            Ok(()) => {
                secure_log!("[S] SE050 factory reset OK");
                ui::show_status("SE050 reset", "OK - reflash");
            }
            Err(_e) => {
                secure_log!("[S] SE050 factory reset FAILED");
                ui::show_status("SE050 reset", "FAILED");
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
        #[cfg(feature = "se050")]
        crypto::provision_with_mnemonic_se050(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);
        #[cfg(not(feature = "se050"))]
        crypto::provision_with_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);

        // Run the verify path so MASTER_SECRET + PIN_VERIFIED end up
        // in the same state as a real unlock.
        #[cfg(feature = "se050")]
        match crypto::verify_pin_se050(&mut *core::ptr::addr_of_mut!(SE), &pin) {
            Ok(master) => nsc::set_e2e_unlocked(master),
            Err(_) => panic!("e2e: verify_pin failed after provision"),
        }
        #[cfg(not(feature = "se050"))]
        match crate::pin::verify_pin(&mut *core::ptr::addr_of_mut!(SE), &pin) {
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
                cortex_m_semihosting::hprintln!("[S] mnemonic (DEBUG):");
                for (i, w) in mnemonic.words().enumerate() {
                    cortex_m_semihosting::hprintln!("  {} {}", i + 1, w);
                }
            }

            ui::show_status("Provisioning", "...");

            #[cfg(feature = "mock-se")]
            crypto::provision_with_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);

            #[cfg(feature = "se050")]
            crypto::provision_with_mnemonic_se050(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);

            #[cfg(feature = "tropic01-se")]
            (&mut *core::ptr::addr_of_mut!(SE))
                .provision(&mnemonic, &pin, sphincs_tz_shared::MAX_ATTEMPTS)
                .expect("TROPIC01 provisioning failed");

            // Debug-only: log the verifying key the SE just stored.
            // SE050 objects require an authenticated session to read, so
            // we skip this readback for the se050 feature.
            #[cfg(all(feature = "debug-log", not(feature = "se050")))]
            {
                let mut vk_buf = [0u8; 64];
                if let Ok(_) =
                    (&mut *core::ptr::addr_of_mut!(SE)).r_mem_read(crypto::RMEM_VERIFYING_KEY, &mut vk_buf)
                {
                    cortex_m_semihosting::hprintln!("[S] vk (DEBUG):");
                    for chunk in vk_buf[..32].chunks(8) {
                        cortex_m_semihosting::hprintln!(
                            "  {:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}",
                            chunk[0], chunk[1], chunk[2], chunk[3],
                            chunk[4], chunk[5], chunk[6], chunk[7]
                        );
                    }
                }
            }

            // Auto-unlock with the PIN the user just entered so the device
            // is immediately usable (caches entropy blob + VK for signing).
            #[cfg(feature = "se050")]
            match crypto::verify_pin_se050(&mut *core::ptr::addr_of_mut!(SE), &pin) {
                Ok(master) => {
                    nsc::unlock_with_master(master);
                    secure_log!("[S] Auto-unlocked after provisioning");
                }
                Err(_) => secure_log!("[S] WARNING: auto-unlock failed after provision"),
            }
            #[cfg(not(feature = "se050"))]
            match crate::pin::verify_pin(&mut *core::ptr::addr_of_mut!(SE), &pin) {
                Ok(master) => {
                    nsc::unlock_with_master(master);
                    secure_log!("[S] Auto-unlocked after provisioning");
                }
                Err(_) => secure_log!("[S] WARNING: auto-unlock failed after provision"),
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

                #[cfg(feature = "se050")]
                let result = crypto::verify_pin_se050(
                    &mut *core::ptr::addr_of_mut!(SE), &pin,
                );
                #[cfg(not(feature = "se050"))]
                let result = crate::pin::verify_pin(
                    &mut *core::ptr::addr_of_mut!(SE), &pin,
                );

                pin.zeroize();

                match result {
                    Ok(master) => {
                        nsc::unlock_with_master(master);
                        ui::show_status("PQSigner OS", "Ready");
                        secure_log!("[S] PIN verified — unlocked");
                        break;
                    }
                    Err(sphincs_tz_shared::NscStatus::PinLocked) => {
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

    secure_log!("[S] Booting non-secure world...");
    unsafe { boot_ns::boot(NS_FLASH_BASE) }
}

#[cfg(not(test))]
#[cortex_m_rt::exception]
fn SysTick() {
    timeout::tick();

    // Background idle wipe: if PIN state is unlocked and the inactivity
    // timer has fired with no command in flight, wipe.
    if timeout::is_idle() && nsc::is_unlocked() {
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

/// PendSV handler — runs the PIN re-unlock flow after an idle wipe.
///
/// Triggered by SysTick when it detects idle timeout. Runs at the lowest
/// exception priority so it doesn't block SysTick ticks or CMSE veneers.
/// The blocking PIN entry UI is safe here.
#[cfg(all(not(test), feature = "stm32u585"))]
#[cortex_m_rt::exception]
fn PendSV() {
    // Only run if we're actually locked (avoids spurious re-entry)
    if nsc::is_unlocked() {
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

            #[cfg(feature = "se050")]
            let result = crypto::verify_pin_se050(
                &mut *core::ptr::addr_of_mut!(SE), &pin,
            );
            #[cfg(not(feature = "se050"))]
            let result = crate::pin::verify_pin(
                &mut *core::ptr::addr_of_mut!(SE), &pin,
            );

            pin.zeroize();

            match result {
                Ok(master) => {
                    nsc::unlock_with_master(master);
                    timeout::reset_activity();
                    ui::show_status("PQSigner OS", "Ready");
                    secure_log!("[S] Re-unlocked after idle wipe");
                    break;
                }
                Err(sphincs_tz_shared::NscStatus::PinLocked) => {
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
        // Best-effort debug output -- may fail if semihosting is unavailable
        cortex_m_semihosting::hprintln!("[S] PANIC: {}", _info);
    }

    loop {
        cortex_m::asm::bkpt();
    }
}
