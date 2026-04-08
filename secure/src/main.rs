#![no_std]
#![no_main]
#![feature(cmse_nonsecure_entry)]
// The `e2e-test` build intentionally bypasses the interactive UI paths
// (wizard, pin entry confirm, interactive main()). Silence the resulting
// dead-code noise ONLY in that build so production builds still surface
// genuinely unused symbols.
#![cfg_attr(feature = "e2e-test", allow(dead_code))]

/// Conditional debug logging macro. Compiles to no-op without the `debug-log` feature,
/// ensuring no semihosting output in production builds.
#[cfg(feature = "debug-log")]
macro_rules! secure_log {
    ($($arg:tt)*) => { cortex_m_semihosting::hprintln!($($arg)*) };
}
#[cfg(not(feature = "debug-log"))]
macro_rules! secure_log {
    ($($arg:tt)*) => {};
}

mod boot_ns;
mod crypto;
mod db_roots;
mod erc20;
#[cfg(not(feature = "stm32u585"))]
mod host_rng;
#[cfg(any(feature = "pka-accel", feature = "stm32u585"))]
mod hw;
mod nsc;
mod rng;
mod pin;
mod sau;
mod secure_element;
#[cfg(feature = "tropic01-se")]
mod semihosting_spi;
mod timeout;
#[cfg(feature = "tropic01-se")]
mod tropic01_se;
mod tx;
mod ui;
mod zk;

use crypto::{RMEM_ENCRYPTED_ENTROPY, RMEM_PIN_STATE, RMEM_VERIFYING_KEY};
use secure_element::{MockSecureElement, SecureElement};

#[cfg(not(feature = "stm32u585"))]
const NS_FLASH_BASE: u32 = 0x0020_0000; // QEMU mps2-an505: NS alias of SSRAM-0
#[cfg(feature = "stm32u585")]
const NS_FLASH_BASE: u32 = 0x0810_0000; // STM32U585: flash bank 2 NS alias

const SYST_CSR: *mut u32 = 0xE000_E010 as *mut u32;
const SYST_RVR: *mut u32 = 0xE000_E014 as *mut u32;
const SYST_CVR: *mut u32 = 0xE000_E018 as *mut u32;

// Global mock SE (used when mock-se feature is active)
#[cfg(feature = "mock-se")]
static mut SE: MockSecureElement = MockSecureElement::new();

// Global TROPIC01 SE (used when tropic01-se feature is active)
#[cfg(feature = "tropic01-se")]
static mut SE: tropic01_se::Tropic01SecureElement = tropic01_se::Tropic01SecureElement::new();

/// SysTick reload value for ~1 ms tick.
/// QEMU mps2-an505: 25 MHz → 25_000.  STM32U585: set dynamically from rcc::init().
#[cfg(not(feature = "stm32u585"))]
const SYSTICK_RELOAD: u32 = 25_000;
#[cfg(feature = "stm32u585")]
static mut SYSTICK_RELOAD: u32 = 16_000; // overwritten by rcc::init() result

fn setup_systick() {
    unsafe {
        core::ptr::write_volatile(SYST_RVR, SYSTICK_RELOAD);
        core::ptr::write_volatile(SYST_CVR, 0);
        core::ptr::write_volatile(SYST_CSR, 0x07);
    }
}

/// Returns true if the secure element already holds an encrypted seed,
/// PIN state, and verifying key. Used to skip re-provisioning on every boot.
fn is_provisioned(se: &mut impl SecureElement) -> bool {
    let mut buf = [0u8; 128];
    se.r_mem_read(RMEM_ENCRYPTED_ENTROPY, &mut buf).is_ok()
        && se.r_mem_read(RMEM_PIN_STATE, &mut buf).is_ok()
        && se.r_mem_read(RMEM_VERIFYING_KEY, &mut buf).is_ok()
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
        secure_log!("[S] RCC: {} MHz + HSI48 + TRNG configured", mhz);
    }

    secure_log!("[S] Secure world starting...");

    sau::init();
    secure_log!("[S] SAU + MPC configured");

    ui::init();
    secure_log!("[S] UI initialized");

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
        crypto::provision_with_mnemonic(&mut *core::ptr::addr_of_mut!(SE), &mnemonic, &pin);

        // Run the verify path so MASTER_SECRET + PIN_VERIFIED end up
        // in the same state as a real unlock.
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

            #[cfg(feature = "tropic01-se")]
            (&mut *core::ptr::addr_of_mut!(SE))
                .provision(&mnemonic, &pin, sphincs_tz_shared::MAX_ATTEMPTS)
                .expect("TROPIC01 provisioning failed");

            // Debug-only: log the verifying key the SE just stored. This is
            // the regression guard for the recovery promise — same mnemonic
            // must always produce the same VK.
            #[cfg(feature = "debug-log")]
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

            // mnemonic drops here → indices zeroed.
            use zeroize::Zeroize;
            pin.zeroize();
            ui::show_status("Wallet ready", "");
            secure_log!("[S] Provisioned");
        } else {
            secure_log!("[S] Device already provisioned");
        }
    }

    // Initialize PKA hardware accelerator for BLS12-381 field arithmetic.
    // Preloads the Fp modulus into PKA RAM (stays resident for all operations).
    #[cfg(feature = "pka-accel")]
    unsafe {
        hw::pka::init();
        secure_log!("[S] PKA initialized (BLS12-381 Fp accelerated)");
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

#[cortex_m_rt::exception]
fn SysTick() {
    timeout::tick();

    // Background idle wipe: if PIN state is unlocked and the inactivity
    // timer has fired with no command in flight, wipe.
    if timeout::is_idle() && nsc::is_unlocked() {
        nsc::zeroize_sensitive_state();
        ui::show_status("Locked", "(idle wipe)");
    }

    // QEMU-only: drain the shared-memory mailbox. On STM32U585 the
    // gateway is driven synchronously by CMSE veneers, so SysTick only
    // services the timeout/idle-wipe bookkeeping above.
    #[cfg(not(feature = "stm32u585"))]
    nsc::poll_gateway();
}

/// Custom panic handler: zeroizes all sensitive state before halting.
/// This ensures secrets don't persist in RAM after a crash.
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
