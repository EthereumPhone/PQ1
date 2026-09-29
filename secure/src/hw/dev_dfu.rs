//! `dev-dfu` — re-enter the STM32U585 ROM bootloader (USB DFU) from firmware.
//!
//! Bench convenience for a **sealed** board with no probe and no SBU cable:
//! if BOTH buttons are held while the board powers up, the very first thing
//! `main` does after the clock tree is to clear the `nSWBOOT0` and `nBOOT0`
//! option bits and reload option bytes. RM0456 Table 26 (TZEN=1) /
//! AN2606 Pattern 12: `nBOOT0=0, nSWBOOT0=0` boots the RSS/bootloader
//! regardless of the BOOT0 pin, so the chip comes back up as `0483:df11`.
//! The host flash script (`tools/evt-dev-flash.sh`) restores
//! `nSWBOOT0=1, nBOOT0=1` as its last step, which boots flash again and
//! keeps the BOOT0-pin (SBU cable) path usable as a rescue.
//!
//! Placed before ANY UI / SE / USB code on purpose: a UI change that hangs
//! later in boot must not take the re-flash path down with it. Keep this
//! module and its call site untouched while iterating.
//!
//! Register ownership follows `sphincs_tz_shared::lockdown`: `OPTSTRT` and
//! `OBL_LAUNCH` live in `FLASH_NSCR` (bits 17 / 27), `OPTLOCK` is NSCR bit
//! 30, and `OPTKEYR` needs the NS flash controller unlocked first (`NSKEYR`).
//! NEVER SHIP — `dev-dfu` is in the Makefile's PROD_FORBIDDEN.
#![cfg(all(feature = "dev-dfu", feature = "stm32u585"))]

use crate::board;
use crate::hw::mmio::{Reg32, RoReg32};
use sphincs_tz_shared::lockdown::{
    FLASH_NSCR_OFF, FLASH_NSSR_OFF, FLASH_OBL_LAUNCH, FLASH_OPTSTRT,
};

const FLASH_NS: u32 = 0x4002_2000;
const NSKEYR_OFF: u32 = 0x08;
const OPTKEYR_OFF: u32 = 0x10;
const OPTR_OFF: u32 = 0x40;
const KEY1: u32 = 0x4567_0123;
const KEY2: u32 = 0xCDEF_89AB;
const OPT_KEY1: u32 = 0x0819_2A3B;
const OPT_KEY2: u32 = 0x4C5D_6E7F;
const NSCR_LOCK: u32 = 1 << 31;
const NSCR_OPTLOCK: u32 = 1 << 30;
const NSSR_BSY: u32 = 1 << 16;
const NSSR_WDW: u32 = 1 << 17;
/// FLASH_OPTR bit 26 (`NSWBOOT0`) and bit 27 (`NBOOT0`), RM0456 §7.9.
const OPTR_NSWBOOT0: u32 = 1 << 26;
const OPTR_NBOOT0: u32 = 1 << 27;

const LEFT: (u32, u32) = (board::BTN_LEFT_PORT, board::BTN_LEFT_PIN);
const RIGHT: (u32, u32) = (board::BTN_RIGHT_PORT, board::BTN_RIGHT_PIN);

fn input_pullup(pin: (u32, u32)) {
    // SAFETY: MODER/PUPDR of a board-map GPIO port; RMW confined to this pin.
    let (moder, pupdr) = unsafe { (Reg32::new(pin.0), Reg32::new(pin.0 + 0x0C)) };
    let two = pin.1 * 2;
    let field = 0b11u32 << two;
    moder.modify(|v| v & !field); // input
    pupdr.modify(|v| (v & !field) | (0b01 << two)); // pull-up
}

fn pressed(pin: (u32, u32)) -> bool {
    // SAFETY: IDR of a board-map GPIO port; read-only.
    let idr = unsafe { RoReg32::new(pin.0 + 0x10) };
    idr.read() & (1 << pin.1) == 0 // active-low: pressed pulls to GND
}

/// Sample both buttons; if both are held for ~50 ms, enter the bootloader.
/// Returns (doing nothing else) otherwise. Call right after `rcc::init`.
pub fn check_and_enter() {
    // SAFETY: the secure-alias RCC AHB2ENR1; `gpio_rcc_bit` maps each port
    // to its own enable bit, so this RMW touches no other driver's bit.
    let enr = unsafe { Reg32::new(board::RCC_S + board::RCC_AHB2ENR1_OFF) };
    enr.set_bits(board::gpio_rcc_bit(LEFT.0) | board::gpio_rcc_bit(RIGHT.0));
    let _ = enr.read();
    cortex_m::asm::dsb();
    input_pullup(LEFT);
    input_pullup(RIGHT);
    // Settle + debounce: 5 samples 10 ms apart, all must read pressed.
    for _ in 0..5 {
        cortex_m::asm::delay(1_600_000); // 10 ms at 160 MHz
        if !(pressed(LEFT) && pressed(RIGHT)) {
            return;
        }
    }
    // SAFETY: nothing else has touched the flash controller yet this boot;
    // the sequence below only stages two option bits and reloads them.
    unsafe { enter_bootloader() }
}

/// Clear `nSWBOOT0` + `nBOOT0` and reload option bytes → system reset into
/// the ROM bootloader. Never returns on success; on a pre-launch error it
/// spins with the option bytes untouched (the chip then boots normally on
/// the next power cycle).
///
/// # Safety
/// Must run with the flash controller idle and before any other flash use.
pub unsafe fn enter_bootloader() -> ! {
    // SAFETY: NS-alias FLASH registers at their RM0456 offsets; single-core,
    // interrupts masked for the whole sequence.
    let (nskeyr, optkeyr, optr, nscr, nssr) = unsafe {
        (
            Reg32::new(FLASH_NS + NSKEYR_OFF),
            Reg32::new(FLASH_NS + OPTKEYR_OFF),
            Reg32::new(FLASH_NS + OPTR_OFF),
            Reg32::new(FLASH_NS + FLASH_NSCR_OFF),
            Reg32::new(FLASH_NS + FLASH_NSSR_OFF),
        )
    };
    let ok = cortex_m::interrupt::free(|_| {
        while nssr.read() & (NSSR_BSY | NSSR_WDW) != 0 {
            cortex_m::asm::nop();
        }
        if nscr.read() & NSCR_LOCK != 0 {
            nskeyr.write(KEY1);
            nskeyr.write(KEY2);
            cortex_m::asm::dsb();
            if nscr.read() & NSCR_LOCK != 0 {
                return false;
            }
        }
        if nscr.read() & NSCR_OPTLOCK != 0 {
            optkeyr.write(OPT_KEY1);
            optkeyr.write(OPT_KEY2);
            cortex_m::asm::dsb();
            if nscr.read() & NSCR_OPTLOCK != 0 {
                return false;
            }
        }
        optr.modify(|v| v & !(OPTR_NSWBOOT0 | OPTR_NBOOT0));
        nscr.set_bits(FLASH_OPTSTRT);
        while nssr.read() & NSSR_BSY != 0 {
            cortex_m::asm::nop();
        }
        if optr.read() & (OPTR_NSWBOOT0 | OPTR_NBOOT0) != 0 {
            return false;
        }
        nscr.set_bits(FLASH_OBL_LAUNCH);
        true
    });
    let _ = ok;
    loop {
        cortex_m::asm::wfe();
    }
}
