//! Option-byte configurator for STM32U585.
//!
//! This firmware is linked at 0x0C000000 (secure flash page 0) and runs
//! in secure mode when TZEN=1.  It unconditionally uses the SECURE flash
//! controller registers to program SECWM and SECBOOTADD0.
//!
//! TZEN must already be set to 1 (via OpenOCD) before running this.

#![no_std]
#![no_main]

use core::ptr::{read_volatile, write_volatile};

// Sequential progress markers in secure SRAM
static mut MARKER_IDX: u32 = 0;
fn mark(val: u32) {
    unsafe {
        let addr = (0x3000_0100u32 + MARKER_IDX * 4) as *mut u32;
        write_volatile(addr, val);
        MARKER_IDX += 1;
    }
}

// Secure flash controller (RM0456)
const FLASH_S: u32 = 0x5002_2000;

const SECKEYR: *mut u32 = (FLASH_S + 0x0C) as *mut u32;
const OPTKEYR: *mut u32 = (FLASH_S + 0x10) as *mut u32;
const SECCR1: *mut u32 = (FLASH_S + 0x24) as *mut u32;
const SECSR: *const u32 = (FLASH_S + 0x2C) as *const u32;
const OPTR: *const u32 = (FLASH_S + 0x40) as *const u32;
const SECBOOTADD0R: *mut u32 = (FLASH_S + 0x4C) as *mut u32;
const SECWM1R1: *mut u32 = (FLASH_S + 0x50) as *mut u32;
const SECWM2R1: *mut u32 = (FLASH_S + 0x60) as *mut u32;

const FLASH_KEY1: u32 = 0x4567_0123;
const FLASH_KEY2: u32 = 0xCDEF_89AB;
const OPT_KEY1: u32 = 0x0819_2A3B;
const OPT_KEY2: u32 = 0x4C5D_6E7F;

const OPTSTRT: u32 = 1 << 17;
const OBL_LAUNCH: u32 = 1 << 27;
const LOCK_BIT: u32 = 1 << 31;
const OPTLOCK_BIT: u32 = 1 << 30;
const BSY: u32 = 1 << 16;

fn wait_bsy() {
    unsafe {
        let mut n = 0u32;
        while read_volatile(SECSR) & BSY != 0 {
            cortex_m::asm::nop();
            n += 1;
            if n > 10_000_000 { return; }
        }
    }
}

#[cortex_m_rt::entry]
fn main() -> ! {
    unsafe {
        // [0] Read OPTR from S alias
        mark(read_volatile(OPTR));

        // [1] Read SECCR1 before unlock
        let cr = read_volatile(SECCR1 as *const u32);
        mark(cr);

        // [2] Read SECSR
        mark(read_volatile(SECSR));

        // Wait for not busy
        wait_bsy();

        // Unlock secure flash controller
        write_volatile(SECKEYR, FLASH_KEY1);
        write_volatile(SECKEYR, FLASH_KEY2);
        cortex_m::asm::dsb();

        // [3] SECCR1 after flash unlock (LOCK bit 31 should be 0)
        let cr_after = read_volatile(SECCR1 as *const u32);
        mark(cr_after);

        if cr_after & LOCK_BIT != 0 {
            // Flash unlock failed — might not be in secure mode
            mark(0xBAD0_0001);
            loop { cortex_m::asm::bkpt(); }
        }

        // Unlock option bytes
        write_volatile(OPTKEYR, OPT_KEY1);
        write_volatile(OPTKEYR, OPT_KEY2);
        cortex_m::asm::dsb();

        // [4] SECCR1 after opt unlock (OPTLOCK bit 30 should be 0)
        let cr_opt = read_volatile(SECCR1 as *const u32);
        mark(cr_opt);

        if cr_opt & OPTLOCK_BIT != 0 {
            mark(0xBAD0_0002);
            loop { cortex_m::asm::bkpt(); }
        }

        // Write SECWM1R1: bank 1 all secure (PSTRT=0, PEND=0x7F)
        write_volatile(SECWM1R1, 0x007F_0000);
        // [5] readback
        mark(read_volatile(SECWM1R1 as *const u32));

        // Write SECWM2R1: bank 2 all NS (PSTRT=0x7F > PEND=0)
        write_volatile(SECWM2R1, 0x0000_007F);
        // [6] readback
        mark(read_volatile(SECWM2R1 as *const u32));

        // Write SECBOOTADD0: 0x0C000000 >> 7 = 0x180000
        write_volatile(SECBOOTADD0R, 0x0018_0000);
        // [7] readback
        mark(read_volatile(SECBOOTADD0R as *const u32));

        // Trigger OPTSTRT to commit option bytes to flash
        write_volatile(SECCR1, OPTSTRT);
        wait_bsy();

        // [8] SECSR after OPTSTRT (check for errors)
        mark(read_volatile(SECSR));

        // [9] SECWM1R1 after commit
        mark(read_volatile(SECWM1R1 as *const u32));

        // [10] SECBOOTADD0R after commit
        mark(read_volatile(SECBOOTADD0R as *const u32));

        // [11] sentinel
        mark(0xAAAA_BBBB);

        // Trigger OBL_LAUNCH to apply new option bytes
        write_volatile(SECCR1, OBL_LAUNCH);

        // [12] should NOT reach here
        mark(0xDEAD_BEEF);
        loop { cortex_m::asm::bkpt(); }
    }
}

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    mark(0xDEAD_DEAD);
    loop { cortex_m::asm::bkpt(); }
}
