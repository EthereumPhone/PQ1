//! Bare-metal I2C master driver for the SE050 on STM32U585.
//!
//! Provides blocking `write` and `read` operations to communicate with
//! the SE050 at I2C slave address 0x48.
//!
//! The register base comes from `crate::board`, so which physical bus
//! this driver talks on is a board fact rather than a literal here; the
//! offsets are bound once into typed [`Reg32`] / [`RoReg32`] handles so
//! individual touches in the transfer loops are safe.

use crate::board::SE050_I2C_BASE as I2C_BASE;
use crate::hw::mmio::{Reg32, RoReg32};

/// SE050 I2C slave address (7-bit, matching OM-SE050ARD default).
pub const SE050_ADDR: u8 = 0x48;

/// I2C error types.
#[derive(Debug)]
pub enum I2cError {
    /// NACK received from slave.
    Nack,
    /// Bus error (BERR).
    Bus,
    /// Arbitration lost.
    Arbitration,
    /// Timeout waiting for a flag.
    Timeout,
}

/// Maximum iterations to spin waiting for a flag before declaring timeout.
const TIMEOUT_LOOPS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// I2C1 register block — typed handles so the unsafe register-address
// construction happens exactly once at module scope.
// ---------------------------------------------------------------------------

struct I2cRegs {
    cr2: Reg32,
    isr: RoReg32,
    icr: Reg32,
    rxdr: RoReg32,
    txdr: Reg32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register on
// the I2C peripheral `crate::board` assigns to the SE050 (secure alias),
// exclusively owned by the SE drivers. The secure world is single-threaded
// and non-preemptive, so even where a board puts both chips on ONE bus
// (`iota2`: OPTIGA and SE050 both on I2C1) the two drivers use it
// sequentially and never race; where a board gives them separate buses
// (`pq1`: this driver drives I2C4 on PB6/PB7) they cannot interfere at all.
// After this one-time construction every register touch below is via
// safe `.read()` / `.write()` methods.
const REG: I2cRegs = unsafe {
    I2cRegs {
        cr2: Reg32::new(I2C_BASE + 0x04),
        isr: RoReg32::new(I2C_BASE + 0x18),
        icr: Reg32::new(I2C_BASE + 0x1C),
        rxdr: RoReg32::new(I2C_BASE + 0x24),
        txdr: Reg32::new(I2C_BASE + 0x28),
    }
};

// ---------------------------------------------------------------------------
// I2C ISR (Interrupt and Status Register) bit positions
// ---------------------------------------------------------------------------
const ISR_TXIS: u32 = 1 << 1; // Transmit interrupt status
const ISR_RXNE: u32 = 1 << 2; // Receive data register not empty
const ISR_NACKF: u32 = 1 << 4; // NACK received flag
const ISR_STOPF: u32 = 1 << 5; // STOP detection flag
const ISR_TCR: u32 = 1 << 7; // Transfer complete reload
const ISR_BERR: u32 = 1 << 8; // Bus error
const ISR_ARLO: u32 = 1 << 9; // Arbitration lost

// ICR (Interrupt Clear Register) bits
const ICR_NACKCF: u32 = 1 << 4;
const ICR_STOPCF: u32 = 1 << 5;
const ICR_BERRCF: u32 = 1 << 8;
const ICR_ARLOCF: u32 = 1 << 9;

// CR2 bits
const CR2_START: u32 = 1 << 13;
const CR2_AUTOEND: u32 = 1 << 25;
const CR2_RELOAD: u32 = 1 << 24;
const CR2_RD_WRN: u32 = 1 << 10; // 1 = read, 0 = write

/// Wait for a flag in ISR, with timeout. Returns the ISR value.
fn wait_flag(mask: u32) -> Result<u32, I2cError> {
    for _ in 0..TIMEOUT_LOOPS {
        let isr = REG.isr.read();
        if isr & ISR_NACKF != 0 {
            REG.icr.write(ICR_NACKCF);
            return Err(I2cError::Nack);
        }
        if isr & ISR_BERR != 0 {
            REG.icr.write(ICR_BERRCF);
            return Err(I2cError::Bus);
        }
        if isr & ISR_ARLO != 0 {
            REG.icr.write(ICR_ARLOCF);
            return Err(I2cError::Arbitration);
        }
        if isr & mask != 0 {
            return Ok(isr);
        }
    }
    Err(I2cError::Timeout)
}

/// Configure CR2 for a transfer: slave address, direction, byte count,
/// and START/AUTOEND/RELOAD flags.
fn configure_transfer(addr: u8, nbytes: u8, direction: u32, flags: u32) {
    let cr2 = ((addr as u32) << 1) // SADD[7:1] (7-bit addressing)
        | direction                 // RD_WRN
        | ((nbytes as u32) << 16)  // NBYTES
        | flags                     // START, AUTOEND, RELOAD
        | CR2_START;
    REG.cr2.write(cr2);
}

/// Write `data` to the SE050 (blocking).
/// Handles transfers > 255 bytes using RELOAD mode.
pub fn write(data: &[u8]) -> Result<(), I2cError> {
    let total = data.len();
    if total == 0 {
        return Ok(());
    }

    let mut offset = 0;
    while offset < total {
        let remaining = total - offset;
        let chunk = remaining.min(255);
        let is_last = chunk == remaining;

        let flags = if is_last { CR2_AUTOEND } else { CR2_RELOAD };

        if offset == 0 {
            configure_transfer(SE050_ADDR, chunk as u8, 0, flags);
        } else {
            let cr2 = ((SE050_ADDR as u32) << 1) | ((chunk as u32) << 16) | flags;
            REG.cr2.write(cr2);
        }

        for i in 0..chunk {
            wait_flag(ISR_TXIS)?;
            REG.txdr.write(data[offset + i] as u32);
        }

        if !is_last {
            wait_flag(ISR_TCR)?;
        }

        offset += chunk;
    }

    wait_flag(ISR_STOPF)?;
    REG.icr.write(ICR_STOPCF);

    Ok(())
}

/// Read `buf.len()` bytes from the SE050 (blocking).
/// Handles transfers > 255 bytes using RELOAD mode.
pub fn read(buf: &mut [u8]) -> Result<(), I2cError> {
    let total = buf.len();
    if total == 0 {
        return Ok(());
    }

    let mut offset = 0;
    while offset < total {
        let remaining = total - offset;
        let chunk = remaining.min(255);
        let is_last = chunk == remaining;

        let flags = if is_last {
            CR2_AUTOEND // Last chunk: auto-STOP after NBYTES
        } else {
            CR2_RELOAD // More chunks: TCR flag instead of STOP
        };

        if offset == 0 {
            configure_transfer(SE050_ADDR, chunk as u8, CR2_RD_WRN, flags);
        } else {
            // RELOAD: update NBYTES and flags in CR2 (no new START)
            let cr2 = ((SE050_ADDR as u32) << 1) | CR2_RD_WRN | ((chunk as u32) << 16) | flags;
            REG.cr2.write(cr2);
        }

        for i in 0..chunk {
            wait_flag(ISR_RXNE)?;
            buf[offset + i] = REG.rxdr.read() as u8;
        }

        if !is_last {
            // Wait for Transfer Complete Reload before next chunk
            wait_flag(ISR_TCR)?;
        }

        offset += chunk;
    }

    // Wait for STOP (generated by AUTOEND on last chunk)
    wait_flag(ISR_STOPF)?;
    REG.icr.write(ICR_STOPCF);

    Ok(())
}
