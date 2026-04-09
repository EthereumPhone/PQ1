//! Bare-metal I2C1 master driver for STM32U585.
//!
//! Provides blocking `write`, `read`, and `write_read` operations
//! to communicate with the SE050 at I2C slave address 0x48.
//!
//! All register addresses are imported from `hw::i2c_hw`.

use core::ptr::{read_volatile, write_volatile};
use crate::hw::i2c_hw::*;

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
// I2C ISR (Interrupt and Status Register) bit positions
// ---------------------------------------------------------------------------
const ISR_TXE: u32 = 1 << 0; // Transmit data register empty
const ISR_TXIS: u32 = 1 << 1; // Transmit interrupt status
const ISR_RXNE: u32 = 1 << 2; // Receive data register not empty
const ISR_NACKF: u32 = 1 << 4; // NACK received flag
const ISR_STOPF: u32 = 1 << 5; // STOP detection flag
const ISR_TC: u32 = 1 << 6; // Transfer complete
const ISR_TCR: u32 = 1 << 7; // Transfer complete reload
const ISR_BERR: u32 = 1 << 8; // Bus error
const ISR_ARLO: u32 = 1 << 9; // Arbitration lost
const ISR_BUSY: u32 = 1 << 15; // Bus busy

// ICR (Interrupt Clear Register) bits
const ICR_NACKCF: u32 = 1 << 4;
const ICR_STOPCF: u32 = 1 << 5;
const ICR_BERRCF: u32 = 1 << 8;
const ICR_ARLOCF: u32 = 1 << 9;

// CR2 bits
const CR2_START: u32 = 1 << 13;
const CR2_STOP: u32 = 1 << 14;
const CR2_AUTOEND: u32 = 1 << 25;
const CR2_RELOAD: u32 = 1 << 24;
const CR2_RD_WRN: u32 = 1 << 10; // 1 = read, 0 = write

/// Wait for a flag in ISR, with timeout. Returns the ISR value.
unsafe fn wait_flag(mask: u32) -> Result<u32, I2cError> {
    for _ in 0..TIMEOUT_LOOPS {
        let isr = read_volatile(I2C1_ISR);
        if isr & ISR_NACKF != 0 {
            write_volatile(I2C1_ICR, ICR_NACKCF);
            return Err(I2cError::Nack);
        }
        if isr & ISR_BERR != 0 {
            write_volatile(I2C1_ICR, ICR_BERRCF);
            return Err(I2cError::Bus);
        }
        if isr & ISR_ARLO != 0 {
            write_volatile(I2C1_ICR, ICR_ARLOCF);
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
unsafe fn configure_transfer(addr: u8, nbytes: u8, direction: u32, flags: u32) {
    let cr2 = ((addr as u32) << 1) // SADD[7:1] (7-bit addressing)
        | direction                 // RD_WRN
        | ((nbytes as u32) << 16)  // NBYTES
        | flags                     // START, AUTOEND, RELOAD
        | CR2_START;
    write_volatile(I2C1_CR2, cr2);
}

/// Write `data` to the SE050 (blocking).
/// Handles transfers > 255 bytes using RELOAD mode.
pub unsafe fn write(data: &[u8]) -> Result<(), I2cError> {
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
            let cr2 = ((SE050_ADDR as u32) << 1)
                | ((chunk as u32) << 16)
                | flags;
            write_volatile(I2C1_CR2, cr2);
        }

        for i in 0..chunk {
            wait_flag(ISR_TXIS)?;
            write_volatile(I2C1_TXDR, data[offset + i] as u32);
        }

        if !is_last {
            wait_flag(ISR_TCR)?;
        }

        offset += chunk;
    }

    wait_flag(ISR_STOPF)?;
    write_volatile(I2C1_ICR, ICR_STOPCF);

    Ok(())
}

/// Read `buf.len()` bytes from the SE050 (blocking).
/// Handles transfers > 255 bytes using RELOAD mode.
pub unsafe fn read(buf: &mut [u8]) -> Result<(), I2cError> {
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
            let cr2 = ((SE050_ADDR as u32) << 1)
                | CR2_RD_WRN
                | ((chunk as u32) << 16)
                | flags;
            write_volatile(I2C1_CR2, cr2);
        }

        for i in 0..chunk {
            wait_flag(ISR_RXNE)?;
            buf[offset + i] = read_volatile(I2C1_RXDR) as u8;
        }

        if !is_last {
            // Wait for Transfer Complete Reload before next chunk
            wait_flag(ISR_TCR)?;
        }

        offset += chunk;
    }

    // Wait for STOP (generated by AUTOEND on last chunk)
    wait_flag(ISR_STOPF)?;
    write_volatile(I2C1_ICR, ICR_STOPCF);

    Ok(())
}

/// Write `tx` then read `rx` in a single I2C transaction (repeated START).
pub unsafe fn write_read(tx: &[u8], rx: &mut [u8]) -> Result<(), I2cError> {
    if tx.is_empty() {
        return read(rx);
    }
    if rx.is_empty() {
        return write(tx);
    }

    // Write phase: no AUTOEND (we'll send repeated START instead of STOP)
    configure_transfer(SE050_ADDR, tx.len().min(255) as u8, 0, 0);

    for &byte in tx {
        wait_flag(ISR_TXIS)?;
        write_volatile(I2C1_TXDR, byte as u32);
    }

    // Wait for transfer complete (not STOP — we disabled AUTOEND)
    wait_flag(ISR_TC)?;

    // Read phase: repeated START, AUTOEND
    configure_transfer(SE050_ADDR, rx.len().min(255) as u8, CR2_RD_WRN, CR2_AUTOEND);

    for byte in rx.iter_mut() {
        wait_flag(ISR_RXNE)?;
        *byte = read_volatile(I2C1_RXDR) as u8;
    }

    wait_flag(ISR_STOPF)?;
    write_volatile(I2C1_ICR, ICR_STOPCF);

    Ok(())
}
