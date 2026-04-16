//! Bare-metal I2C1 master driver for OPTIGA Trust M (address 0x30).
//!
//! Structurally identical to `se050/i2c.rs` but targets the OPTIGA Trust M
//! slave address instead of SE050. Both chips share the same I2C1 bus
//! (PB8 SCL, PB9 SDA) — no address conflict.
//!
//! Register definitions imported from `hw::i2c_hw`.

use core::ptr::{read_volatile, write_volatile};
use crate::hw::i2c_hw::*;

/// OPTIGA Trust M I2C slave address (7-bit).
pub const OPTIGA_ADDR: u8 = 0x30;

/// I2C error types.
#[derive(Debug)]
pub enum I2cError {
    Nack,
    Bus,
    Arbitration,
    Timeout,
}

const TIMEOUT_LOOPS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// ISR / ICR / CR2 bit positions (same register layout as se050/i2c.rs)
// ---------------------------------------------------------------------------

const ISR_TXIS: u32 = 1 << 1;
const ISR_RXNE: u32 = 1 << 2;
const ISR_NACKF: u32 = 1 << 4;
const ISR_STOPF: u32 = 1 << 5;
const ISR_TC: u32 = 1 << 6;
const ISR_TCR: u32 = 1 << 7;
const ISR_BERR: u32 = 1 << 8;
const ISR_ARLO: u32 = 1 << 9;

const ICR_NACKCF: u32 = 1 << 4;
const ICR_STOPCF: u32 = 1 << 5;
const ICR_BERRCF: u32 = 1 << 8;
const ICR_ARLOCF: u32 = 1 << 9;

const CR2_START: u32 = 1 << 13;
const CR2_AUTOEND: u32 = 1 << 25;
const CR2_RELOAD: u32 = 1 << 24;
const CR2_RD_WRN: u32 = 1 << 10;

/// Wait for a flag in ISR, with timeout.
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

/// Configure CR2 for a transfer.
unsafe fn configure_transfer(addr: u8, nbytes: u8, direction: u32, flags: u32) {
    let cr2 = ((addr as u32) << 1)
        | direction
        | ((nbytes as u32) << 16)
        | flags
        | CR2_START;
    write_volatile(I2C1_CR2, cr2);
}

/// Probe a single 7-bit I2C address with a 0-byte write. Returns `Ok(())`
/// iff the slave ACKs.
pub unsafe fn probe_addr(addr: u8) -> Result<(), I2cError> {
    use crate::hw::i2c_hw::*;

    write_volatile(I2C1_ICR, ICR_NACKCF | ICR_STOPCF | ICR_BERRCF | ICR_ARLOCF);

    let cr2: u32 = ((addr as u32) << 1)
        | (0u32 << 16)
        | CR2_START
        | CR2_AUTOEND;
    write_volatile(I2C1_CR2, cr2);

    let mut t = TIMEOUT_LOOPS;
    loop {
        let isr = read_volatile(I2C1_ISR);
        if isr & ISR_NACKF != 0 {
            write_volatile(I2C1_ICR, ICR_NACKCF);
            let mut s = TIMEOUT_LOOPS;
            while read_volatile(I2C1_ISR) & ISR_STOPF == 0 {
                s -= 1;
                if s == 0 { break; }
            }
            write_volatile(I2C1_ICR, ICR_STOPCF);
            return Err(I2cError::Nack);
        }
        if isr & ISR_STOPF != 0 {
            write_volatile(I2C1_ICR, ICR_STOPCF);
            return Ok(());
        }
        t -= 1;
        if t == 0 {
            return Err(I2cError::Timeout);
        }
    }
}

/// One-shot 0-byte write probe — returns Ok(()) iff the OPTIGA at
/// `OPTIGA_ADDR` ACKs the address byte.
pub unsafe fn probe() -> Result<(), I2cError> {
    probe_addr(OPTIGA_ADDR)
}

/// Probe that writes a single register-address byte (IFX I2C REG_I2C_STATE
/// = 0x82). Some chip firmware revisions NACK bare address-only writes but
/// ACK when any data byte follows. This is the minimal transaction the
/// OPTIGA's register-access layer guarantees to accept.
pub unsafe fn probe_with_reg() -> Result<(), I2cError> {
    write(&[0x82])
}

/// Scan every 7-bit address on I2C1 and log each responder. Used during
/// bring-up when we don't know what address the OPTIGA ended up at.
pub unsafe fn scan() {
    secure_log!("[OPTIGA/i2c] Scanning I2C1 0x08..0x77 for responders");
    for addr in 0x08u8..=0x77u8 {
        if probe_addr(addr).is_ok() {
            secure_log!("[OPTIGA/i2c]   found responder at 0x{:02x}", addr);
        }
    }
    secure_log!("[OPTIGA/i2c] Scan complete");
}

/// Write `data` to the OPTIGA Trust M (blocking).
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
            configure_transfer(OPTIGA_ADDR, chunk as u8, 0, flags);
        } else {
            let cr2 = ((OPTIGA_ADDR as u32) << 1)
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

/// Read `buf.len()` bytes from the OPTIGA Trust M (blocking).
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
        let flags = if is_last { CR2_AUTOEND } else { CR2_RELOAD };

        if offset == 0 {
            configure_transfer(OPTIGA_ADDR, chunk as u8, CR2_RD_WRN, flags);
        } else {
            let cr2 = ((OPTIGA_ADDR as u32) << 1)
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
            wait_flag(ISR_TCR)?;
        }

        offset += chunk;
    }

    wait_flag(ISR_STOPF)?;
    write_volatile(I2C1_ICR, ICR_STOPCF);
    Ok(())
}

/// Write `tx` then read `rx`.
///
/// IFX I2C register-read pattern per Infineon's reference driver:
///   1. Write: `[addr+W | reg_addr | STOP]`
///   2. Wait `PL_GUARD_TIME_INTERVAL_US` (50 µs) for the chip to latch the
///      register selector.
///   3. Read: `[addr+R | data... | STOP]` (no register address — the chip
///      remembers the selector across transactions).
///
/// Repeated-START is not used: the Trust M silicon NACKs the restart
/// address byte when it transitions directly from write to read phase.
pub unsafe fn write_read(tx: &[u8], rx: &mut [u8]) -> Result<(), I2cError> {
    if tx.is_empty() {
        return read(rx);
    }
    if rx.is_empty() {
        return write(tx);
    }
    write(tx)?;

    // 50 µs guard time at 160 MHz ≈ 8000 NOPs.
    for _ in 0..8_000u32 {
        core::arch::asm!("nop");
    }

    read(rx)
}
