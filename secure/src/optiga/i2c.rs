//! Bare-metal I2C master driver for OPTIGA Trust M (address 0x30).
//!
//! Structurally identical to `se050/i2c.rs` but targets the OPTIGA Trust M
//! slave address instead of SE050. Both chips share the same I2C1 bus
//! (PB8 SCL, PB9 SDA) — no address conflict.
//!
//! The register base comes from `crate::board`, so which physical bus
//! this driver talks on is a board fact rather than a literal here; the
//! offsets are bound once into typed [`Reg32`] / [`RoReg32`] handles so
//! individual touches in the transfer loops are safe.

use crate::board::OPTIGA_I2C_BASE as I2C_BASE;
use crate::hw::mmio::{Reg32, RoReg32};

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

/// GUARD_TIME pad — Trust M requires ≥ 50 µs from the STOP of one
/// transaction to the START of the next on the same device (SRM
/// "Protocol stack variation": GUARD_TIME = 50 µs; datasheet bring-up
/// notes: "the specified guard time must be applied between each
/// attempt of write / read operation by the Host", and per the IFX I2C
/// spec it must be respected even if another address — i.e. the SE050
/// on this shared bus — was accessed in between). Every OPTIGA
/// transaction funnels through [`write`] / [`read`] / [`probe_addr`],
/// so a leading pad here enforces the bound structurally instead of
/// relying on inter-transaction code-path latency: the DATA-read →
/// ACK-write turn in `ifx_i2c::receive_response` could otherwise
/// restart in single-digit µs after a short frame. 8 000 cycles is
/// 50 µs nominal at 160 MHz (~150 µs wall-clock with the ~3× `delay`
/// calibration — see `pin_diag.rs`), still ≪ one frame time at
/// 400 kHz, so the throughput cost is noise. Violations were
/// previously absorbed by NACK-retry loops; a pad is deterministic.
#[inline]
fn guard_time_pad() {
    cortex_m::asm::delay(8_000);
}

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
// the I2C peripheral `crate::board` assigns to the OPTIGA Trust M (secure alias),
// exclusively owned by the SE drivers. The secure world is single-threaded
// and non-preemptive, so even where a board puts both chips on ONE bus
// (`iota2`: OPTIGA and SE050 both on I2C1) the two drivers use it
// sequentially and never race; where a board gives them separate buses
// (`pq1`: this driver keeps I2C1 on PB8/PB9) they cannot interfere at all.
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
// ISR / ICR / CR2 bit positions (same register layout as se050/i2c.rs)
// ---------------------------------------------------------------------------

const ISR_TXIS: u32 = 1 << 1;
const ISR_RXNE: u32 = 1 << 2;
const ISR_NACKF: u32 = 1 << 4;
const ISR_STOPF: u32 = 1 << 5;
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

/// Configure CR2 for a transfer.
fn configure_transfer(addr: u8, nbytes: u8, direction: u32, flags: u32) {
    let cr2 = ((addr as u32) << 1)
        | direction
        | ((nbytes as u32) << 16)
        | flags
        | CR2_START;
    REG.cr2.write(cr2);
}

/// Probe a single 7-bit I2C address with a 0-byte write. Returns `Ok(())`
/// iff the slave ACKs.
pub fn probe_addr(addr: u8) -> Result<(), I2cError> {
    guard_time_pad();
    REG.icr.write(ICR_NACKCF | ICR_STOPCF | ICR_BERRCF | ICR_ARLOCF);

    let cr2: u32 = ((addr as u32) << 1)
        | (0u32 << 16)
        | CR2_START
        | CR2_AUTOEND;
    REG.cr2.write(cr2);

    let mut t = TIMEOUT_LOOPS;
    loop {
        let isr = REG.isr.read();
        if isr & ISR_NACKF != 0 {
            REG.icr.write(ICR_NACKCF);
            let mut s = TIMEOUT_LOOPS;
            while REG.isr.read() & ISR_STOPF == 0 {
                s -= 1;
                if s == 0 { break; }
            }
            REG.icr.write(ICR_STOPCF);
            return Err(I2cError::Nack);
        }
        if isr & ISR_STOPF != 0 {
            REG.icr.write(ICR_STOPCF);
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
pub fn probe() -> Result<(), I2cError> {
    probe_addr(OPTIGA_ADDR)
}

/// Probe that writes a single register-address byte (IFX I2C REG_I2C_STATE
/// = 0x82). Some chip firmware revisions NACK bare address-only writes but
/// ACK when any data byte follows. This is the minimal transaction the
/// OPTIGA's register-access layer guarantees to accept.
pub fn probe_with_reg() -> Result<(), I2cError> {
    write(&[0x82])
}

/// Scan every 7-bit address on I2C1 and log each responder. Used during
/// bring-up when we don't know what address the OPTIGA ended up at.
pub fn scan() {
    secure_log!("[OPTIGA/i2c] Scanning I2C1 0x08..0x77 for responders");
    for addr in 0x08u8..=0x77u8 {
        if probe_addr(addr).is_ok() {
            secure_log!("[OPTIGA/i2c]   found responder at 0x{:02x}", addr);
        }
    }
    secure_log!("[OPTIGA/i2c] Scan complete");
}

/// Write `data` to the OPTIGA Trust M (blocking).
pub fn write(data: &[u8]) -> Result<(), I2cError> {
    let total = data.len();
    if total == 0 {
        return Ok(());
    }

    guard_time_pad();

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

/// Read `buf.len()` bytes from the OPTIGA Trust M (blocking).
pub fn read(buf: &mut [u8]) -> Result<(), I2cError> {
    let total = buf.len();
    if total == 0 {
        return Ok(());
    }

    guard_time_pad();

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
            REG.cr2.write(cr2);
        }

        for i in 0..chunk {
            wait_flag(ISR_RXNE)?;
            buf[offset + i] = REG.rxdr.read() as u8;
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
pub fn write_read(tx: &[u8], rx: &mut [u8]) -> Result<(), I2cError> {
    if tx.is_empty() {
        return read(rx);
    }
    if rx.is_empty() {
        return write(tx);
    }
    write(tx)?;

    // 50 µs guard time at 160 MHz ≈ 8000 NOPs.
    for _ in 0..8_000u32 {
        // SAFETY: `nop` is an unprivileged hint instruction with no
        // memory effects; safe in every CPU mode.
        unsafe { core::arch::asm!("nop") };
    }

    read(rx)
}
