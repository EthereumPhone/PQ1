//! Bare-metal SPI master driver implementing `embedded_hal::spi::SpiDevice`.
//!
//! Provides the `Stm32Spi` struct that wraps direct register access to the
//! STM32U585 SPI peripheral (SPI1 or SPI2, selected by `spi1-arduino`
//! feature). Used by the `tropic01` crate driver for communication with
//! the TROPIC01 secure element.
//!
//! Register base address comes from `hw::spi_hw::SPI_BASE`; this file owns
//! the per-register `Reg32` / `RoReg32` handles. All MMIO is funnelled
//! through `hw::mmio::{Reg32, RoReg32}` — the one `unsafe { ... }` for
//! address binding lives at module scope below.

use embedded_hal::spi::{self, ErrorKind, Operation};

use crate::hw::mmio::{Reg32, RoReg32};
use crate::hw::spi_hw::{cs_assert, cs_deassert, SPI_BASE};

// ---------------------------------------------------------------------------
// SPI register handles — STM32U5 SPI v2 layout, offsets from SPI_BASE:
//   0x00 CR1, 0x04 CR2, 0x14 SR, 0x18 IFCR, 0x20 TXDR, 0x30 RXDR
// ---------------------------------------------------------------------------

struct SpiRegs {
    cr1: Reg32,
    cr2: Reg32,
    sr: RoReg32,
    ifcr: Reg32,
    /// 32-bit-aligned TXDR. The peripheral also exposes 8-bit access at the
    /// same address (used by `transfer_inplace` for single-byte FIFO writes
    /// matching DSIZE=8). The 8-bit access stays a tight `unsafe` block in
    /// the inner loop — `Reg32` is u32-only.
    txdr_addr: u32,
    rxdr_addr: u32,
}

// SAFETY: each address below is a real, 4-byte-aligned MMIO register on the
// STM32U585 SPI peripheral, exclusively owned by this driver. The secure
// world is single-threaded and non-preemptive — nothing else races us.
const REG: SpiRegs = unsafe {
    SpiRegs {
        cr1: Reg32::new(SPI_BASE + 0x00),
        cr2: Reg32::new(SPI_BASE + 0x04),
        sr: RoReg32::new(SPI_BASE + 0x14),
        ifcr: Reg32::new(SPI_BASE + 0x18),
        txdr_addr: SPI_BASE + 0x20,
        rxdr_addr: SPI_BASE + 0x30,
    }
};

// ---------------------------------------------------------------------------
// SPI SR (Status Register) bit positions — STM32U5 SPI (v2)
// ---------------------------------------------------------------------------
const SR_TXP: u32 = 1 << 1;   // Tx-packet space available
const SR_RXP: u32 = 1 << 0;   // Rx-packet data available
const SR_EOT: u32 = 1 << 3;   // End of transfer
const SR_OVR: u32 = 1 << 6;   // Overrun
const SR_TXTF: u32 = 1 << 4;  // Transmission transfer filled

// CR1 bits
const CR1_SPE: u32 = 1 << 0;  // SPI enable
const CR1_CSTART: u32 = 1 << 9; // Master transfer start

// IFCR bits (clear flags)
const IFCR_EOTC: u32 = 1 << 3;
const IFCR_TXTFC: u32 = 1 << 4;
const IFCR_OVRC: u32 = 1 << 6;

/// Maximum iterations to spin waiting for a flag before declaring timeout.
const TIMEOUT_LOOPS: u32 = 1_000_000;

// ---------------------------------------------------------------------------
// Error type
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub enum SpiError {
    Timeout,
    Overrun,
}

impl spi::Error for SpiError {
    fn kind(&self) -> ErrorKind {
        match self {
            SpiError::Timeout => ErrorKind::Other,
            SpiError::Overrun => ErrorKind::Overrun,
        }
    }
}

// ---------------------------------------------------------------------------
// Stm32Spi — the driver struct
// ---------------------------------------------------------------------------

/// Bare-metal SPI master driver for TROPIC01.
///
/// Stateless (all state is in hardware registers).
/// Implements `embedded_hal::spi::SpiDevice` for use with the `tropic01` crate.
pub struct Stm32Spi {
    _private: (),
}

impl Stm32Spi {
    /// Create a new SPI driver.
    ///
    /// # Safety
    /// Caller must have called `spi_hw::init()` first.
    pub unsafe fn new() -> Self {
        Self { _private: () }
    }

    /// Enable SPI peripheral and start a master transfer.
    fn enable_and_start(&self, nbytes: u16) {
        // Clear any pending flags
        REG.ifcr.write(IFCR_EOTC | IFCR_TXTFC | IFCR_OVRC);

        // Set transfer size in CR2 (TSIZE[15:0])
        REG.cr2.write(nbytes as u32);

        // Enable SPI (SPE = 1)
        REG.cr1.set_bits(CR1_SPE);

        // Start master transfer (CSTART = 1)
        REG.cr1.set_bits(CR1_CSTART);
    }

    /// Wait for end-of-transfer, then disable SPI.
    fn wait_eot_and_disable(&self) -> Result<(), SpiError> {
        // Wait for EOT
        for _ in 0..TIMEOUT_LOOPS {
            let sr = REG.sr.read();
            if sr & SR_OVR != 0 {
                REG.ifcr.write(IFCR_OVRC);
                // Don't fail on overrun during EOT wait — data is already transferred
            }
            if sr & SR_EOT != 0 {
                // Clear EOT and TXTF flags
                REG.ifcr.write(IFCR_EOTC | IFCR_TXTFC);

                // Disable SPI (SPE = 0)
                REG.cr1.clear_bits(CR1_SPE);
                return Ok(());
            }
        }
        // Timeout — force disable
        REG.cr1.clear_bits(CR1_SPE);
        Err(SpiError::Timeout)
    }

    /// Full-duplex transfer of `data` (in-place): sends each byte and
    /// overwrites it with the received byte.
    fn transfer_inplace(&self, data: &mut [u8]) -> Result<(), SpiError> {
        if data.is_empty() {
            return Ok(());
        }

        self.enable_and_start(data.len() as u16);

        let mut tx_idx: usize = 0;
        let mut rx_idx: usize = 0;

        while rx_idx < data.len() {
            let sr = REG.sr.read();

            // Check overrun
            if sr & SR_OVR != 0 {
                REG.ifcr.write(IFCR_OVRC);
                REG.cr1.clear_bits(CR1_SPE);
                return Err(SpiError::Overrun);
            }

            // Feed TX FIFO if space available and we have bytes left
            if tx_idx < data.len() && sr & SR_TXP != 0 {
                // Write single byte to TXDR (8-bit access).
                // SAFETY: TXDR supports 8-bit writes per RM (DSIZE=8). The
                // address is owned by this driver; volatile write prevents
                // reordering across the surrounding register touches.
                unsafe {
                    core::ptr::write_volatile(REG.txdr_addr as *mut u8, data[tx_idx]);
                }
                tx_idx += 1;
            }

            // Drain RX FIFO if data available
            if sr & SR_RXP != 0 {
                // Read single byte from RXDR (8-bit access).
                // SAFETY: RXDR supports 8-bit reads per RM (DSIZE=8). The
                // address is owned by this driver; volatile read prevents
                // reordering across the surrounding register touches.
                let b = unsafe {
                    core::ptr::read_volatile(REG.rxdr_addr as *const u8)
                };
                data[rx_idx] = b;
                rx_idx += 1;
            }
        }

        self.wait_eot_and_disable()
    }
}

impl spi::ErrorType for Stm32Spi {
    type Error = SpiError;
}

impl spi::SpiDevice for Stm32Spi {
    fn transaction(&mut self, operations: &mut [Operation<'_, u8>]) -> Result<(), Self::Error> {
        // Assert CS at the start of the transaction.
        // SAFETY: `cs_assert` is a thin GPIO-BSRR write; single-threaded secure world.
        unsafe {
            cs_assert();
        }

        let mut result = Ok(());
        for op in operations {
            match op {
                Operation::TransferInPlace(data) => {
                    result = self.transfer_inplace(data);
                }
                Operation::Read(buf) => {
                    // Send zeros, receive into buf
                    buf.fill(0x00);
                    result = self.transfer_inplace(buf);
                }
                Operation::Write(data) => {
                    // Send data, discard received bytes
                    let mut tmp = [0u8; 300]; // MAX_FRAME from semihosting_spi
                    let len = data.len().min(tmp.len());
                    tmp[..len].copy_from_slice(&data[..len]);
                    result = self.transfer_inplace(&mut tmp[..len]);
                }
                Operation::Transfer(read, write) => {
                    // Copy write data into read buffer, then transfer in-place
                    let len = read.len().min(write.len());
                    read[..len].copy_from_slice(&write[..len]);
                    result = self.transfer_inplace(&mut read[..len]);
                }
                Operation::DelayNs(ns) => {
                    // Busy-wait delay. At 160 MHz, ~6.25 ns per cycle.
                    // Conservative: assume ~10 ns per nop iteration.
                    let iters = (*ns as u64) / 10;
                    for _ in 0..iters {
                        cortex_m::asm::nop();
                    }
                }
            }
            if result.is_err() {
                break;
            }
        }

        // Deassert CS at the end of the transaction (always, even on error).
        // SAFETY: `cs_deassert` is a thin GPIO-BSRR write; single-threaded secure world.
        unsafe {
            cs_deassert();
        }

        result
    }
}
