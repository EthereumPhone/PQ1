//! Typed MMIO register handles — encapsulates `read_volatile` /
//! `write_volatile` so peripheral drivers don't have to sprinkle
//! `unsafe` at every register touch.
//!
//! Each peripheral driver constructs `Reg32` / `RoReg32` handles **once**
//! at module scope (a single `unsafe` per address) and then uses safe
//! `.read()` / `.write()` / `.modify()` calls everywhere. The unsafety
//! moves from "every access" to "asserting once that this address is a
//! real, exclusively-owned MMIO register."
//!
//! ## Safety contract
//!
//! Construction is `unsafe`: the caller asserts that the address is a
//! 4-byte-aligned MMIO register and that no other code in the firmware
//! aliases the same physical register through a different handle. The
//! secure world is single-threaded and non-preemptive — once a driver
//! module owns a register, nothing else races it.
//!
//! After construction the API is safe: volatile semantics prevent the
//! compiler from reordering or elision; the address is `Copy`, so handles
//! can be passed by value without moving anything.
//!
//! ## What this does NOT cover
//!
//! - Bit-banding, atomic register sets (BSRR / BCRR style) — peripherals
//!   that need them should expose their own typed wrappers around a
//!   `Reg32` for clarity.
//! - DMA descriptors / shared-memory regions — those have lifetime
//!   constraints that need richer types than a fixed-address handle.

#![allow(dead_code)]

use core::ptr::{read_volatile, write_volatile};

/// Read/write 32-bit MMIO register.
#[derive(Copy, Clone)]
pub struct Reg32 {
    addr: *mut u32,
}

// SAFETY: `Reg32` is just a wrapped pointer to a fixed peripheral
// address. The peripheral itself is the synchronization point (single-
// threaded secure world); the handle has no interior state.
unsafe impl Send for Reg32 {}
unsafe impl Sync for Reg32 {}

impl Reg32 {
    /// # Safety
    /// `addr` must be a 4-byte-aligned MMIO register that the calling
    /// driver owns exclusively for the lifetime of the program.
    #[inline(always)]
    pub const unsafe fn new(addr: u32) -> Self {
        Self { addr: addr as *mut u32 }
    }

    #[inline(always)]
    pub fn read(self) -> u32 {
        // SAFETY: address validity is the construction precondition.
        unsafe { read_volatile(self.addr) }
    }

    #[inline(always)]
    pub fn write(self, v: u32) {
        // SAFETY: address validity is the construction precondition.
        unsafe { write_volatile(self.addr, v) }
    }

    #[inline(always)]
    pub fn modify(self, f: impl FnOnce(u32) -> u32) {
        self.write(f(self.read()));
    }

    #[inline(always)]
    pub fn set_bits(self, mask: u32) {
        self.modify(|v| v | mask);
    }

    #[inline(always)]
    pub fn clear_bits(self, mask: u32) {
        self.modify(|v| v & !mask);
    }

    /// Read register at `self.addr + offset` words. Useful for contiguous
    /// register banks (PKA RAM operand slots, e.g.).
    ///
    /// # Safety
    /// `offset` must point inside the same MMIO bank as `self`.
    #[inline(always)]
    pub unsafe fn read_at(self, offset: usize) -> u32 {
        // SAFETY: caller asserts offset is in-bank; volatile prevents the
        // compiler from speculating across the bank boundary.
        unsafe { read_volatile(self.addr.add(offset)) }
    }

    /// Write register at `self.addr + offset` words.
    ///
    /// # Safety
    /// `offset` must point inside the same MMIO bank as `self`.
    #[inline(always)]
    pub unsafe fn write_at(self, offset: usize, v: u32) {
        // SAFETY: caller asserts offset is in-bank.
        unsafe { write_volatile(self.addr.add(offset), v) }
    }
}

/// Read-only 32-bit MMIO register (status, digest output, etc.).
#[derive(Copy, Clone)]
pub struct RoReg32 {
    addr: *const u32,
}

// SAFETY: see `Reg32`.
unsafe impl Send for RoReg32 {}
unsafe impl Sync for RoReg32 {}

impl RoReg32 {
    /// # Safety
    /// Same contract as [`Reg32::new`].
    #[inline(always)]
    pub const unsafe fn new(addr: u32) -> Self {
        Self { addr: addr as *const u32 }
    }

    #[inline(always)]
    pub fn read(self) -> u32 {
        // SAFETY: address validity is the construction precondition.
        unsafe { read_volatile(self.addr) }
    }

    /// Read register at `self.addr + offset` words. Useful for contiguous
    /// register banks (e.g. HASH_HR0..HR7, RNG_DR repeated reads).
    ///
    /// # Safety
    /// `offset` must point inside the same MMIO bank as `self`.
    #[inline(always)]
    pub unsafe fn read_at(self, offset: usize) -> u32 {
        // SAFETY: caller asserts offset is in-bank; volatile prevents the
        // compiler from speculating across the bank boundary.
        unsafe { read_volatile(self.addr.add(offset)) }
    }
}
