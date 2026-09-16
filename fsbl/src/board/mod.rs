//! Board pin map for the FSBL display port, selected at compile time.
//!
//! The FSBL drives exactly one board-dependent peripheral: the NV3007 SPI LCD
//! it renders the firmware fingerprint on. This module holds that pin map —
//! and nothing else — one file per physical board, so [`crate::nv3007`] reads
//! constants instead of hard-coding a port base.
//!
//! ## Why this is a SUBSET of `secure/src/board/`, not a move of it
//!
//! The secure world has the full map (console UART, both SE buses, buttons,
//! USB, consumption mask, SCA trigger, free pins). Hoisting it into a shared
//! crate would break the nine `include_str!` pins that read
//! `secure/src/board/{mod,iota2,pq1}.rs` by relative path
//! (`se050_under_test`, `hw_platform_under_test`, `hw_io_under_test`), so the
//! FSBL keeps a deliberately narrow copy of only the `LCD_*` facts it
//! consumes. Drift is caught by a test, not by construction:
//! `fsbl-tests/tests/source_invariants.rs` asserts every `pub const LCD_`
//! line here appears verbatim in the secure board file for the same board.
//!
//! ## Selection is MANDATORY — there is no default
//!
//! Naming no board is a compile error, and naming both is a compile error.
//! This is not a style choice; it is the retraction of an earlier "opt-in to
//! pq1" model in the secure crate, where `board-iota2` was inert and the
//! *absence* of `board-pq1` meant iota2. That made "forgot to choose"
//! indistinguishable from a valid choice, and it silently compiled the iota2
//! pin map onto pq1 silicon (`make build-hw-prodtest BOARD=pq1`, whose
//! hardcoded `--features` list carried no board).
//!
//! The FSBL has a stronger reason to refuse than the secure world does: it is
//! the *measuring* stage. A wrong-board FSBL does not fail loudly — it drives
//! pads that are not bonded on a 48-pin part, renders nothing, and branches
//! into the slot anyway, so the fingerprint window that invariant #10 rests on
//! is silently absent.
//!
//! Note the fence below is UNCONDITIONAL. The secure world's equivalent is
//! gated on `cfg(feature = "stm32u585")`; the FSBL has no such feature (it
//! only ever builds for `thumbv8m.main-none-eabi`), so copying that form would
//! have produced a fence that can never fire — exactly the silent-guard bug
//! this design exists to prevent.

#[cfg(all(feature = "board-iota2", feature = "board-pq1"))]
compile_error!(
    "FSBL_BOARD_AMBIGUOUS: board-iota2 and board-pq1 are mutually exclusive — \
     pick exactly one. Use `make <fsbl target> BOARD=iota2|pq1`."
);

#[cfg(not(any(feature = "board-iota2", feature = "board-pq1")))]
compile_error!(
    "FSBL_BOARD_UNSET: every FSBL build must name its board — pass `board-iota2` \
     or `board-pq1`. `make <target> BOARD=iota2|pq1` derives it, but a recipe or \
     test with a HARDCODED --features list must append $(BOARD_FEATURE) itself. \
     Without a board the LCD pin map is undefined, and a wrong map is SILENT on \
     this die: writes to an unbonded port still succeed, so the FSBL renders \
     nothing and branches anyway, dropping the boot-fingerprint window."
);

#[cfg(feature = "board-pq1")]
mod pq1;
#[cfg(feature = "board-pq1")]
pub use pq1::*;

#[cfg(all(feature = "board-iota2", not(feature = "board-pq1")))]
mod iota2;
#[cfg(all(feature = "board-iota2", not(feature = "board-pq1")))]
pub use iota2::*;

// ---------------------------------------------------------------------------
// Facts shared by both boards — same die, same peripheral addresses.
//
// Every value here is byte-identical to `secure/src/board/mod.rs`, and to the
// addresses `nv3007.rs` used to hard-code before this module existed.
// ---------------------------------------------------------------------------

/// RCC, **secure alias**. With `TZEN=1` this is the only alias that can
/// clock-gate peripherals classified secure-by-default; writing `GPIOAEN`
/// through the NS alias leaves the bit clear.
pub const RCC_S: u32 = 0x5602_0C00;

/// `RCC_AHB2ENR1` offset — GPIO port clock enables (`GPIOxEN` = bit x).
pub const RCC_AHB2ENR1_OFF: u32 = 0x8C;
/// `RCC_APB2ENR` offset — SPI1.
pub const RCC_APB2ENR_OFF: u32 = 0xA4;
/// `RCC_APB2RSTR` offset — peripheral resets matching `APB2ENR`.
pub const RCC_APB2RSTR_OFF: u32 = 0x7C;

/// `SPI1EN` — `RCC_APB2ENR` bit 12.
pub const RCC_SPI1EN_BIT: u32 = 1 << 12;
/// `SPI1RST` — `RCC_APB2RSTR` bit 12 (same position as the enable).
pub const RCC_SPI1RST_BIT: u32 = 1 << 12;

/// GPIO port base addresses, **secure alias** (`0x5202_0000 + 0x400 * n`).
///
/// Present on the die for every port regardless of package; only the *pads*
/// differ, which is why `GPIOE_S` is addressable but inert on `pq1` and why a
/// wrong pin map fails silently rather than faulting.
pub const GPIOA_S: u32 = 0x5202_0000;
/// Used by `pq1` only (DC / RST / backlight), hence unreferenced on `iota2`.
#[allow(dead_code)]
pub const GPIOB_S: u32 = 0x5202_0400;
/// Used by `iota2` only (the whole panel), hence unreferenced on `pq1`.
#[allow(dead_code)]
pub const GPIOE_S: u32 = 0x5202_1000;

/// SPI1, **secure alias** (SVD lists the NS alias `0x4001_3000`).
pub const SPI1_S: u32 = 0x5001_3000;

/// `RCC_AHB2ENR1` bit for a GPIO port base — `GPIOAEN` is bit 0, and each
/// subsequent port is the next bit up, matching the 0x400 base stride.
#[must_use]
pub const fn gpio_rcc_bit(port_base: u32) -> u32 {
    1 << ((port_base - GPIOA_S) / 0x400)
}

// ---------------------------------------------------------------------------
// GPIO register offsets, shared by every port.
// ---------------------------------------------------------------------------

pub const GPIO_MODER_OFF: u32 = 0x00;
pub const GPIO_OTYPER_OFF: u32 = 0x04;
pub const GPIO_OSPEEDR_OFF: u32 = 0x08;
pub const GPIO_PUPDR_OFF: u32 = 0x0C;
pub const GPIO_BSRR_OFF: u32 = 0x18;

/// `AFRL` (0x20) for pins 0..7, `AFRH` (0x24) for 8..15.
///
/// pq1's LCD pins (4/5/7) are the first in this driver's history to land in
/// the low half — iota2's 12..15 are all in `AFRH`, which is why the previous
/// hard-coded form wrote `AFRH` nibbles unconditionally.
#[must_use]
pub const fn afr_off(pin: u32) -> u32 {
    if pin < 8 {
        0x20
    } else {
        0x24
    }
}

/// Nibble position of `pin` within its AFR word.
#[must_use]
pub const fn afr_shift(pin: u32) -> u32 {
    (pin % 8) * 4
}
