//! Test-only scaffold for the `secure-se050` slice.
//!
//! The production `se050` module is `#[cfg(all(feature = "se050",
//! not(test)))]` because:
//!   * `i2c.rs` binds `crate::hw::i2c_hw::I2C1` MMIO addresses that don't
//!     exist on host.
//!   * `t1oi2c.rs` calls `cortex_m::asm::nop()` in its busy-wait loops —
//!     the `cortex-m` crate is gated to `cfg(target_arch = "arm")` in
//!     `secure/Cargo.toml`, so it does not link on x86_64.
//!   * `apdu.rs` and `scp03.rs` ride on top of those two and on `crate::rng`
//!     / `crate::hw::secret_keys`, all of which are firmware-only.
//!
//! None of those files can be path-included verbatim under `cargo test`
//! without a heavier stubbing investment than the slice warrants. The
//! pure-logic primitives the slice depends on (`crate::iso7816::*`,
//! `crate::scp03_logic::*` — AES-128 ECB/CBC, CMAC-AES-128, the SP 800-108
//! KDF inputs, the GP `PUT KEY` builder, KCV) already live in always-on
//! modules with their own `#[cfg(test)] mod tests` blocks, so the AES /
//! CMAC / KAT / KDF surface is covered there and not duplicated here.
//!
//! What this scaffold adds is the slice-specific layer that is NOT
//! covered by `scp03_logic` or `iso7816`:
//!
//!   * Wire-format byte pins for the SE050 transport stack (T=1' over
//!     I²C, NAD/PCB/LEN/CRC layout, GP 1.0 CRC algorithm shape, frame
//!     size limits, R/S/I-block PCB encoding).
//!   * APDU-layer constants whose silent shift would break every
//!     handshake (SE050 AID, INS/P1/P2/TLV-tag triples, AR policy bit
//!     masks, the WRITE | AUTH_OBJECT INS combination — HW lesson #1).
//!   * SE050 OID assignments (the v6 `0x7B10_xxxx` range, the
//!     `ADMIN_WIPE_OBJ = 0x7B10_00A0` constant the dual-SE wipe path is
//!     wired to, the reserved-range filter inside the iterative-delete
//!     sweep).
//!   * SCP03-session control bytes (`KEY_VERSION = 0x0B`, EXTERNAL
//!     AUTHENTICATE P1 = 0x03 — HW lesson #6, the secure-messaging
//!     `apdu[0] |= 0x04` CLA flip, the counter init at `0x01`).
//!   * CLAUDE.md invariant pins: no classical signer references in the
//!     SE050 driver; admin policy entry grants ALLOW_DELETE only (never
//!     ALLOW_READ) so a compromised admin PIN cannot leak entropy
//!     (invariant #2, #5).
//!   * Re-implementation + cross-check of the GP 1.0 CRC-16 algorithm
//!     and the wrap_apdu SCP03 envelope so a refactor that "modernises"
//!     either to a more standard but incompatible variant fails the
//!     suite before it bricks every paired chip.
//!
//! Per the test-writing brief, the negative suite is the primary
//! deliverable: each `negative_*` test names the assumption being
//! attacked (KDF tag stability, OID range, INS mask, policy bit set,
//! counter wrap, missing CLEAR_LAST_ERROR-style guard) and asserts the
//! precise pin that proves the property still holds.

#[cfg(test)]
mod pure_tests;
