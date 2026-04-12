# PQSigner OS -- Work TODO

Tracks what remains to go from "working single-SE demo" to "end-to-end hardware wallet on STM32U585 + Tropic01 + SE050, PIN-gated, doing real transactions."

Last audited: 2026-04-12

---

## CRITICAL -- Blocks E2E

### 1. Dual-SE Entropy Split

**Status:** NOT STARTED

The core security model. Currently, whichever SE is selected at compile time holds the **full 32-byte entropy** alone. The XOR-split design is not implemented.

**What's needed:**
- [ ] Provisioning path: generate entropy, split into `half_T` (Tropic01) and `half_E` (SE050), store each on its respective chip
- [ ] Unlock path: unlock Tropic01 -> read `half_T`; unlock SE050 -> read `half_E`; XOR-reconstruct
- [ ] HKDF reconstruction: add `hkdf` crate to `secure/Cargo.toml`, implement `E = HKDF(half_T XOR half_E)`
- [ ] Two global SE instances: `static mut SE_TROPIC01` and `static mut SE_SE050`, both active simultaneously
- [ ] New combined feature flag (e.g. `dual-se`) that enables both `se050` and `tropic01-se`
- [ ] Remove mutual exclusion in `#[cfg]` gates in `secure/src/main.rs`

**Files to change:** `secure/src/main.rs`, `secure/src/crypto.rs`, `secure/Cargo.toml`

---

### 2. Real SPI Driver for Tropic01

**Status:** NOT STARTED

`secure/src/semihosting_spi.rs` routes SPI through ARM semihosting to `/dev/ttyACM0`. Only works with a debugger attached. No real STM32U585 SPI driver exists. (For comparison, the SE050 I2C driver at `secure/src/se050/i2c.rs` is complete.)

**What's needed:**
- [ ] Implement `embedded_hal::spi::SpiDevice` for STM32U585 SPI peripheral (likely SPI1 or SPI2)
- [ ] GPIO pin config for MOSI/MISO/SCK/CS
- [ ] Clock config matching Tropic01 requirements
- [ ] Polling or DMA-based transfers
- [ ] Replace `SemihostingSpi` usage in `tropic01_se.rs` when `stm32u585` feature is active

**Files to create:** `secure/src/hw/spi.rs`
**Files to change:** `secure/src/tropic01_se.rs`, `secure/src/main.rs`

---

### 3. Physical GPIO Button Input

**Status:** STUB ONLY

The OLED UI backend (`secure/src/ui/oled.rs`) has button input explicitly marked as a stub. Currently uses semihosting file I/O -- a Python script (`tools/wallet_run_hw.py`) maps keyboard presses over TCP to probe-rs. Without real buttons, a user can't enter PINs, confirm transactions, or navigate the seed wizard.

**What's needed:**
- [ ] GPIO input driver for two physical buttons (left/right) on chosen pins
- [ ] Debouncing (hardware or software)
- [ ] Short-press vs long-press detection
- [ ] Wire into the `Input` struct in `secure/src/ui/oled.rs`
- [ ] Runs in secure world (buttons are secure-only peripherals per CLAUDE.md)

**Files to create:** `secure/src/hw/buttons.rs`
**Files to change:** `secure/src/ui/oled.rs`

---

### 4. Dual-Chip PIN Lockout Synchronization

**Status:** NOT STARTED

Each SE has independent retry counters (Tropic01: 10 MACD-based attempts, SE050: 9 UserID attempts). The design requires atomic unlock of both chips or neither.

**What's needed:**
- [ ] Intent log in secure flash: write `PENDING{attempt=N}` before attempting either chip
- [ ] Boot-time recovery: if intent log found, reconcile both chips to post-attempt state
- [ ] Wipe-on-disagreement: if the two counters ever disagree, erase everything
- [ ] Coordinate MAX_ATTEMPTS across both SEs (pick min of 9 and 10, or align)

**Files to create:** `secure/src/intent_log.rs`
**Files to change:** `secure/src/main.rs`, `secure/src/crypto.rs`, `secure/src/pin.rs`

---

## HIGH -- Security-critical or blocks dual-SE

### 5. SE050 SecureElement Trait Unification

**Status:** BY DESIGN, but blocks dual-SE

The SE050 has its own provisioning/unlock path (`provision_with_mnemonic_se050()`, `verify_pin_se050()`) that bypasses the `SecureElement` trait. For dual-SE, need a unified interface.

**What's needed:**
- [ ] Either implement `SecureElement` trait for SE050, or create a new `DualSecureElement` abstraction
- [ ] Unified provisioning that calls both SEs
- [ ] Unified unlock that reads from both SEs

**Files to change:** `secure/src/se050/mod.rs`, `secure/src/secure_element.rs`, `secure/src/crypto.rs`

---

### 7. HUK-SAES Key Wrapping (SE050 only)

**Status:** PARTIALLY DONE

Tropic01 pairing key: **DONE** — TRNG-generated per-device key stored in secure flash page 127 (`0x0C0FE000`) via `hw/flash.rs`. Written at first provisioning, read on every boot. Devkit keys (slot 0) kept as fallback.

SE050 SCP03 keys (`PLATFORM_ENC`, `PLATFORM_MAC`) are still hardcoded constants. On a real device, these should be wrapped by the STM32U585 Hardware Unique Key via the SAES peripheral.

**What remains:**
- [ ] SAES peripheral driver for STM32U585
- [ ] SE050 SCP03 key wrapping/unwrapping via HUK-SAES
- [ ] Optional: wrap the Tropic01 pairing key with HUK-SAES for defense-in-depth (currently plaintext in secure flash, protected by RDP level 2)

**Files to create:** `secure/src/hw/saes.rs`
**Files to change:** `secure/src/se050/scp03.rs`

---

### 8. Boot-Time SE Attestation

**Status:** NOT STARTED

The firmware trusts both SEs unconditionally on boot. Should verify identity and integrity before establishing encrypted sessions.

**What's needed:**
- [ ] SE050: attestation APDU commands to retrieve cert chain
- [ ] SE050: verify cert chain against pinned NXP root
- [ ] SE050: verify device UID matches pinned value in secure flash
- [ ] Tropic01: factory attestation signature verification (if TS1302 supports it)
- [ ] Refuse to boot if attestation fails

**Files to change:** `secure/src/se050/apdu.rs`, `secure/src/se050/mod.rs`, `secure/src/tropic01_se.rs`, `secure/src/main.rs`

---

## MEDIUM -- Defense-in-depth / PQ hardening

### 9. ML-KEM-1024 Inner Wrap

**Status:** NOT STARTED (no ML-KEM crate)

Adds post-quantum confidentiality on top of the classical encrypted channels (Noise_KK1, SCP03). Even if a CRQC breaks X25519 or AES-128, the entropy halves remain protected.

**What's needed:**
- [ ] Add ML-KEM-1024 crate (`no_std`) to `secure/Cargo.toml`
- [ ] Key generation on factory provisioning
- [ ] Encapsulate each entropy half before storing on SE
- [ ] Decapsulate after reading from SE during unlock
- [ ] Blob format: `ct || aead` on each chip

**Files to change:** `secure/Cargo.toml`, `secure/src/crypto.rs`, `secure/src/tropic01_se.rs`, `secure/src/se050/mod.rs`

---

### 10. Multi-Source RNG (3-way XOR)

**Status:** NOT STARTED (building blocks exist but unused)

`Tropic01SecureElement::get_trng_bytes()` exists but is never called. SE050 has TRNG capability but no APDU wrapper. Design: `STM32_TRNG XOR Tropic01_TRNG XOR SE050_TRNG`.

**What's needed:**
- [ ] SE050 TRNG APDU wrapper in `secure/src/se050/apdu.rs`
- [ ] XOR combination function in `secure/src/rng.rs`
- [ ] Use combined RNG for all entropy generation (seed, nonces, ephemeral keys)

**Files to change:** `secure/src/rng.rs`, `secure/src/se050/apdu.rs`

---

### 11. SCP03 Key Rotation for SE050

**Status:** NOT IMPLEMENTED (uses hardcoded NXP OEF 0xA921 platform keys)

Same keys across all SE050 chips of the same OEM firmware edition. Should be rotated to per-device keys during factory provisioning.

**What's needed:**
- [ ] SCP03 key rotation APDU
- [ ] Per-device key derivation (from device UID or HUK)
- [ ] Integration with HUK-SAES wrapping (item 7)

**Files to change:** `secure/src/se050/scp03.rs`, `secure/src/se050/apdu.rs`

---

### 12. SLH-DSA-SHA2-192f Migration

**Status:** 128f works. 192f documented as production target.

Parameter change in the SLH-DSA crate. Signature grows from 17,088 to 35,664 bytes. Changes the recovery contract (same 24 words produce different keys under different parameter set).

**What's needed:**
- [ ] Switch `slh-dsa` type parameter from `Sha2_128f` to `Sha2_192f`
- [ ] Update USB HID transport buffer sizes (signature is now ~35 KB)
- [ ] Update on-chain verifier contract to match
- [ ] Migration plan for any existing test wallets

**Files to change:** `secure/src/crypto.rs`, `secure/src/nsc/sign_and_emit.rs`, `nonsecure/src/usb/transport.rs`, contracts

---

## LOW -- Production infrastructure

### 13. OEMiROT Secure Boot (ML-DSA-65)

**Status:** NOT STARTED

Custom bootloader that verifies S-world and NS-world firmware images with ML-DSA-65 + Ed25519 hybrid before any code runs.

**What's needed:**
- [ ] Bootloader project (separate binary)
- [ ] ML-DSA-65 verification code
- [ ] Ed25519 fallback verification
- [ ] Public keys pinned in HDPL1
- [ ] STM32U585 RDP Level 2 lockdown

---

### 14. Firmware Update / OTA

**Status:** NOT STARTED

No flash programming, update protocol, or version management.

**What's needed:**
- [ ] Update protocol over USB (signed firmware images)
- [ ] Flash write driver for STM32U585 internal flash
- [ ] Rollback protection (monotonic counter)
- [ ] Integrity verification before boot

---

### 15. Power Management

**Status:** NOT STARTED

No sleep/idle power modes, watchdog, or graceful power-down sequences.

**What's needed:**
- [ ] IWDG (independent watchdog) setup
- [ ] Low-power sleep modes during idle
- [ ] Brownout detection -> zeroize secrets
- [ ] Graceful shutdown on power loss

---

## Completion Log

When a task above is completed, update it here with the date and a one-line summary.

| Date | Item | Summary |
|------|------|---------|
| | | |
