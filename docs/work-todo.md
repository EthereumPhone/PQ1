# PQSigner OS -- Work TODO

Tracks what remains to go from "working dual-SE demo" to "end-to-end hardware wallet on STM32U585 + OPTIGA Trust M + SE050, PIN-gated, doing real transactions."

Last audited: 2026-04-13

---

## CRITICAL -- Blocks E2E

### 1. Dual-SE Entropy Split

**Status:** DONE (2026-04-12)

Implemented in `secure/src/dual_se.rs`. Feature flag `dual-se` (implies `tropic01-se` + `se050`).

- [x] Provisioning path: generate random `half_T`, compute `half_E = entropy XOR half_T`, store each on its respective chip
- [x] Unlock path: unlock Tropic01 → `master_T`; unlock SE050 → `master_E`; constant-time cross-verify; read and decrypt both halves; XOR-reconstruct full entropy
- [x] Reconstruction: `entropy = half_T XOR half_E`, verified via `kdf("sphincs-master", entropy, 0) == master_secret`
- [x] Single `DualSecureElement` struct wraps both SEs, implements `WalletStore`
- [x] New combined feature flag `dual-se` enables both `se050` and `tropic01-se`
- [x] Conditional `#[cfg]` gates in `main.rs` support mock-se, standalone tropic01-se, standalone se050, and dual-se

**Files created:** `secure/src/dual_se.rs`
**Files changed:** `secure/src/main.rs`, `secure/Cargo.toml`

---

### 2. Real SPI Driver for Tropic01

**Status:** DONE (2026-04-12)

Bare-metal SPI driver at `secure/src/hw/spi_hw.rs` (init) + `secure/src/hw/spi.rs` (`SpiDevice` impl).

- [x] `embedded_hal::spi::SpiDevice` impl for STM32U585 SPI peripheral (`Stm32Spi`)
- [x] Default: SPI2 on PB12=CS, PB13=SCK (AF5), PB14=MISO (AF5), PB15=MOSI (AF5)
- [x] `spi1-arduino` feature: SPI1 on PE12=CS, PE13=SCK (AF5), PE14=MISO (AF5), PE15=MOSI (AF5) — Arduino R3 headers for MicroE Clicker via SE050 shield
- [x] 5 MHz clock (160 MHz PCLK / 32), SPI Mode 0 (CPOL=0, CPHA=0), MSB first
- [x] Polling-based full-duplex transfers with timeout
- [x] `tropic01_se.rs` `with_session!` macro auto-selects `Stm32Spi` on `stm32u585`, `SemihostingSpi` on QEMU
- [x] SPI peripheral initialized in `main.rs` boot sequence (after `rcc::init()` + `sau::init()`)
- [x] Post-reboot ~10 ms delay before Noise_KK1 handshake (required for back-to-back sessions)
- [x] Tested: full provisioning + MACD PIN unlock on real STM32U585 + Tropic01 MicroE Clicker (SPI1 path)

**Files created:** `secure/src/hw/spi_hw.rs`, `secure/src/hw/spi.rs`
**Files changed:** `secure/src/hw/mod.rs`, `secure/src/tropic01_se.rs`, `secure/src/main.rs`

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

Each SE has independent retry counters (Tropic01: 10 MACD-based attempts, SE050: 10 UserID attempts). The design requires atomic unlock of both chips or neither.

**What's needed:**
- [ ] Intent log in secure flash: write `PENDING{attempt=N}` before attempting either chip
- [ ] Boot-time recovery: if intent log found, reconcile both chips to post-attempt state
- [ ] Wipe-on-disagreement: if the two counters ever disagree, erase everything
- [ ] Coordinate MAX_ATTEMPTS across both SEs (pick min of 9 and 10, or align)

**Files to create:** `secure/src/intent_log.rs`
**Files to change:** `secure/src/main.rs`, `secure/src/crypto.rs`, `secure/src/pin.rs`

---

## HIGH -- Security-critical or blocks dual-SE

### 6. PIN Entry Digit Scrambling

**Status:** NOT STARTED

PIN entry UI (`secure/src/ui/pin_entry.rs`) currently presents digits in fixed 0-9 order. An attacker observing button presses (shoulder-surfing, overhead camera, compromising EMI) can reconstruct the PIN from the press pattern alone. Scrambling the digit layout per-entry decouples button positions from digit values.

**What's needed:**
- [ ] Generate a fresh random permutation of 0-9 on every PIN entry session, using the hardware TRNG (never software PRNG)
- [ ] Render the scrambled layout on the OLED; confirm/cancel buttons keep fixed positions
- [ ] Ensure the permutation lives only in secure-world SRAM and is zeroized after PIN entry completes (success, cancel, or timeout)
- [ ] Constant-time digit selection -- no secret-dependent branches or lookup-table timing leaks
- [ ] Re-scramble after each digit (optional, defeats memorization of the layout between digits)

**Files to change:** `secure/src/ui/pin_entry.rs`, `secure/src/ui/oled.rs`

---

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

### 15. Hash-Signature Firmware Update Model

**Status:** NOT STARTED (design complete, see README.md "Firmware Update Model")

Instead of signing firmware binaries, the manufacturer signs the measurement hash (the same SHA-256 displayed as 8 BIP-39 words at boot). Users build from source, download the published signature, and flash. The device verifies the signature and that the hash matches the installed firmware.

**What's needed:**
- [ ] ML-DSA-44 signature verification in secure world (`slh-dsa` or `ml-dsa` crate)
- [ ] Manufacturer public key storage in OTP or WRP-protected flash
- [ ] Signature storage: dedicated flash page outside the measured region, or USB transfer during update
- [ ] Update handshake protocol: companion app sends firmware + signature over USB
- [ ] Boot-time verification: hash firmware, verify signature, reject on mismatch
- [ ] Key rotation mechanism: signed key-update message from current key to new key
- [ ] CI/CD: build firmware, compute hash, sign with manufacturer key, publish signature to GitHub Releases
- [ ] Companion app: embed `fwmeasure` logic + sparse-checkout repo build for full reproducible verification

**Files to create:** `secure/src/update.rs` (update protocol), `secure/src/fw_verify.rs` (signature verification)
**Files to change:** `secure/src/main.rs` (boot-time verification), `secure/src/hw/flash.rs` (signature page)

---

### 16. Immutable Bootloader (Defense-in-Depth)

**Status:** NOT STARTED

Split the firmware measurement code into a separate immutable bootloader in WRP-locked flash pages. Protects against a compromised update that replaces both the firmware and the measurement code simultaneously.

**What's needed:**
- [ ] Separate bootloader binary with its own linker script (ORIGIN = 0x0C000000, ~16-32 KB)
- [ ] Minimal OLED driver, SHA-256, BIP-39 wordlist, I2C init, GPIO buttons in bootloader
- [ ] Main firmware linker script updated: ORIGIN starts after bootloader region
- [ ] WRP option bytes to permanently protect bootloader flash pages
- [ ] Bootloader: hash firmware region, display 8 words, verify signature, jump to main firmware
- [ ] HDP activation: bootloader becomes execute-only after measurement (optional, for attestation key protection)

**Files to create:** `bootloader/` (new binary crate), `bootloader/memory.x`, `bootloader/src/main.rs`
**Files to change:** `secure/memory-stm32u585.x` (adjust ORIGIN), `Makefile` (bootloader build target)

---

### 17. Power Management

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
| 2026-04-12 | #2 Real SPI Driver | Bare-metal SPI driver (SPI2/PB12-15 default, SPI1/PE12-15 `spi1-arduino`) with `embedded_hal::SpiDevice` impl. Tested on real STM32U585 + Tropic01 MicroE Clicker |
| 2026-04-12 | #1 Dual-SE Entropy Split | XOR split via `DualSecureElement` in `dual_se.rs`, `dual-se` feature flag |
| 2026-04-13 | OPTIGA Trust M driver | Full IFX I2C stack + shielded connection + WalletStore impl. Dual-SE updated to OPTIGA Trust M + SE050 |
| 2026-04-14 | Firmware measurement | Boot-time SHA-256 of secure flash → 8 BIP-39 words on OLED. Host tool `fwmeasure` for reproducible-build comparison |
| 2026-04-14 | SE050 PIN-lockout wipe | Two-entry TAG_POLICY with admin UserID at 0x7B06_00A0; admin PIN generated via STM32 TRNG + persisted to secure flash page 125; round-trip selftest at first-boot; crash-safe wipe flag. `make se050-admin-wipe-e2e` validated PASS on hardware. Full docs in docs/se050-factory-reset.md |
| 2026-04-14 | Per-chain key derivation + OTS tracking | Fixed `sign_and_emit.rs` to use `derive_main_key_from_entropy(entropy, chain_id, key_index)` instead of legacy single-key path. Wired key_index/ots_index from v2 USB handler through to secure world via bit-31 flag on total_len. Added session-scoped OTS monotonicity enforcement in SecureState. |
