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

**Status:** PHASE 1 LANDED — authoritative MCU-side counter in place. Phase 2 (reconciliation + FI-hardening + OPTIGA monotonic-counter migration) still owed.

Originally scoped for Tropic01 + SE050 before the OPTIGA + SE050 dual-SE cutover. The core problem remains the same: each SE has an independent retry counter, and without a shared gate an attacker who resets one (e.g. OPTIGA F1E1 via `Conf(E140)` PBS rewrite) can bypass the lockout on the other.

**Phase 1 — MCU-side authoritative counter (LANDED):**
- [x] **Secure-flash page 126 as attempt counter.** Each wrong PIN burns one QW (`[0x00; 16]`). Counter = number of programmed QWs. Reset = page erase (only after successful PIN). Capacity 32 attempts per layout; MAX_ATTEMPTS is 10. `secure/src/hw/flash.rs::pin_attempts_{read,bump,reset}`.
- [x] **Pre-commit pattern.** `nsc::gated_unlock` bumps the MCU counter BEFORE calling `WalletStore::unlock`, so a power-loss or glitch mid-SE-verify still charges the attempt. Mirrors Trezor `storage/storage.c:1171-1311`. `secure/src/nsc/mod.rs::gated_unlock`.
- [x] **Fault-injection guard.** Post-bump readback; if the programmed QW count didn't advance by exactly one, refuse the attempt with `InternalError` and do NOT call the SE driver. Prevents "glitch flash writes to burn SE attempts without MCU attempts."
- [x] **Every PIN entry point routes through `gated_unlock`:** `CMD_REQUEST_UNLOCK` (`nsc/cmd_request_unlock.rs`), PendSV idle-wipe re-unlock (`main.rs:PendSV`), post-first-boot interactive unlock. First-boot auto-unlock and e2e-test fast-path deliberately bypass (PIN is known-correct by construction; bypass avoids a flash page cycle per provisioning).
- [x] **Boot-time lockout check.** `main.rs` checks page 126 at boot; if already at MAX, run `factory_reset_admin` + erase page 126 before any unlock path runs. Handles "prior session burned last attempt but crashed before `trigger_lockout_wipe` completed."
- [x] **Lockout path clears counter.** `trigger_lockout_wipe` erases page 126 after the SE wipe so the next boot sees unprovisioned-state + blank counter → first-boot wizard, not a lockout loop.

**Phase 2 (not yet started):**
- [ ] **Boot-time reconciliation against OPTIGA F1E1.** Trezor `storage.c:1677-1700` pattern: read both MCU remaining + OPTIGA remaining, accept the minimum. Today the OPTIGA soft counter (F1E1) still bumps independently via `authenticate_and_read`; if it disagrees with the MCU counter (e.g. attacker reset OPTIGA), the stricter of the two wins via independent lockout, but explicit reconciliation would harden the "attacker can run until BOTH lock out" upper bound.
- [ ] **Cryptographic FI checksum on the bump.** Trezor uses a paired counter (`ctr` + `ctr_ck`) and `handle_fault()` on mismatch. Our current post-bump readback catches most fault classes but doesn't distinguish "flash glitch" from "all state intact but count wrong" — a checksum would tighten it.
- [ ] **SE050 reconciliation.** SE050's silicon retry counter can't be read without burning an attempt (only surfaces via `SW=0x63Cx` in verify response). A voluntary "peek" via a known-wrong PIN would burn one attempt to sync — counter-productive. Design TBD; the current defense ("SE050 is the silicon-hard final gate, we trust it") is acceptable.
- [ ] **Migrate OPTIGA counter to `0xE120` hardware-monotonic.** Tracked separately in #24 P1 — closes the "OPTIGA counter is soft" hole entirely. Once `0xE120` lands, OPTIGA is silicon-hard too, and the MCU counter becomes a redundant consistency gate rather than the sole authoritative source.

**Files created / changed in Phase 1:**
- Added: `pin_attempts_{read,bump,reset}` + `PIN_ATTEMPTS_PAGE_ADDR/NUM` in `secure/src/hw/flash.rs`.
- Added: `nsc::gated_unlock` in `secure/src/nsc/mod.rs`.
- Changed: `secure/src/nsc/cmd_request_unlock.rs` — routes through `gated_unlock`, adds lockout-boot-check in wipe path.
- Changed: `secure/src/main.rs` — PendSV + boot-interactive unlock paths route through `gated_unlock`; boot-time lockout check.

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

### 7. Three-tier key hierarchy (DHUK + BHK + OTP), Trezor-parity

**Status:** PARTIALLY DONE — OTP tier landed under #24; DHUK + BHK tiers NOT STARTED. Ordering: DHUK before BHK (BHK is DHUK-wrapped at rest).

Mirrors Trezor Safe 3/5's three-tier model on STM32U5. Verbatim references into `/home/nicola/repos/trezor-firmware` noted per tier below.

> See also #23 (Safe 7 gap closure), #20 (production key rotation), #24 (OPTIGA pairing restructure — the OTP tier that this item extends). Trezor Safe 7 extends the three-tier model with seed-decryption-key derivation from MCU flash; our wrapping scope here stays narrower by design because our seed never lands on MCU flash (dual-SE XOR split — see CLAUDE.md invariant #1).

#### Tier 1 — DHUK (silicon-fused, software-inaccessible)

**What it is.** STM32U5 Device Hardware Unique Key, TRNG-burnt by ST at wafer sort, never exposed to firmware. Usable only as a key *selector* through the SAES peripheral. Trezor wrapper: `core/embed/sec/secure_aes/stm32u5/secure_aes.c:48-60` (`get_keysel()`, `SECURE_AES_KEY_DHUK_SP`) + ECB driver at lines 73-220. Used as KEK for master-key slots in flash (`core/embed/sec/secret/stm32u5/secret.c:326,366`).

**What it replaces in our codebase.** `hw::secret_keys::derive_into` currently does `HKDF-Expand(OTP_master_read_from_flash, label)`. DHUK migration replaces it with `SAES-CMAC(DHUK_selector, domain_label || counter)`. Caller API `domain_tag → bytes` stays identical — every existing consumer (`optiga_pairing_secret`, `se050_scp03_{enc,mac}_key`, `tropic01_pairing_key`) is transparent.

**Threat closed.** Post-migration, secure-world RCE can still *use* SAES to compute the derivation with DHUK as the key, but cannot dump DHUK bytes to exfiltrate or replay on a different chip or in emulation. The current "dump OTP master → replicate all pairings off-chip" path closes entirely.

**What's needed — P0:**
- [ ] `secure/src/hw/saes.rs`: SAES driver. Init (enable clock, check `RCC_AHB2ENR2.SAESEN`), ECB encrypt/decrypt under `KEYSEL=DHUK`, CMAC mode for 32-byte derivations. Follow `stm32u5xx_hal_cryp.c` for register layout.
- [ ] Confirm SAES bit-field positions against RM0456 + CMSIS `stm32u585xx.h` (flagged unverified in #20 — same lookup applies here).
- [ ] Rewrite `hw::secret_keys::derive_into` to use SAES-CMAC(DHUK, info) for 32-byte outputs, chained CMAC for 64-byte outputs (PBS). Delete the HKDF path but preserve the `otp-hardcoded-master-key` dev feature — under that feature, fall back to the HKDF-over-constant path so QEMU + bench without SAES-DHUK still work.
- [ ] Remove `hw::otp::read_device_master` / `ensure_device_master` / `burn_device_master` once no caller remains. `MASTER_KEY_ADDR..MASTER_KEY_ADDR+32` becomes reserved.

#### Tier 2 — BHK (Boot Hardware Key, flash-stored, software-inaccessible after boot)

**What it is.** 32 bytes of TRNG output generated once at first-boot provisioning, encrypted under DHUK via SAES-ECB, stored in a dedicated secure-flash page. At every subsequent boot: unwrap with DHUK into STM32 TAMP backup registers, then **lock** `TAMP_S->SECCFGR` so only the SAES peripheral can use it (as a second key selector — `SECURE_AES_KEY_BHK`). Firmware can never read BHK bytes after boot lock.

Trezor references: `core/embed/sec/secret/stm32u5/secret.c:426-442` (`secret_bhk_regenerate` — TRNG fill + flash write), `secret.c:593-612` (`secret_prepare_fw` — TAMP load + lock at boot), `secret.c:177-179` (the lock comment quoted above). Layout: `core/embed/models/T3W1/secret_layout.h:57-58` (`SECRET_BHK_OFFSET=0x2000`, `SECRET_BHK_LEN=0x20`). SAES selector: `secure_aes.c:52` (`SECURE_AES_KEY_BHK`).

**Why BHK in addition to DHUK.** Defense-in-depth across two *independent* SAES key selectors. Compromising DHUK alone (hypothetical SAES glitch, or ST errata disclosing DHUK semantics) leaves BHK-wrapped operations sealed — the attacker would also need to read flash *before* `TAMP_S->SECCFGR` lock completes at boot. Compromising BHK alone (e.g. flash dump of wrapped BHK + offline DHUK-ECB crack) does not unlock DHUK-wrapped master-key slots. Neither alone defeats the user PIN path because that also consumes OTP randomness (tier 3).

Quoted from Trezor `secret.c:593-595`:
> "The BHK is copied to the backup registers, which are accessible by the SAES peripheral. The BHK register is locked, so the BHK can't be accessed by the software."

**Which SE goes under which key.** Recommended split:
- DHUK → OPTIGA PBS (current derivation), user-PIN storage-wrap (if we ever add one)
- BHK → SE050 SCP03 enc+mac, SE050 admin PIN, TROPIC01 pairing

That way a compromise of one selector exposes at most one SE's channel. If BHK provisioning is deferred (dev boards), a "BHK absent → fall back to DHUK for those keys" gate keeps builds running, with a stern log line so production firmware can refuse to boot BHK-less.

**What's needed — P0 (requires Tier 1 landed first):**
- [ ] `secure/src/hw/bhk.rs`: first-boot generation (`rng::fill` 32 bytes), DHUK-ECB wrap via `hw::saes`, flash write to a new dedicated secret-flash page (TBD — new region, distinct from current `ADMIN_PAGE_ADDR=0x0C0F_A000`). Subsequent-boot load + TAMP-write + SECCFGR lock.
- [ ] `TAMP_S->SECCFGR` lock sequence: set `BHKLOCK` bit (STM32U5 has this per RM0456 §"TAMP" — verify exact bit). Once locked, register is read-0 from software; SAES peripheral still sees it.
- [ ] Extend `hw::secret_keys` with a second derive path that uses `SAES-CMAC(BHK_selector, info)`. Split existing callers per the DHUK/BHK table above.
- [ ] Dev gate: `otp-hardcoded-master-key` also hardcodes a BHK test constant (distinctive ASCII, e.g. `"PQSIGNER-TEST-BHK-DHUK-WRAP-v1!!"`) so bench boards without real SAES can exercise derivations.
- [ ] Integration check: a reflash that preserves OTP also preserves the DHUK-wrapped-BHK on flash (same page across updates). If a firmware update would erase that page, restore-from-wrap fails and the chip falls into the same class of brick as the original OPTIGA bug. Treat the BHK page as **write-once-at-provisioning, read-only from firmware** — no firmware-update path may touch it.

#### Early-adopt: derive SE050 admin PIN from OTP master (pre-DHUK)

**Status:** **CORE PATH DONE (2026-04-23).** Both `Se050::store_objects` (provisioning) and `Se050::factory_reset_admin` (wipe) now derive the 16-byte admin PIN via `hw::secret_keys::se050_admin_pin()` → HKDF-Expand over the OTP master. The flash page 125 PIN slot is no longer consulted on the production provision/unlock/wipe paths. `dual-se-admin-wipe-e2e` PASSES all 8 steps on real silicon with the new derivation (commits `1bfb572` + `e6b8c2f` + `38982c7`).

**Remaining cleanup (non-blocking):** `hw::flash::read_admin_pin` / `write_admin_pin` are still called from a handful of legacy / test paths (`se050/mod.rs:749,825`, `dual_se.rs:389,608`, `main.rs:1799`). Delete those + retire `ADMIN_PIN_OFFSET` entirely once the migration is fully settled — the wipe-in-progress flag at `WIPE_FLAG_OFFSET=16` stays on page 125 (different slot), no flash-layout change needed. Until the legacy readers are removed the slot is dead storage (never read by production code paths) but still burns a quadword.

**The gap.** `secure/src/se050/mod.rs:35-42` already carries an aspirational docstring:

> The admin PIN itself is never persisted in plaintext anywhere — derived on demand via `crypto::derive_se050_admin_pin(&pbs)`.

But `crypto::derive_se050_admin_pin` was never written. The actual implementation at `se050/mod.rs:1196-1224` does `rng::fill(&mut admin_pin); flash::write_admin_pin(&admin_pin)` on first provision, and `flash::read_admin_pin(...)` on every wipe. The PIN exists only in flash page 125, and any action that erases page 125 without simultaneously deleting the on-chip admin UserID renders the chip permanently un-wipe-able.

This bit us on 2026-04-21: the first iteration of the OPTIGA admin-wipe e2e test erased page 125 as post-test hygiene (to clear the armed-wipe flag). The bench SE050 still had its production admin UserID but the flash now held zeros. All subsequent dual-SE admin-wipe attempts on that chip fail at `policy_roundtrip_selftest` because the newly-generated admin PIN doesn't match what the chip is holding.

**The fix.** Add `hw::secret_keys::se050_admin_pin() -> [u8; 16]`:

```rust
pub fn se050_admin_pin() -> Result<[u8; 16], OtpError> {
    let mut out = [0u8; 16];
    derive_into(b"pqsigner/se050-admin-pin-v1", &mut out)?;
    Ok(out)
}
```

Rewire `Se050::provision` to call it instead of `rng::fill` + `write_admin_pin`. Rewire `Se050::factory_reset_admin` to call it instead of `read_admin_pin`. Delete the `ADMIN_PIN_OFFSET=0` slot from page 125 entirely — the wipe-in-progress flag at `WIPE_FLAG_OFFSET=16` moves to a new home (either a dedicated 16-byte page or an OTP one-shot bit; OTP is more aligned with "this action is permanent").

**What this unlocks:**
- Bench chips that lose page 125 still boot with a reproducible admin PIN → wipe path works through cross-test contamination.
- First step of work-todo #7 Tier 1 lands ahead of the full SAES migration. When DHUK goes live, this helper flips from `HKDF(OTP_master, ...)` to `SAES-CMAC(DHUK, ...)` with no caller changes.
- Removes a production attack surface: a flash-extraction attacker no longer gets the admin PIN out of a live page 125 read.

**Dev/migration trap** (document + guard, don't silently change):
- Any chip already provisioned with a TRNG-random admin PIN (i.e., every current dev unit) has a chip-side admin UserID whose PIN doesn't match the derived value. Upgrading those chips requires admin re-provisioning under the OLD (flash-read) PIN — which works only if the flash hasn't been erased. Once this change lands, there's a one-shot "migrate existing admin PIN" step at first boot of the new firmware that reads the old PIN from page 125, deletes the on-chip admin UserID under admin auth, and rewrites with the derived PIN. If page 125 is already blank at that point, migration fails and the chip joins the "cannot auto-recover" set (this bench chip is the first member).
- Once DHUK-based (Tier 1), the derivation produces a DIFFERENT value from the HKDF-over-OTP-master version of the same label. Document the one-shot rotation as part of the DHUK migration plan; do NOT silently bump the derivation algorithm without a paired on-chip rotation.

**Files to create:** none — extend `secure/src/hw/secret_keys.rs` in place.
**Files to change:** `secure/src/hw/secret_keys.rs` (add helper), `secure/src/se050/mod.rs` (provision + factory_reset_admin), `secure/src/hw/flash.rs` (retire admin-PIN slot, keep wipe flag).

**This work-todo is explicitly pre-Tier-1:** landing it does NOT require the SAES driver. HKDF over the existing OTP master is good enough until DHUK comes online. The API will NOT change when we later move to SAES — only the internal `derive_into` implementation does.

---

#### Tier 3 — OTP randomness (software-readable, per-device salt)

**What it is today.** `hw::otp::read_device_master` returns 32 TRNG bytes burnt at first-boot into `0x0BFA_0080..0x0BFA_00A0`. Used via `hw::secret_keys` for all SE pairing derivations.

**What Trezor does with OTP.** 256 TRNG bytes at factory into `FLASH_OTP_BLOCK_RANDOMNESS` (`otp_layout.h:4-12`), consumed as `hardware_salt = SHA256(OTP_randomness)` in the PBKDF2 PIN-stretching chain (`storage.c:76,978` `derive_kek_v4`). Independent of DHUK/BHK.

**Direction after DHUK lands.** Repurpose OTP bytes 128..160 solely as PBKDF2 salt input for any future PIN-gated MCU-side storage — not as a direct derivation root. All SE pairing secrets move up to tiers 1+2. Specifically:
- [ ] Expose `hw::otp::read_otp_randomness() -> [u8; 32]` (public read; bytes are non-secret — they're salt, not key).
- [ ] When a future PIN-gated MCU storage wrap lands (e.g. for at-rest cached companion objects), its KDF is `PBKDF2(user_pin, SHA256(otp_randomness) || storage_salt, 20_000)` matching Trezor's `derive_kek_v4`.

#### Ordering / dependencies

1. `otp-hardcoded-master-key` stays as the dev-bench safety valve throughout all three tier migrations. Never ship. Guarded by compile_error gate already in `nsc/mod.rs`.
2. #24 (OPTIGA pairing restructure) landed the OTP tier + `hw::secret_keys` API + re-rooted `hw::huk::derive_device_key` off `firmware_hash`. **Done.**
3. Work-todo #20 (production key rotation) still assumes the HKDF-over-OTP path for SE050 SCP03 + TROPIC01 migration. When Tier 1 lands, #20 pivots to calling the same `secret_keys` API (now SAES-CMAC-backed) — no change in #20's scope, only in the underlying implementation.
4. Tier 2 (BHK) after Tier 1, because BHK-at-rest is DHUK-wrapped.
5. After Tier 1+2, `hw::huk::derive_device_key` becomes the last software-readable root and should be deleted — see header comment in that file which already flags this retirement.

#### Files

**Create:** `secure/src/hw/saes.rs`, `secure/src/hw/bhk.rs`.

**Change:** `secure/src/hw/secret_keys.rs` (swap HKDF → SAES-CMAC under a compile-time selector), `secure/src/hw/otp.rs` (narrow the master-key region to salt duty, or deprecate entirely once DHUK lands), `secure/src/hw/huk.rs` (delete after tier 2), `secure/src/hw/flash.rs` (add BHK page region), `secure/Cargo.toml` (new dev-gate feature for hardcoded BHK under `otp-hardcoded-master-key`).

#### Wipe-flow impact (cross-ref the dual-SE admin wipe)

None visible to SE-side wipe code. The SE drivers continue to call `secret_keys::optiga_pairing_secret()` / `secret_keys::se050_scp03_enc_key()` etc. What changes underneath: Tier 1 migration makes those bytes computable only via SAES on-chip. The wipe sequence (OPTIGA `Conf(E140)` DATA overwrites + SE050 admin-UserID DELETE) is unchanged. One new cleanup question: if the BHK page becomes corrupted (brown-out mid-wipe, bit-flip), what's recovery? Options: (a) treat as permanent brick (Trezor's answer), (b) fall through to DHUK-only with every-SE-pairing re-derivation + forced re-provisioning of both SEs. Decide before shipping.

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

### 11. SCP03 Key Rotation for SE050 (wire derived-root + GP PUT KEY ceremony)

**Status:** NOT IMPLEMENTED — dormant derivation infrastructure landed in #24, feature flag + ceremony still owed. Wire-up is the immediate parallel to OPTIGA's OTP-derived PBS.

Today `secure/src/se050/scp03.rs:21-30` hardcodes the NXP AN12436 Rev 2.4 defaults for SE050E OEF `0xA921` (`PLATFORM_ENC` + `PLATFORM_MAC` 16-byte constants, `KEY_VERSION = 0x0B`). Every device built from the same firmware presents identical static keys → single-firmware-extraction breaks the entire fleet's SE050 channel.

**The deterministic-root infrastructure already exists** (landed in #24, currently dormant):
```rust
// secure/src/hw/secret_keys.rs:126-137
pub fn se050_scp03_enc_key() -> Result<[u8; 16], OtpError> { ... }
pub fn se050_scp03_mac_key() -> Result<[u8; 16], OtpError> { ... }
```
Both currently `HKDF-Expand(OTP_master, "pqsigner/se050-scp03-{enc,mac}-v1")`. Under #7 Tier 1 migration the internal primitive becomes `SAES-CMAC(DHUK, label)`; under Tier 2 it shifts to `SAES-CMAC(BHK, label)` for the per-SE selector split. Callers never change.

#### The problem with a naive swap

`PLATFORM_ENC`/`PLATFORM_MAC` are what the firmware uses; the *chip* has its own copy of the same bytes at keyset `0x0B` (factory-provisioned by NXP). They have to match byte-for-byte for `INITIALIZE UPDATE` to produce a matching CardCryptogram. So:

- Changing just firmware to use derived keys → SCP03 establishment fails against a factory-default chip (key mismatch at the MAC step).
- We must do a GP `PUT KEY` ceremony against the chip THAT MATCHES the firmware's new derivation, and then commit the firmware to use the new keyset version.

This is a two-build, one-chip-operation flow.

#### Three-stage landing

**Stage A — derivation plumbing (reversible, ready to land now):**
- [ ] Add a helper `secure/src/se050/scp03.rs::load_platform_keys()` that returns `Result<([u8; 16], [u8; 16]), Se050Error>`. Default variant returns `(PLATFORM_ENC, PLATFORM_MAC)` (hardcoded); gated variant under a new Cargo feature returns `(secret_keys::se050_scp03_enc_key()?, secret_keys::se050_scp03_mac_key()?)`.
- [ ] Change `scp03.rs:211-213` `kdf(&PLATFORM_ENC, ...)` → `kdf(&platform_enc, ...)` where `platform_enc` comes from `load_platform_keys()`.
- [ ] Change `KEY_VERSION = 0x0B` (scp03.rs:30) to a const that flips to `0x11` under the same feature.
- [ ] **Feature name**: `se050-derived-scp03` (narrower than "rotate" — this step picks the root, doesn't mutate chip state yet).
- [ ] Under the feature ON: a build that targets a post-rotation chip. Under the feature OFF: the default build, targets a factory-default chip. Either can talk to its own chip, neither can talk to the other — a device committed to derived keys is boot-incompatible with default-key firmware.

**Stage B — one-shot rotation ceremony (irreversible per chip; sacrificial-part-first):**
- [ ] New `se050-rotate-scp03` Cargo feature (P0 guardrail, default OFF, implies `se050-derived-scp03`). At first boot of a fresh chip:
  1. Establish SCP03 against default keyset `0x0B` with hardcoded constants (revert helper to hardcoded path for just this one boot).
  2. Compute new keys via `secret_keys::se050_scp03_{enc,mac}_key()`.
  3. Compute Key Check Value for each: `KCV = AES-ECB-Enc(key, zeros)[..3]` (per GP 2.3 §11.8 + AN12436 §5.2).
  4. AES-ECB-wrap each new key under the corresponding current key: `wrapped = AES-ECB-Enc(current_key, new_key)`.
  5. Send GP `PUT KEY` (`CLA=0x84 INS=0xD8 P1=0x81 P2=<new_kvn=0x11>`) with body:
     `[new_kvn] [key_type=0x88 (AES)] [len=0x10] [wrapped_enc] [kcv_enc_len=0x03] [kcv_enc]`
     × 3 for ENC / MAC / DEK (SCP03 always installs all three even if we don't use DEK — AN12436 §5.2.3).
  6. Verify SW=9000.
  7. Mark a "SCP03 rotated" flag — location TBD, not flash page 125 (colocated with admin PIN — we've already seen cross-test hygiene burn us). Candidates: OTP one-shot bit, a dedicated flash page, or probe-on-boot (try 0x11 first, fall back to 0x0B if rotation hasn't happened yet — simplest, skip the flag entirely).
  8. All subsequent boots establish against `KVN=0x11` with derived keys.
- [ ] **Brick class after rotation**: lose derivation root → cannot re-establish → same "lose the derivation, lose the chip" failure mode as OPTIGA PBS loss. Work-todo #7 Tier 1/2 closes this by moving the root off a readable OTP master onto DHUK/BHK.
- [ ] **Probe-on-boot fallback** (stage B sub-option): skip the rotation flag. Instead, `establish()` tries `KVN=0x11` + derived keys first; on `SW=0x6A88` (key not found) or MAC failure, retry with `KVN=0x0B` + hardcoded defaults. One extra failed auth per boot on un-rotated chips; zero on rotated ones. Avoids adding persistent state.

**Stage C — clone-resistance binding (optional, per #20 P0):**
- [ ] Mix SE050 UID into the derivation context: `secret_keys::se050_scp03_*_key_bound(uid: &[u8; 18]) -> [u8; 16]` that does `HKDF(OTP_master, "pqsigner/se050-scp03-{enc,mac}-v1" || uid)`. Defeats "clone a device's OTP master to a different SE050" — the derivation is only valid for the specific SE050 UID it was rotated against.
- [ ] SE050 UID read via `Se05x_API_ReadObject` on object `0xA000_F00E` (standard NXP-provisioned UID). No SCP03 needed to read.
- [ ] Documented but not mandatory for Stage B — adds 14 bytes of binding + one extra APDU per boot.

#### Cross-references

- #7 (three-tier DHUK + BHK + OTP) — rotates the derivation primitive under `secret_keys` without touching this item's ceremony.
- #20 (production key management) — the factory-ceremony superset that includes this rotation, OPTIGA PBS commit, binding manifest.
- #24 (OPTIGA pairing restructure, LANDED) — established the `hw::secret_keys` API that this item consumes.
- Production-todo §"SE050 — SCP03 + ADMIN provisioning" — mirror-image checklist for the irreversible side of stage B.

**Files to change (Stage A):** `secure/src/se050/scp03.rs` (helper + `KEY_VERSION` const + feature gate), `secure/Cargo.toml` (new `se050-derived-scp03` feature).

**Files to change (Stage B):** `secure/src/se050/scp03.rs` (rotation APDU), `secure/src/se050/apdu.rs` (`put_key` helper), `secure/Cargo.toml` (`se050-rotate-scp03` feature), `secure/src/main.rs` (one-shot dispatcher, pattern-identical to the existing `se050-admin-wipe-e2e` block), new `Makefile` target `make flash-hw-se050-rotate-scp03` with the same sacrificial-chip warning as `optiga-admin-wipe-e2e`.

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

**Status:** CORE LANDED (2026-04-20), hardware bring-up + trusted-UI
confirm + A/B linker split remaining.

**Design:** hash-signature model (item 15 below) realised via
SPHINCS+C10 over a minimal 75-byte preimage
(`"PQFW_V1" || fw_version_be || secure_hash || nonsecure_hash`). One
`.pqfw` per release works for either A/B slot. Full architecture in
`docs/firmware-update.md`.

**What landed:**
- [x] Reproducible builds (`.cargo/config.toml`, `make verify-repro`)
- [x] `fw-manifest` crate — no_std manifest parser/builder + CRC + verify chain
- [x] `fwsign` tool — `keygen`/`pubkey`/`sign`/`verify`/`verify-release`/`extract-sig`/`inspect`
- [x] Bank-2 (NS flash) write/erase in `secure/src/hw/flash.rs`
- [x] OTP rollback counter in `secure/src/hw/otp.rs`
- [x] Boot-state page in `secure/src/hw/boot_state.rs`
- [x] `fsbl/` immutable bootloader (18 KB / 32 KB budget)
- [x] `CMD_FW_BEGIN`/`CHUNK`/`COMMIT`/`STATUS`/`ABORT` over USB APDU v2
- [x] PIN-unlock gate on every FW command
- [x] `docs/firmware-update.md` + `docs/reproducible-builds.md`

**What's left:**
- [ ] Trusted-UI confirmation dialog (stubbed — blocked on the
      ongoing `secure/src/tx/display/` refactor; will reuse
      `ui::confirm::confirm()` once the render helpers stabilise)
- [ ] A/B slot linker scripts (`SLOT=A|B` variants of
      `secure/memory-stm32u585.x` + `nonsecure/memory-stm32u585.x`)
- [ ] `make flash-hw-production` factory sequence + WRP1A on
      `ob-configurator`
- [ ] Companion updater (`tools/fwupdate.py`)
- [ ] Hardware end-to-end test (v1 → v2 install → try-once revert →
      OTP rollback floor enforcement on a real B-U585I-IOT02A)

---

### 15. Hash-Signature Firmware Update Model

**Status:** LANDED (2026-04-20), subsumed into item 14.

The manufacturer's SPHINCS+C10 signature covers
`SHA-256("PQFW_V1" || fw_version || secure_hash || nonsecure_hash)`
— a 75-byte preimage an auditor reconstructs from source alone
(`fwsign verify-release`). No classical crypto in the sign/verify
path; entire chain is PQ.

**Shipped:**
- [x] SPHINCS+C10 verify in FSBL (re-uses `sphincs-c10` crate, software SHA-256)
- [x] Vendor public key embedded at FSBL build time via `FSBL_VENDOR_PUBKEY` env var
- [x] Signature stored inside the manifest page (4008 bytes at offset 180)
- [x] USB APDU v2 update handshake (INS 0x70..0x74)
- [x] Boot-time image-hash re-verification in FSBL before branch
- [x] `fwsign verify-release` for independent reproducible verification
- [x] Version binding prevents signed-hash replay with a higher version claim

**Remaining for this item specifically:**
- [ ] Key rotation mechanism (single root today; delegation keys are future work — tracked as a separate item when product scale needs it)
- [ ] CI/CD signing pipeline: build + `make verify-repro` + `fwsign sign` → GitHub Releases
- [ ] Companion app: the fwsign library could be compiled to WASM for in-browser verification

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

### 18. SLH-DSA side-channel + fault-injection hardening

**Status:** NOT STARTED (research complete — see `docs/production-security.md`)

> See also #23 for PIN counter hardening gap surfaced by Bundle F: OPTIGA OID 0xF1D5 is firmware-managed decrement-before-auth (glitch during decrement can revert the counter); TROPIC01 uses physically irreversible fused slots. Either migrate to OPTIGA monotonic counter objects or add a secure-flash-anchored shadow counter as an anti-rollback check.

Research-derived mitigations from the deep-research round of 2026-04-14. Critical finding: **both verify-after-sign is inadequate** (RFC 9814 / Genêt TCHES 2023) and **OptRand = 0 (deterministic signing) enables PRF recovery**. These are not theoretical.

**STM32U5 is confirmed-vulnerable to voltage glitching**, not merely presumed. The Masaryk U Simonik thesis (verified real in the 2026-04-15 round) demonstrates ~76% PIN-glitch bypass on STM32U5 silicon (same family as our STM32U585). Ledger Donjon's March 2025 statement that no public attack existed was correct at publication but invalidated within months. Plan the FihInt / fail-in / double-compute items in this backlog as **must-ship**, not optional.

**SHAKE-vs-SHA2 decision remains open** post-verification. The Fluhrer ePrint 2024/500 "1.7× overhead, backward-compatible PRF-tree" citation that argued for SHAKE migration is **not verifiable** per §3 of production-security.md — the claim is technically implausible on its face. The qualitative argument (SHAKE easier to mask than SHA-256) still holds, but don't commit to SHAKE on Fluhrer's alleged overhead number. Independent benchmark of SLH-DSA-SHAKE-128f performance + masking cost on Cortex-M33 needed before the decision is production-ready.

- [ ] **SHAKE-vs-SHA2 architectural decision** (was P1 in original list, now a prerequisite). Benchmark SLH-DSA-SHAKE-128f masked implementation vs SLH-DSA-SHA2-128f with HASH peripheral + software countermeasures. Don't rely on Fluhrer's 1.7× figure — measure directly.

**What's needed — P0 (must ship with these):**
- [ ] **SLH-DSA double-compute**: sign twice on disjoint SRAM regions, constant-time compare, release only on match. Verify-after-sign alone is NOT sufficient — faulty sigs still verify per RFC 9814.
- [ ] **Non-deterministic OptRand** on every signature: 16 B (128f) / 24 B (192f) freshly drawn from STM32 TRNG per sign call. Replace the current OptRand=0 deterministic path.
- [ ] **Signing rate limiter**: global token-bucket caps at ~1 sig/sec, ~500/day, hard-rotate after 2^16 signatures per key. Extends attacker trace-collection window from minutes to months.
- [ ] **WOTS chain + FORS tree shuffling** via Fisher-Yates, TRNG-seeded per sign. Desynchronises traces against profiled DPA.
- [ ] **FihInt-style complement-storage** for all security-critical booleans (`blob_cached`, `pin_verified`, `match_ok`). Magic constants 0x1AAA_AAAA / 0x1555_5555, stored with XOR complement. Verify via `core::ptr::read_volatile` on every check (never `core::hint::black_box`).
- [ ] **PIN-lockout fail-in pattern**: invert comparison to `if remaining != 0, continue` instead of `if remaining == 0, wipe`. A single-glitch branch-skip then misses wipe rather than triggering it.
- [ ] **Compiler fence + DSB barrier after every zeroize** of master_secret, entropy, PIN buffers.

**What's needed — P1 (strongly recommended):**
- [ ] Architectural decision: **SHAKE vs SHA2 parameter set**. SHAKE enables Fluhrer PRF-tree (~1.7× overhead) with cleaner SCA story than SHA2 (masking ~3-5×, HASH peripheral has no DPA resistance per UM3370). Backward-compatible with on-chain verifier per the research.
- [ ] Control-flow-integrity step counters: increment before critical call, decrement after, fail on mismatch. Detects function-skip glitches.
- [ ] Random delays before security-critical ops (DWT or TRNG-seeded NOP sled).
- [ ] Redundant volatile reads (2-3×) on critical state with OR-based fail-in.

**Files to create:** `secure/src/fih.rs` (FihInt type + read_volatile helpers)
**Files to change:** `secure/src/crypto.rs` (OptRand + double-compute), `secure/src/nsc/sign_and_emit.rs`, `secure/src/nsc/cmd_request_unlock.rs`, `secure/src/dual_se.rs` (seed XOR reconstruction hardening)

---

### 19. USB stack hardening (USB-C only attack surface)

**Status:** NOT STARTED (research complete — see `docs/production-security.md`)

Dev-research from Prompt D identified the USB path as our **largest remote attack surface** and surfaced concrete DWC2 errata workarounds and FI-resistant patterns.

**What's needed — P0:**
- [ ] **FI-resistant `min()`** in every USB control-transfer length-clamping site. Defeats Colin O'Flynn USENIX WOOT 2019 EMFI-on-min attack. Pattern: compute `min(a,b)` then verify `result <= a && result <= b`; if not, recompute via explicit conditional.
- [ ] **DWC2 TxFIFO write atomicity**: ensure no CSR access to other endpoints between successive FIFO writes of one endpoint, per STM32U5 DWC2 errata. Single-packet transfers (DIEPTSIZ.XFRSIZ = DIEPCTL.MPSIZ).
- [ ] **DWC2 ZLP race**: sequence SNAK/CNAK/EPENA per errata; flush all FIFOs on USB reset (GRSTCTL.RXFFLSH + GRSTCTL.TXFFLSH TXFNUM=0x10).
- [ ] **Bounded APDU reassembly**: enforce `4 ≤ declared_len ≤ 4096` at seq=0; 5-second reassembly timeout with buffer scrub; abort-and-scrub if seq=0 arrives during active reassembly.
- [ ] **HID OUT rate limiter**: token bucket ~200 reports/sec sustained, bucket size 64. NAK endpoint when empty.
- [ ] **APDU CLA/INS allowlist** at non-secure before any NSC call.

**What's needed — P1:**
- [ ] Force OTG_GUSBCFG.FDMOD = 1 (device-only mode), disable SOF interrupt (timing side-channel).
- [ ] FIFO sizing per RM0456 formula with ≥30% safety margin.
- [ ] IWDG hang detection for USB path (2s timeout, kicked per transaction).
- [ ] Response-buffer locking for 17,088-byte SLH-DSA signatures (ISO 7816 SW=0x61xx chunking; 30s timeout).

**Verified 2026-04-15**: `CVE-2026-4179` is real (published 2026-03-16; Zephyr advisory `GHSA-9xg7-g3q3-9prf`). We initially flagged it as hallucinated because it was future-dated relative to our training cutoff — that flag was wrong. Safe to cite.

**Additional action item from CVE-2026-4179 verification**:
- [ ] Audit whether our USB stack shares patterns with the Zephyr bug. The advisory describes `usb_write()` called from ISR context then triggering `k_yield()` → infinite loop. Our stack is Rust on top of the `synopsys-usb-otg` crate rather than Zephyr C. Still worth grepping our ISR handlers for: (a) scheduler calls from ISR context, (b) blocking waits inside IRQ, (c) any `yield!()`-equivalent patterns. Likely not affected since we're a different stack, but worth the 30 minutes.

**Files to create:** `secure/src/fih.rs` (shared with #18)
**Files to change:** `secure/src/hw/usb_hw.rs`, `nonsecure/src/usb/transport.rs`, `nonsecure/src/usb/hid.rs`, `nonsecure/src/usb/commands.rs`

---

### 20. Production key management (SCP03 rotation + HUK-SAES + binding record)

**Status:** NOT STARTED (research complete — see `docs/production-security.md`)

Prompt B surfaced a concrete production-provisioning protocol. Supersedes the brief HUK-SAES note in item #7.

**What's needed — P0:**
- [ ] **Two-stage RDP provisioning**. Stage 1 at RDP0: read all 3 UIDs (STM32, SE050, OPTIGA), derive per-device SCP03 keys via CMAC-KDF(FMK, label, SE050_UID), rotate SE050 SCP03 from NXP default KVN=0x0B → KVN=0x11 via PUT KEY. Stage 2 at RDP1+: wrap all secrets with real DHUK via SAES (DHUK is a known constant at RDP0 — wrapping there is meaningless).
- [ ] **Two-level SAES wrapping**: DHUK-ECB wraps 256-bit MasterKey → HKDF-SHA256(MasterKey, purpose) derives per-use keys → AES-GCM per-use wraps SCP03 / PBS / binding separately. Single-level DHUK-ECB has no integrity.
- [ ] **Per-device SCP03 keys via CMAC-KDF** with SE050 UID as context. Mass-clone defence.
- [ ] **OPTIGA PBS lifecycle lock**: OID 0xE140 to Operational state, Read=Never, Change=Conf(0xE140). Irreversible after provisioning.
- [ ] ~~**Binding record** signed by provisioner at factory: bind(STM32_UID, SE050_UID, OPTIGA_UID, fw_version, ts) signed ECDSA-P256~~ → **SUPERSEDED by #22** — use SLH-DSA-128s manifest with firmware_hash inclusion instead. Implement #22, retire this ECDSA design.
- [ ] ~~**Boot-time anti-swap verify**~~ → **SUPERSEDED by #22** — the full boot-time ceremony including both SE-attested reads + firmware-hash verification is in #22.

**What's needed — P1:**
- [ ] OPTIGA monotonic counter (OID 0xF1E0, Conf(0xE140) protected) for firmware anti-rollback.
- [ ] Blob format versioning for smooth firmware upgrades (magic 0x504B4559, version byte, HKDF label).
- [ ] SE050 attestation on every boot (ReadObject_W_Attst with key 0xF0000012) — optional, +100ms boot time.
- [ ] OPTIGA cert chain verification against pinned Infineon Root CA — optional.

**Verification items** (remaining after 2026-04-15 web verification round):
- [x] ~~Confirm NXP default SCP03 keys against current AN12436 revision~~ — **VERIFIED**. AN12436 Rev 2.4 (July 2024), all three hex values match byte-for-byte. Safe to use.
- [ ] Confirm SAES register bit-field positions against RM0456 + CMSIS `stm32u585xx.h` header (research author flagged as unknown — not verified in web-search round).
- [ ] Confirm STM32U585 DHUK actually returns a known constant at RDP0 (not merely "documented behaviour") — DHUK semantics may differ per errata.

**Files to create:** `provisioning/` (new host-side tooling crate), `secure/src/hw/saes.rs`, `secure/src/attestation.rs`, `secure/src/binding.rs`
**Files to change:** `secure/src/main.rs` (boot-time anti-swap gate), `secure/src/se050/scp03.rs` (per-device keys), `secure/src/optiga/shield.rs` (PBS lifecycle lock)

---

### 21. TAMP + CSS + PVD configuration (hardware supervisor Stage 2)

**Status:** NOT STARTED (already planned as Stage 2 of brownout roadmap — confirmed + expanded by research)

Confirmed by Prompt A that factory defaults are "dangerously insecure." Masaryk U 76% PIN-glitch bypass on STM32U5A9 (same core family) traced directly to defaults.

**What's needed — P0 (one-time at provisioning, burned in option bytes):**
- [ ] `BOR_LEV` = 3 or 4 in FLASH_OPTR. Narrows voltage-glitch window hardware-wide.
- [ ] `IWDG_SW` = 0 (hardware watchdog, cannot be disabled by firmware). 100-500 ms timeout.
- [ ] `IWDG_STOP` = 0 + `IWDG_STDBY` = 0 (continue in low-power modes).
- [ ] `SRAM2_ECC` = 1, `SRAM3_ECC` = 1 (ECC is OFF by default on U5 — earlier doc claim was wrong).
- [ ] `SRAM2_RST` = 0 (auto-erase SRAM2 on every system reset).

**What's needed — P0 (runtime config at boot):**
- [ ] PVD enabled at highest threshold below 3.3V via `PWR_SVMCR.PVDE` + `PVDLS[2:0]`. EXTI16 handler zeroizes secrets + last-gasp write to backup register.
- [ ] TAMP internal tampers: ITAMP1 (VBAT voltage), ITAMP2 (temperature), ITAMP3 (LSE CSS) all enabled with automatic backup-domain erasure on trigger.
- [ ] CSS (Clock Security System) on HSE: `RCC_CR.CSSON` = 1.
- [ ] ECCD double-bit NMI handler: read `RAMCFG_MxISR` + `RAMCFG_MxFEAR`, zeroize, soft-reset.

**Hardware:**
- [ ] **0.47-1 F supercap on VBAT** via Schottky from Vdd (1N5819 + 47Ω optional series R). See the decision rationale in `docs/brownout-hardening.md` "VBAT power source: supercap, not battery." Gives ~12-24 h bounded tamper retention — acceptable vs battery chemistry in enclosure.
- [ ] For dev board: tack-solder to unpopulated CR1220 holder pads on back of board.

**Files to create:** `secure/src/hw/power.rs` (PVD + PVM), `secure/src/hw/tamp.rs` (tamper config + backup regs)
**Files to change:** `Makefile` (`stm32-harden-opts` target — add SRAM2/SRAM3 ECC + IWDG option bytes), `secure/src/main.rs` (boot-time PVD + TAMP init)

---

### 22. Supply-chain + provisioning attestation (triple-UID binding, SLH-DSA manifest)

**Status:** NOT STARTED (bundle E research complete — see `docs/production-security.md` §2.5; raw result at `docs/research-bundles/results/compass_artifact_wf-b5bd18ff-...md`)

> See also #23 for a complementary anti-interdiction layer: "ship without firmware" (Trezor Safe 7 pattern) eliminates firmware-tampering during shipping without needing the attestation ceremony to execute on a potentially hostile binary. Defence in depth, not a replacement.

Bundle E extends item #20 with a **triple-UID cryptographically-signed manifest** + transparency log + user-facing WebUSB box-opening ceremony. This closes the single-chip-replacement attack surface that has affected every shipping hardware wallet (Trezor Safe 3, Ledger Snake demo, ColdCard firmware-reset). No shipping wallet implements what's described here today.

**Relationship to #20**: #20's ECDSA-P256 binding record is **superseded** by the SLH-DSA-128s manifest design in this item. Implement #22 and retire the ECDSA-P256 path from #20 rather than shipping both.

**What's needed — P0:**

- [ ] **STM32U585 anti-counterfeit probes at boot**: CPUID (expect Cortex-M33 r0p4, DEV_ID `0x482`), UID validation at `0x0BFA_0590` (lot ASCII check, wafer < 25, not all-0/all-0xFF), DHUK probe via SAES against factory-recorded value, errata fingerprinting (`DBGMCU_DBG_AUTH_DEVICE.AUTH_ID` reads zero at RDP0 quirk; MSI low-drift). Halt on any anomaly.
- [ ] **SLH-DSA-128s factory signing key**: M-of-N key ceremony with geographically distributed shares; air-gapped factory HSM; factory pubkey fingerprint published.
- [ ] **Binding manifest in CBOR** with schema: `manifest_type`, 3× UIDs, `firmware_hash` (SHA3-256 over the image — this ties chip identity to a specific firmware build, not in #20), `firmware_version`, `device_serial` = SHA3-256(3 UIDs), `production_ts`, `manifest_version`, `factory_pubkey_fp`. Signed SLH-DSA-128s.
- [ ] **Manifest stored 3×**: SE050 as binary secure object, OPTIGA Trust M data object, STM32 internal flash. Plus SHA3-256 anchor to STM32 OTP bytes 6-37 (already in #20).
- [ ] **SE050 attestation at boot**: `Se05x_API_ReadObject_W_Attst` with 16-byte freshness nonce + key `0xF0000012` → ECDSA-SHA256 signed response containing 18-byte chipId. Verify chain to pinned NXP root CA. ⚠ **Variant gate**: confirm we're on SE050 **C, E, or F** variant — A/B/D do NOT have pre-provisioned attestation certs at OID `0xF0000013`.
- [ ] **OPTIGA attestation at boot**: `optiga_crypt_ecdsa_sign` with key `0xE0F0`, cert from OID `0xE0E0`, UID from `0xE0C2`. Chain signature to pinned Infineon OPTIGA ECC Root CA 2.
- [ ] **Boot-time ceremony** (runs in secure world before entropy reconstruction): read STM32 UID → load manifest → verify SLH-DSA signature → compare all 3 UIDs to manifest + against each SE's own attested response → compare SHA3-256(firmware) against manifest.firmware_hash → check anti-rollback counter → ATTESTATION_PASSED. Any mismatch → permanent lockdown (no entropy release).
- [ ] **Transparency log**: append-only public record of every `device_serial` + manifest hash emitted at the factory. Merkle-anchored (scheme TBD — see research prompt). Enables detection of rogue production runs even under HSM compromise.
- [ ] **RDP Level 2** burned at end of provisioning (also in #20 — coordinate).

**Reference point**: Trezor Safe 7 (verified real, announced Oct 21 2025, shipping late 2025 / early 2026) is the closest existing production-wallet architecture. Uses TROPIC01 as transparent SE + EAL6+ second SE for dual attestation. PQSigner adds the triple-UID SLH-DSA manifest on top. Worth studying Trezor's public documentation on Safe 7's attestation protocol before we finalise our own — we may learn from their transparent-SE approach, and we should be explicit where our design intentionally diverges.
- [ ] Study Trezor Safe 7 attestation protocol (public docs + any security evaluations) and document how our triple-UID SLH-DSA design differs. May surface improvements or shared patterns.

**What's needed — P1:**

- [ ] **WebUSB verification page** at `verify.pqsigner.io`: browser sends fresh random challenge via WebUSB → both SEs sign → server-side independent verification of NXP + Infineon cert chains + manifest signature + UID consistency → displays ✓ + device serial. No customer tool install required. Three independent trust anchors converge (NXP root, Infineon root, factory SLH-DSA pubkey).
- [ ] **M-of-N factory HSM ceremony procedures**: documented operational runbook; number of shares; threshold; geographic distribution; rotation schedule.
- [ ] **Transparency-log audit tooling**: periodic audit that every shipped device's serial appears in the log; alerting on anomalies.
- [ ] **Automatic USB CDC self-attestation** on every first-connect: device emits a structured attestation report over serial (status, serial, per-chip verification, firmware version, manifest signature validity). Complements WebUSB for users who prefer command-line verification.

**What's needed — P2:**

- [ ] Recovery / warranty procedure for devices that brick due to genuine hardware failure vs. attestation failure. UX for distinguishing "we got a bad SE" from "someone tried to swap chips."
- [ ] Carrier / distributor notifications when transparency-log audit detects anomalies.

**Verification items after 2026-04-15 web verification round**:
- [x] ~~Ledger Donjon March 2025 Trezor Safe 3 attack~~ — **VERIFIED REAL**. Blog post at `ledger.com/why-secure-elements-make-a-crucial-difference-to-hardware-wallet-security` (March 12, 2025). Trezor confirmation at `trezor.io/vulnerability/donjon-s-trezor-safe-3-evaluation`.
- [x] ~~Trezor Safe 7 with TROPIC01~~ — **VERIFIED REAL**. Announced October 21, 2025; shipping late 2025 / early 2026. Dual attestation (TROPIC01 + EAL6+ SE).
- [x] ~~Masaryk U Simonik thesis 76% PIN-glitch~~ — **VERIFIED REAL**. Bachelor's thesis on fault injection vs STM32U5 (Trezor Safe 5). Reference: `it4sec.substack.com/p/fault-injection-attack-on-the-stm32u5`.
- [x] ~~BlaatSchaap research on STM32F103 clones~~ — **VERIFIED REAL**. `blaatschaap.be/identifying-32f103-clones/` and multi-part Cortex-M series. Safe to cite.
- [x] ~~TheCharlatan May 2020 ColdCard firmware-reset~~ — **VERIFIED REAL**. `thecharlatan.ch/COLDCARD-Supply-Chain/`.
- [ ] ES0499 specific sub-section numbers (§2.26.2, §2.26.3, etc.) — ES0499 Rev 11 exists and covers USB OTG errata but exact sub-section numbering not confirmed in web search. Pin citations to Rev 11 PDF before writing code against specific section numbers.
- Bundle E claim "STM32U5 clones do not exist as of early 2025" — appropriately hedged in the original; Simonik thesis + Donjon March 2025 attack now invalidate the "glitch-immune" subtext. U5 is presumed-vulnerable.

**Attribution correction (2026-04-15)**: One item in Bundle E / D had wrong attribution. "Riscure LFI on ColdCard" (Mk2 ATECC508A single-shot; Mk3 ATECC608A multi-shot) was actually done by **Ledger Donjon (Olivier Hériveaux)**, not Riscure. See `blog.coinkite.com/laser-fault-injection/` + SSTIC 2020/2021 papers. Fix wherever we cite this.

**Files to create:** `provisioning/` host-side tooling (extend #20), `secure/src/attestation.rs` (extend #20), `secure/src/hw/chip_id_probe.rs` (anti-counterfeit), `verify-webusb/` (browser verification page + server component)
**Files to change:** `secure/src/main.rs` (full boot-time ceremony), `secure/src/se050/apdu.rs` (add ReadObject_W_Attst wrapper), `secure/src/optiga/apdu.rs` (add attested-sign + cert-chain verify)

---

### 23. Trezor Safe 7 gap closure (feature parity + ship-ready infrastructure)

**Status:** NOT STARTED (bundle F research complete — see `docs/research-bundles/results/compass_artifact_wf-bb70bc61-...md`)

Comparative review against **Trezor Safe 7** (announced 2025-10-21, shipping Nov 2025) surfaced a set of gaps that are *not* covered by the existing PQ / attestation / SCA tracks in this document. These are standalone features + infrastructure deliverables shipping today in Trezor's product. The research is honest: Trezor wins 6 of 10 comparison dimensions; this section is the concrete list of items needed to close that gap where structurally possible.

**What's needed — P0 (prerequisites for any v1 security claim):**

- [ ] **Reproducible builds.** Nix + Docker pipeline producing byte-identical firmware except for the signature block. Precondition for the measured-boot 8-word display (item #5) being a meaningful verification mechanism — without repro builds, a user comparing the 8 words against `fwmeasure` output can't distinguish "I built the right source" from "I built something that hashes the same." Trezor ships this today; gold standard to copy.
- [ ] **Hybrid boot signature.** Current plan signs measurement with ML-DSA-44 only. Bundle F recommends hybrid Ed25519 + ML-DSA-44 (or EdDSA + SLH-DSA-128, per Trezor's boardloader) so firmware remains verifiable even if one scheme breaks. *Cross-ref: extend #5 / #18.*
- [ ] **Published security-disclosure page.** Establish the Trezor-style "past security issues" page from day one: every CVE, researcher, severity, resolution. Reputation is built by publishing incidents, not hiding them.

**What's needed — P1 (feature parity):**

- [ ] **SLIP-39 Shamir backup.** SatoshiLabs-invented, MIT-licensed (github.com/satoshilabs/slips/blob/master/slip-0039.md). Single-24-word backup is a resilience SPOF. Support ≥2-of-3 and ≥3-of-5 share configurations for geographic distribution.
- [ ] **BIP-39 passphrase ("hidden wallet").** Up to 50 ASCII chars, $5-wrench defence + plausible deniability. Maps straight into existing KDF as an extra input alongside the 24 words.
- [ ] **On-device backup verification flow.** Equivalent of Trezor "Check backup": user re-enters the 24 words on OLED, device confirms they match the stored seed, no host involved. SSD1306 128×64 is constrained but doable.

**What's needed — P3 (low priority / unlikely to ship):**

- [ ] **Ship-without-firmware anti-interdiction.** Factory flashes only boardloader + bootloader; firmware installed by user on first boot via companion app over USB with bootloader signature check. Defeats firmware-swap interdiction. *Decision 2026-04-15: deprioritised — significant build-pipeline + provisioning-flow rework, and #22 triple-UID attestation + hybrid-signed firmware already cover the bulk of the threat. Reconsider only if we hit a concrete interdiction threat model we can't close otherwise.* Cross-ref: complementary to #22.

**What's needed — P2 (doc clarifications surfaced by Bundle F critique):**

- [ ] **Document the Groth16 split architecture explicitly.** Bundle F correctly notes on-device proof *generation* is infeasible on Cortex-M33 for non-trivial circuits. Our design is host-side proof generation + on-device verify — but the current docs make this easy to misread. Add a subsection to `docs/architecture.md` ZK section clarifying: prover = companion app, verifier = secure world + trusted display. Document the constraint-count ceiling we tested at.
- [ ] **Clarify "no seed on MCU flash" differentiation.** Trezor Safe 7 stores seed **encrypted** on MCU flash (SE-contributed KDF). Our XOR-split means MCU flash extraction reveals **zero entropy bits** — a genuine differentiator worth naming explicitly in `README.md` and `docs/architecture.md` threat-model sections. Currently implicit.

**Cross-references to existing items:**

- **#5** (Measured boot) — extend to hybrid PQ+classical signature per Bundle F.
- **#7** (HUK-SAES) — unchanged; note that our wrapping scope is narrower by design (we don't need to derive a seed-decryption key because no seed lives on MCU flash).
- **#18** (SLH-DSA SCA + FI) — PIN counter hardening note added to its header.
- **#22** (Supply-chain attestation) — ship-without-firmware is a complementary layer.

**What this section does NOT try to close (structural, not feature-gap):**

- Physical enclosure / active-mesh / IP67 case. That's a product manufacturing step, not firmware work. Tracked out-of-band.
- Bluetooth / Qi2 / battery. Explicit PQSigner design choice: USB-C only.
- Color touchscreen. OLED was picked deliberately for simplicity of the trusted display.
- Universal blockchain support. We're PQ-only AA by design; chasing ECDSA parity is a category error.

**Relationship to Trezor's publicly-unknown details:**

Bundle F flags several Safe 7 specifics as not publicly disclosed yet (exact SE secret-sharing scheme, SLH-DSA-192f migration, anti-rollback counter granularity). Don't over-engineer against assumed Trezor designs. Re-audit Bundle F once SatoshiLabs publishes the Safe 7 firmware (their OSS track record suggests within ~6 months of shipping).

**Files to create:** `scripts/repro-build.sh` + Nix/Docker config, `secure/src/ui/slip39_wizard.rs`, `secure/src/ui/passphrase.rs`, `secure/src/ui/backup_verify.rs`
**Files to change:** `README.md` (explicit threat-model diff vs Trezor), `docs/architecture.md` (ZK split-architecture subsection, "no seed on MCU flash" framing), `secure/src/measured_boot.rs` (hybrid sig slot)

---

### 24. OPTIGA pairing restructure: OTP-derived PBS + HUK re-root

**Status:** IN PROGRESS (2026-04-17). Full rationale and mechanism in `docs/optiga-brick-postmortem.md`.

We bricked the Shielded Connection on our TRUSTMV3SHIELDTOBO1 bring-up chip during rx_seq debugging. Root cause analysis shows the current pairing code **would brick any customer device on any firmware update** — this is a ship blocker, not a bench anomaly. Three compounding issues:

- PBS is generated as random per-provisioning (non-deterministic).
- PBS is sealed to MCU flash page 126 with an AES-256-GCM key that mixes `firmware_hash()` — so any firmware rebuild produces a different key and the seal becomes undecryptable.
- `setup_pbs_no_handshake` bumps `E140 LcsO=Operational` (irreversible) immediately after the write, committing to a pairing that only survives while that one firmware binary is running.

Fix is structural, modelled on Trezor's production design (`~/repos/trezor-firmware/core/embed/sec/optiga/` + `sec/secret_keys/stm32u5/`). See the postmortem doc for the full trace, the `firmware_hash()` attestation-vs-HUK separation of concerns, and the decision record on which Trezor patterns we port vs. skip.

**What's needed — P0 (this week, unblocks continued dev):**

- [x] **`optiga-no-shield` dev feature**: skip `setup_pbs_no_handshake` entirely + make `ensure_shield` a no-op. Lets the current bricked chip exercise all non-PRL paths (provisioning F1Dx OIDs, PIN HMAC via `DecryptSym`, entropy reads, factory-reset) while new shields are in transit.
- [x] **Gate `setup_pbs_no_handshake`'s LcsO=op bump** behind a `optiga-lock-operational` Cargo feature. Default OFF — future dev chips stay at LcsO=Creation (rewriteable) and cannot be bricked by rebuild. Production builds opt in once OTP is burned.
- [x] **Remove the `optiga-bringup-fresh` feature.** Its flash-page-126 erase was what finished off our test chip; once PBS is OTP-derived (below) the feature is meaningless. (Landed 2026-04-20: feature dropped from `secure/Cargo.toml`, `optiga/mod.rs::auth_ref_is_authref_typed` deleted, `lock_oid` + `provision_user_oid` + `store_objects` simplified, Makefile `flash-hw-optiga-reset` recipe updated.)

**What's needed — P0 (step 2, the actual fix):**

- [x] **`secure/src/hw/otp.rs` extension**: `read_device_master`, `burn_device_master` (one-shot), `is_device_master_burned`, `ensure_device_master`. Reserves OTP bytes 128..160 (two quad-words past the rollback tally). Feature-gated test stub under `otp-hardcoded-master-key` (ASCII pattern `"PQSIGNER-TEST-OTP-MASTER-DNS-v1!"`) so the derivation can be exercised on dev bench without consuming real OTP.
- [x] **`secure/src/hw/secret_keys.rs`** (Trezor parallel): domain-labelled HMAC-SHA256 expansions of the OTP master. `optiga_pairing_secret`, `se050_scp03_enc_key`, `se050_scp03_mac_key`, `tropic01_pairing_key`. Sets up the API surface for work-todo #7 HUK-SAES to re-implement against SAES-wrapped key material later.
- [x] **Trezor-style first-boot self-provisioning** in place of the originally-planned `make stm32-burn-device-key` factory target: on the first call of `ensure_device_master` against a blank OTP, fill 32 TRNG bytes and program the region. No factory workflow step — the device provisions itself on first power-up.
- [x] Rewrite `setup_pbs_no_handshake` to derive PBS from `secret_keys::optiga_pairing_secret()` instead of `rng::fill`. Flash-seal removed (`hw::flash::write_pbs` call deleted). Added a belt-and-braces guard that refuses the LcsO=op bump if `is_device_master_burned()` is false, so an accidental feature-flip on an unburned board cannot reproduce the brick.
- [x] Delete `hw/flash.rs::read_pbs / write_pbs / erase_pbs_page / PBS_PAGE_ADDR / PbsLoadError / PBS_WRAP_DOMAIN / PBS_BLOB_LEN / is_pbs_blank`. (aes-gcm dep still needed — other callers.)
- [x] Simplify `optiga/mod.rs::load_pbs`: drop the flash-seal + blank-page check path, call `self.shield.load_pbs(&secret_keys::optiga_pairing_secret()?)` directly.

**What's needed — P0 (step 3, decouples firmware_hash from HUK):**

- [x] **Re-root `secure/src/hw/huk.rs::derive_device_key`** off `firmware_hash()` and onto `hw::otp::ensure_device_master()`. **`measured_boot::firmware_hash()` unchanged** — 8-BIP-39-word OLED attestation + #22 manifest binding still depend on it. `derive_device_key` now returns `Result<[u8; 32], OtpError>` to propagate first-boot OTP failures; currently no in-tree caller (flash-seal deleted), retained as the documented primitive for any future at-rest sealing need.

**What's needed — P1 (Trezor ports beyond PBS, finish the OPTIGA layer):**

- [ ] **Hardware monotonic counter for PIN attempts**: migrate `OID_COUNTER` from `0xF1E1` (software, glitch-fragile, `Conf(E140)`-gated) → `0xE120` (OPTIGA built-in monotonic counter with `Auto(LUC)` access conditions). Drop the firmware-side decrement-before-verify gymnastics in `authenticate_and_read`. Closes the concern noted in `project_optiga_bringup.md` memory.
- [ ] **Typed `OptigaMetadata` struct** replacing the tag-by-tag `push_ac_simple`/`push_lcso_op` builders in `apdu.rs`. Pure refactor; makes merge-vs-overwrite semantics explicit. Mirror of Trezor's `optiga_metadata`.

**What's needed — P2 (reversible validation, dev-safe):**

- [x] End-to-end Phase-A test on a fresh TRUSTMV3SHIELDTOBO1 shield (2026-04-20): flashed with `otp-hardcoded-master-key` + `e2e-skip-unlock`, LA1010 on PB8/PB9/PE4. Verified: (a) 64-byte PBS derivation matches expected fingerprint `8ca52e4bc284d822` across multiple reflashes with different `firmware_hash` values, (b) E140 accepts 64-byte PBS + metadata at LcsO=Creation (Sta=0x00), (c) hard-RST pulse on PE4 reaches silicon (LA-confirmed 22 ms falling-edge on CH2 / Arduino D5), (d) all six user OIDs (F1D0 AUTH_REF, F1D1 ENTROPY, F1D2 MASTER_SECRET, F1D3 VK, F1D4 BOOTSTRAP_VK, F1E1 COUNTER) provisioned cleanly (user-OID `lock_oid` calls committed on that run — since corrected to be gated by `optiga-lock-operational`, see below), (e) chip still at LcsO=Creation on E140. The `firmware_hash`-in-wrap-key brick is genuinely gone.
- [x] `lock_oid` gated behind `optiga-lock-operational` (2026-04-20 follow-up): default dev builds (`optiga-lock-operational` OFF) no longer commit user-OID LcsO=op. Every OID stays at LcsO=Creation through all normal Phase-A iteration. Logs `[OPTIGA/prov] OID 0xNNNN lock_oid SKIPPED (optiga-lock-operational OFF ...)` on each gated call. This is the main "never waste another chip in dev" guardrail.
- [x] PRL handshake validated in LcsO=Creation (2026-04-20 follow-up 2): `OptigaTrustM::ensure_shield` used to bump E140 LcsO=op before `shield.establish`, on the mistaken belief that PRL required it. The Infineon reference (`example_pair_host_and_optiga_using_pre_shared_secret.c:30-35` `#define FINAL_LCSO_STATE (LCSO_STATE_CREATION)`) + SRM §"Pairing Use Case Pre-conditions" (`LcsO < operational`) + `ifx_i2c_presentation_layer.c:820-829` (no LcsO check in PRL dispatch) all say the opposite — PRL engages fine at Creation. Removed the bump. Confirmed on hardware: chip now emits a full 38-byte SlaveHello against the current (Creation-state) chip, demonstrating PRL engagement is reversible. Session-key exchange still fails at MasterFinished — that's a separate issue tracked below.
- [x] Investigate MasterFinished handshake rejection (2026-04-21, commit 43b6937). Root cause was our PRL-layer implementation diverging from Infineon's `ifx_i2c_presentation_layer.c:285-621` in three places: (1) PRF seed was `random_M ‖ random_S` but reference uses only `random_S` (no master-side random exists in Infineon's PRL), (2) MasterFinished plaintext was `random_M ‖ slave_seq` but must be `random_S ‖ slave_seq`, (3) MasterFinished nonce/AAD/header seq were all zero but must be the `slave_sequence_number` received in SlaveHello. SlaveFinished verification similarly needed `master_sequence_number` extracted from the response header. `establish: DONE` on real B-U585I-IOT02A + OPTIGA Trust M V3.
- [x] Shielded record I/O end-to-end (2026-04-21, commit a1ac0cd). Three additional bugs uncovered once handshake closed: (a) `send_command` sent wrapped records via `ifx.transceive` (no PRESENCE_BIT) — frames hit the APDU parser instead of the PRL layer, chip responded with SCTR=0x40 fatal alert. Now uses `transceive_prl`. (b) `hard_reset_and_reinit` didn't clear `shield.active`, so after every RST pulse we tried to send records encrypted with keys the chip had discarded. Now clears the flag so `ensure_shield` re-handshakes. (c) `store_objects` never called `ensure_shield` at all despite its docstring claiming idempotent re-provisioning via Conf(E140); now threads it after step-1 PBS write and after every `hard_reset_and_reinit`. Validated: six shielded `set_data_object` calls (F1D0..F1D4 + F1E1) through the Shielded Connection on real silicon.
- [x] PIN unlock via AUTHREF HMAC on real silicon (2026-04-21, commit 3d34101). Two more bugs: (a) `PARAM_HMAC_MODE` in the DecryptSym APDU was 0x02 but `optiga_hmac_type_t::OPTIGA_HMAC_SHA_256 = 0x20` per `common/optiga_lib_common.h:213` — this is the `cmd_param` byte selecting HMAC variant. Sending 0x02 made the chip interpret the frame as a different sym mode and reject with Status=0xFF. (b) Missing `GenerateAuthCode` APDU — `optiga_crypt_hmac_verify` is specified to consume a session acquired by `generate_auth_code` (`optiga_crypt.h:2390`); a bare `GetRandom` leaves the session slot empty and the verify rejects. Added the APDU (GetRandom with `store_in_session=TRUE`) and rewired `authenticate_and_read` to use it with 16 B host_nonce + 32 B chip random + 16 B host_tag mirroring the reference example. Log reaches `hmac_verify OK` → `[OPTIGA] Unlocked: entropy + VKs cached` → `gateway pre-unlocked, ready for tests`.
- [x] Skip `set_metadata` when OID LcsO is already Operational (2026-04-21, commit 635e018). Partially-provisioned chips from pre-0b412b4 runs have F1D0..F1DF at LcsO=Op; re-running provisioning would hit the one-way ratchet with Status=0xFF. Guards `provision_auth_ref` / `provision_user_oid` / `provision_counter` to read the current metadata, check tag 0xC0 via `apdu::is_metadata_operational`, and skip both `set_metadata` and `lock_oid` when the stored functional AC tags already match `build_metadata_*` output.
- [ ] Rerun Phase-A on a third fresh chip with the gate in place and confirm the chip stays fully at LcsO=Creation post-provision (all 7 OIDs readable + rewriteable afterwards). Completes the reversibility proof.

**What's out of scope here — moved to `docs/production-todo.md`:**

- Phase-B (E140 LcsO=op commit + full PRL handshake) — one-way.
- First-boot STM32 OTP master-key burn validation — one-way.
- User-OID LcsO=op commits — one-way (our Phase A flipped these accidentally on the 2026-04-20 chip; follow-up landed the `optiga-lock-operational` gate so the default flow no longer does).
- RDP=2, WRP1A, SECBOOTADD0, vendor-key bake-in, SE050 SCP03 rotation, supply-chain manifest signing — all silicon- or fleet-committing actions.

Everything in `docs/production-todo.md` must be validated on sacrificial parts and only executed during explicit factory / end-to-end production provisioning runs with `optiga-lock-operational` (and the other relevant gates) enabled. Dev day-to-day iteration never flips those.

**What we're NOT porting from Trezor** (decision record; full rationale in §6.4 of the postmortem):

- Multi-OID PIN stretching chain (`OID_PIN_CMAC` E200 + `OID_PIN_HMAC` F1D8 + `OID_PIN_ECDH` E0F3). Trezor uses it to defeat offline brute force after flash extraction; our design never stores PIN material in MCU flash so the threat is closed elsewhere.
- ECDSA signing-key masking with an OTP-derived mask. We don't sign with OPTIGA ECC keys. The general pattern may be worth revisiting for work-todo #18 (SLH-DSA SCA/FI), not for the OPTIGA layer.
- `optiga_suspend`/`optiga_resume` with RTC wakeup. Irrelevant for a USB-bus-powered device.

**Cross-references:**

- `docs/optiga-brick-postmortem.md` — full rationale (primary reference for this item)
- #7 HUK-SAES — the OTP + `secret_keys` infrastructure introduced here is what #7 needs; they merge
- #22 Supply-chain attestation — `firmware_hash()` stays intact and is still this manifest's firmware-identity input
- `project_optiga_bringup.md` memory — has the earlier bring-up quirks + a note about PIN counter hardening that this item closes

**Files to create:** `secure/src/hw/otp.rs`, `secure/src/hw/secret_keys.rs`, `scripts/burn_device_key.py` (helper for `stm32-burn-device-key`)
**Files to change:** `secure/Cargo.toml` (new features), `secure/src/optiga/mod.rs` (setup_pbs rewrite, load_pbs simplification, LcsO gate), `secure/src/optiga/apdu.rs` (OptigaMetadata refactor, OID_COUNTER change), `secure/src/hw/huk.rs` (OTP-backed), `secure/src/hw/flash.rs` (delete PBS seal), `secure/src/main.rs` (load_pbs call simplification), `Makefile` (new target)

---

### 25. PIN counter sync polish (three-way lockstep hardening)

**Status:** Gaps 1 + 3 landed 2026-04-22. Three items below remain.

Context: the dual-SE PIN lockout runs three counters in lockstep (MCU page-124 pre-commit + OPTIGA E120 LUC + SE050 UserID chip-side attempt counter). `pin-gate-hw-counter-e2e` (5 phases) and `pin-gate-wipe-e2e` (destructive 10-iteration burn + factory_reset_admin + re-provision) validate the steady-state and wipe-dispatch paths on real silicon. See `memory/project_optiga_hw_counter_validated.md` for the wire-format facts and cross-boot/LcsO=Op caveats; see commits `7574218` (three-way sync), `0ecfe69` (boot-time SE050 cache re-sync), `d0dda77` (wipe-dispatch e2e) for the code.

Three gaps deliberately not closed by the four validation runs on our last bench chip:

- [ ] **Gap 2 — E120 exhaustion lockout on silicon.** The `curr >= HW_PIN_CTR_LIMIT` check in `authenticate_and_read` (`secure/src/optiga/mod.rs:1357-1358`, carries a SAFETY/COVERAGE comment) is validated by inspection only. Running it consumes 32 consecutive wrong-PIN counter slots on the chip with unknown cumulative wear from repeated reset-on-success cycles. Per advisor consult 2026-04-22: the risk of an unknown-unknown on the last bench chip outweighs the marginal coverage versus inspection + LUC increment proven by `optiga-hw-counter-e2e`. Revisit when (a) a fresh spare TRUSTMV3SHIELDTOBO1 arrives and (b) we have either a second bench chip to cross-validate wear behaviour or access to Infineon's datasheet wear budget for the E120 counter OID.

- [ ] **Gap 4 — SE050 silicon-locked SW → `UnlockError::PinLocked` mapping.** The `pin-gate-wipe-e2e` run on 2026-04-22 surfaced that SE05x signals the *terminal* wrong-PIN attempt (the one that decrements the UserID counter from 1 → 0) as the same wrong-PIN SW it returns for earlier attempts. Our driver maps that to `UnlockError::PinIncorrect`, which is correct for the tenth attempt. But any *subsequent* attempt against a silicon-locked UserID — which shouldn't happen in production (MCU wipe fires at attempt 10 before an 11th attempt reaches SE050) but can happen in contrived conditions — returns a different SW that our driver currently maps to `UnlockError::InternalError` via the catch-all arm at `se050/mod.rs:1310`. An `InternalError` at the NSC gateway does NOT trigger `trigger_lockout_wipe` (only `PinIncorrect` + `MCU == MAX` does), so a chip whose SE050 UserID is silicon-locked but whose MCU counter has somehow been reset (flash corruption, manual intervention) could sit in a `PIN try → InternalError` stall loop without wiping. Fix: grep the SE050 datasheet / NXP AppNote AN12413 for the explicit "authentication object locked" SW (candidate: `0x6983`), add an explicit arm in `se050/mod.rs::unlock`'s `map_err` that translates it to `UnlockError::PinLocked`, and wire a deliberate regression test (not destructive — uses `iterative_wipe` to pre-lock a throwaway UserID).

- [ ] **Gap 5 — behaviour under `optiga-lock-operational=ON` (production ratchet).** Every validated test run to date has kept every OID at `LcsO=Creation` per the user's non-negotiable directive while we're still iterating. The production build bumps OIDs to `LcsO=Operational` — an irreversible one-way ratchet per the OPTIGA SRM. All metadata writes become no-ops after the bump (chip rejects). This is fine for the happy path (no metadata rewrites needed post-provision), but needs a deliberate dry-run on a throwaway chip that's been bumped to `LcsO=Op` to confirm: (a) `reset_hw_pin_counter` still works (the Change AC is `Auto(F1D0)` which is preserved across LcsO), (b) `factory_reset` still works (the user-OID Change ACs include `Conf(E140)` which is preserved), (c) the `is_metadata_operational` check in `provision_hw_pin_counter` short-circuits correctly, (d) three-way sync still passes phase-1..4 with E120 operating on a locked-metadata chip. Consumes a second bench chip (the LcsO bump is one-way).

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
| 2026-04-14 | Brownout hardening Stage 1 | Reset-cause classification (RCC_CSR), verified flash quadword writes (post-write read-back), `make stm32-harden-opts` option-byte target (BOR3 + SRAM2_RST=0). Reset cause logged + dirty-reset triggers `zeroize_sensitive_state`. Bit layout for `RCC_CSR` empirically verified on hardware (0x14004400 = SFTRSTF + PINRSTF). Validated regression-free against `se050-admin-wipe-e2e`. Full design + Stages 2-5 in `docs/brownout-hardening.md`. |
| 2026-04-14 | Crash-safety e2e test | New `make se050-crash-safety-e2e` 2-phase target: provision test objects + arm wipe flag + partial wipe + halt; user resets; phase 2 boots, detects flag, finishes wipe, erases flash page 125. Validated PASS on warm reset (`probe-rs reset`) AND true cold cycle (USB unplug — confirmed by SE050 PCB-byte change ef→82 indicating SE chip power-cycled). |
| 2026-04-14 | AI deep-research round | 4 of 5 parallel research bundles run (A fault-injection, B key-mgmt, C SLH-DSA SCA, D USB hardening; E supply-chain pending). Findings synthesised into `docs/production-security.md` + new tasks #18-22 in this file. Hallucinations flagged: `CVE-2026-4179` fabricated; "SLasH-DSA 2025" Rowhammer paper future-dated/unverified; ES0499 §2.26.x section numbers + AN12436 Rev 2.4 SCP03 default keys cited but unverified — verify before code commit. |
| 2026-04-15 | Bundle E supply-chain research | 5th deep-research bundle completed. Synthesised into production-security.md §2.5 + work-todo.md #22. Key finding: triple-UID SLH-DSA-128s factory manifest supersedes Bundle B's ECDSA-P256 binding record (adds firmware_hash + PQ-resistant signing + transparency-log + WebUSB verify ceremony). SE050 variant gate identified — attestation requires SE050 C/E/F, not A/B/D. |
| 2026-04-15 | Bundle F Trezor Safe 7 comparison | 6th deep-research bundle. Trezor wins 6 of 10 comparison dimensions (attestation, FW update model, UX, physical security, open-source maturity, recovery options); PQSigner wins AA/smart-contract posture and PQ signing; ties on SE strategy. New work-todo #23 with P0 (repro builds, hybrid boot sig, security-disclosures page), P1 (SLIP-39, passphrase, on-device backup check), P2 (Groth16 split-architecture docs, "no seed on MCU flash" framing), P3 (ship-without-firmware, deprioritised). Cross-refs into #7/#18/#22. |
| 2026-04-15 | Hallucination verification round | Web-verified every citation previously flagged as fabricated across all 5 bundles. **Most flags were wrong** — CVE-2026-4179, Ledger Donjon March 2025 Trezor Safe 3 attack, Trezor Safe 7, Masaryk Simonik thesis, BlaatSchaap + TheCharlatan research, RFC 9814, NXP AN12436 Rev 2.4, ES0499 all verified REAL. Our training cutoff dismissed post-cutoff publications as hallucinations. Corrected verification log in production-security.md §3. Genuinely fabricated / unverifiable items narrowed down to: Fluhrer ePrint 2024/500 (likely doesn't exist as described), "Extraktor" glitch board (not found — probably SiliconToaster misremembered), NCC "CM-1-C" specific label (series real, label not locatable), some precise trace-count figures. One attribution error fixed: ColdCard LFI attack was Ledger Donjon, not Riscure. |
| 2026-04-16 | JARDÍN cutover (phases 1-7) | Collapsed the multi-signer architecture to a single JARDÍN FORS+C signing path behind one `CMD_SIGN_USEROP`. Flash-backed `SlotState` persists `next_q` across power cycles (phase 1). Added SPHINCS+C11 master key derivation matching the SPHINCs- reference byte-for-byte (phase 2, 7 unit tests + BIP-39 vector). Unified Type 1 / Type 2 state machine emits a `[type1_len \| t1 \| type2_len \| t2]` bundle the companion submits as up to two EntryPoint v0.9 UserOps (phase 3). USB layer cut from 14 INS codes + v1 Keycard Shell compat to 7 native v2 instructions; webhid tool rewritten for the unified bundle (phase 4). `PQJardinWallet` + `PQJardinWalletFactory` contracts replace the multi-signer wallet; 14 new Foundry tests pass; EntryPoint v0.9 via `account-abstraction` submodule update to `releases/v0.9`; CREATE2 salt = `keccak256(masterPkSeed \|\| masterPkRoot)` (phase 5). ERC-20 metadata bundle + Groth16 ZK clear-sign preserved as optional trailer sections on the unified sign payload, verifying against the firmware-embedded Merkle-rooted DBs just like before. Fixed a latent sphincs-c7 bug where `extract_ht_index` used C7 parameters (24-bit mask at bit 128) instead of C11 (16-bit mask at bit 143); self-verification now passes keygen → sign → verify roundtrip. |
| 2026-04-16 | OPTIGA Trust M silicon bring-up | TRUST-M-SHIELD on B-U585I-IOT02A via breadboard wired to I2C1. Rewrote `secure/src/optiga/apdu.rs` for correct wire format (positional InData not TLV, CMD bytes with 0x80 CLEAR_LAST_ERROR flag, access-condition tags AutoRef=0x23/Conf=0x20, data-type tag 0xE8, AUTHREF type 0x31), added `get_random` + `hmac_verify` primitives. Switched `authenticate_and_read` to proper HMAC challenge-response protocol (chip-side verify via DecryptSym CMD 0x95 + tag 0x43). Added admin factory-reset via shielded-connection Conf(E140) path — avoids SE050-style permanent lockout by making every user OID's Change AC `Auto(F1D0) OR Conf(E140)`. Physical fixes validated on real hardware: CTL→3V3 jumper required, 50µs guard time between register-write/read transactions required, ReSynch is fire-and-forget. OpenApplication now returns valid response. Saved bring-up quirks to memory (`project_optiga_bringup.md`). |
| 2026-04-17 | C10 bootstrap cutover | Replaced SPHINCS+C11 bootstrap identity with **SPHINCS+C10** (`h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205 sig=4008`, 4073-byte Type 1 wire frame). New `sphincs-c10/` crate with correct portable `extract_ht_index` (4-byte load for H=18 vs 3-byte for H=16) replaces the old `sphincs-c7/` directory; firmware/crypto/sign-state-machine/shared wire formats all ported. New on-chain `SPHINCsC10Asm.sol` SHA-256-precompile verifier (subtree_h=9, 9-level Merkle auth, target_sum=205) replaces `SPHINCsC11Asm.sol`. Added per-chain `bootstrapUses` counter in `PQOwnable` storage (ERC-7201 slot+1), `MAX_BOOTSTRAP_USES = 65_536` cap enforced in `PQJardinWallet._validateSignature` pre-check and bumped via `_bumpBootstrapUses(cap)` after successful Type 1. Added `BootstrapKeyUsed(newCount)` event and `bootstrapUses()` view. Factory `createAccount` salt still `sha256(masterPkSeed || masterPkRoot)`, so the C11→C10 change re-bases every wallet address for a given seed — acceptable since no live deployments exist. 5 new `SPHINCsC10AsmTest` Foundry tests driven by a Rust-generated `c10_test_vectors.json` (keygen + sign + self-verify runs under `cargo test -p sphincs-c10 --test gen_test_vectors --release`), 4 new bootstrap-counter tests in `PQJardinWalletTest` covering success bump, failure no-bump, cap-rejects-overflow, and post-exhaustion Type 2 still works. All 33 Foundry tests pass. SHA-256 stays throughout; no keccak256 regressions. |
| 2026-04-16 | OPTIGA OID recovery + provisioning workaround | Added SetObjectProtected (CMD 0x83) to the Rust driver — `protected_update_start/continue/final` + chunking helper in `optiga/apdu.rs`, plus new `optiga/reset.rs` (CBOR-signed manifest blob + iter helper) and `optiga/reset_pin.rs` (PE0 = Arduino D5 GPIO toggle for the chip's RST line). Generates 16 manifests via the Infineon `protected_update_data_set` tool (now buildable on Linux via cloned mbedtls 2.28.8 + CRLF/include-separator/buffer-overflow patches) signed by Infineon's sample EC P-256 key, embedded via `include_bytes!`. New `optiga-reset-oids` feature + `make flash-hw-optiga-reset` target. **Validated 16/16 OIDs reset on real silicon.** Same `hard_reset_and_reinit` (RST low ~10 ms + OpenApp) wired into `store_objects` between every provisioning step — works around the chip's "after 2 SetData ops the next APDU never gets a RESP_READY" wedge. End-to-end wallet provisioning succeeds on both OPTIGA and SE050 halves. Shielded Connection handshake remains the next blocker — see `docs/optiga-bringup-status.md` for the open list. |
| 2026-04-21 | #24 Phase-A Shielded Connection + PIN unlock end-to-end | Five commits: (1) `fa06a4f` drop unneeded LcsO=op bump from `ensure_shield`. (2) `43b6937` fix the MasterFinished handshake rejection — PRF seed was `random_M‖random_S` but reference uses only `random_S`, MasterFinished plaintext must be `random_S‖slave_seq`, and header/nonce/AAD seq must be `slave_sequence_number` from SlaveHello (not zero). (3) `a1ac0cd` provisioning-through-shield fixes: `send_command` now uses `transceive_prl` (PRESENCE_BIT) so records reach the PRL layer; `hard_reset_and_reinit` clears `shield.active`; `store_objects` threads `ensure_shield` after PBS write and after every hard-reset. (4) `635e018` skip `set_metadata`+`lock_oid` on OIDs already at LcsO=Operational (one-way ratchet blocker from pre-0b412b4 runs). (5) `3d34101` PIN unlock via AUTHREF HMAC — `PARAM_HMAC_MODE` was 0x02 but must be `OPTIGA_HMAC_SHA_256 = 0x20` per `optiga_lib_common.h:213`; added `generate_auth_code` APDU (`GetRandom` with `store_in_session=TRUE`) required for `hmac_verify` to find a valid session. Full flow reaches `hmac_verify OK → Unlocked: entropy + VKs cached → gateway pre-unlocked, ready for tests` on real B-U585I-IOT02A + OPTIGA Trust M V3. New `flash-hw-optiga-unlock-test` + `flash-hw-optiga-shield-handshake-only` Makefile targets. |
| 2026-04-17 | All-C10 slot cutover + stateless firmware | Per-slot signing key is now SPHINCS+C10 instead of JARDÍN FORS+C — one primitive, one verifier, no variable-length Type 2. The firmware is **stateless** for slot selection: the companion supplies `(chain_id, slot_index, flags)` on every `CMD_SIGN_USEROP`; `FLAG_REGISTER_SLOT` (bit 30 of flags) tells the firmware when to emit a Type 1 ahead of Type 2. Deleted `jardin-fosc/` crate (root + workspace refs), `secure/src/nsc/jardin_flash.rs` (flash pages 123-124 no longer used for slot state), `secure/src/nsc/cmd_get_jardin_slot_info.rs` (CMD 17 retired), `contracts/.../JardinForsCVerifier.sol` and `IJardinVerifier.sol`. `PQJardinWallet` gains a second on-chain counter `slotUses[slotKey]` capped at `MAX_SLOT_USES = 65_536`, bumped by `_bumpSlotUses` inside the Type 2 path; `PQOwnable` extends its ERC-7201 struct with the mapping and a `SlotKeyUsed(slotKey, newCount)` event. Single `c10Verifier` now handles both Type 1 and Type 2 (same stateless SHA-256-precompile verifier, different `(pk_seed, pk_root)` per call). Slot C10 keys are derived deterministically from `(jardin_master_entropy, slot_index)` via new domain tags `"jardin_slot_c10_sk_seed"` / `"jardin_slot_c10_pk_seed"` and cached in SRAM across the unlock session only. New `secure/src/crypto.rs::derive_c10_slot_keypair_with_progress` helper mirrors the master path; `SecureState::JARDIN_SLOT: Option<CachedSlot>` replaces the FORS+C slot cache. Wire formats: Type 2 is now fixed at 4073 bytes (C10 sig); `JARDIN_TYPE2_LEN = 4073`; `MAX_JARDIN_RESPONSE_LEN = 8246`; removed `JARDIN_FORSC_BODY`, `JARDIN_SIG_MIN/MAX`, `JARDIN_Q_MAX`, `JARDIN_WRAPPER_*`, `NscStatus::SlotExhausted`, `CMD_GET_JARDIN_SLOT_INFO`, `CMD_SIGN_JARDIN`, `CMD_REGISTER_JARDIN_SLOT`, `INS_V2_*JARDIN*`. Master C10 derivation unchanged → every seed still maps to the same CREATE2 wallet address. CLAUDE.md invariants updated (old #6 `next_q`-before-flash removed; #7 now covers both use caps; new #8 for the stateless firmware property). Builds clean for `thumbv8m.main-none-eabi` across all feature combos (`mock-se`, `e2e-test`, `bench-key-speed + stm32u585`, `usb`). 4-scenario QEMU e2e runner exercises register/repeat/rotate/second-chain; bench exercises cold first-sign / N cached Type 2 / second-chain cached-slot. |
| 2026-04-17 | Hardware bring-up — SE050+OLED+USB working end-to-end | Wizard runs, SE050 unlock completes, OLED comes up, NS USB HID enumerates on host. Fixes: `secure_log!`-gate the unconditional `hprintln!` in `hw::hash::init_clock`'s SHA-256 self-test (DHCSR `C_DEBUGEN` runtime check) so standalone firmware stops HardFaulting pre-OLED. STM32U5 TRNG init rewritten with the NIST-compliant CR value `0x00F00D00`, CONDRST at bit 30 (not bit 6), and SEIS/CEIS clear path; init moved to after `sau::init()` so GTZC has assigned RNG's security attribute. First-boot wizard now logs every branch of its retry loop. `flash-hw-se050-oled-standalone` now runs `probe-rs reset` after option-byte programming so the target actually starts. GTZC1_TZSC_SECCFGR{1,2,3} cleared to 0 (everything NS) for USB bring-up — USB OTG FS is an AHB2 peripheral governed by a separate GTZC2_TZSC controller whose base address we have not yet confirmed (our guess at `0x52034400` bus-faulted). This is a pre-production regression of invariant #4 tracked in the new CLAUDE.md "Development Posture" section; restoring the allowlist is a known TODO. `debug-log` also removed from the hardware-release `compile_error!` gate so on-target semihosting works during bring-up. |
| 2026-04-18 | EntryPoint v0.9 → v0.6 migration | Full stack retargeted from ERC-4337 EntryPoint v0.9 to v0.6 (Coinbase-Smart-Wallet-compatible). `PQSmartWallet` now imports `IAccount06`/`UserOperation06` from `account-abstraction/legacy/v06/`; `sphincsDigest` rebuilt over individually-encoded gas fields (`callGasLimit`, `verificationGasLimit`, `preVerificationGas`, `maxFeePerGas`, `maxPriorityFeePerGas` — no more packed `bytes32`). Firmware: new `compute_sphincs_digest_v06` in `secure/src/aa/userop.rs` (SHA-256 path stays so the HASH peripheral remains on the hot path), v0.9 helpers (`AaUserOpParamsV09Sha256`, `compute_user_op_hash_v09`, EIP-712 envelope + typehashes) deleted outright. Shared wire format: `SIGN_USEROP_HEADER_LEN` bumped 266 → 330 with five individual u256 gas slots. Companion (`tools/webhid_test.html`), NS e2e + bench runners, USB `GET_DEVICE_INFO` (`ep_version = 0x0006`), `CLAUDE.md`, `docs/companion-app-integration.md`, `docs/usb-protocol-v2.md` all flipped. CREATE2 addresses re-measured offline with `cast create2` under `FOUNDRY_PROFILE=deploy`: SPHINCsC10Asm `0x2f9DA5…79d9` (unchanged), PQSmartWallet impl `0x2f590E…f679`, PQSmartWalletFactory `0x375eBb…D6fB`, `PROXY_INIT_CODE_HASH = 0xdba8c282…e85b` — all baked into `shared/src/lib.rs` and `contracts/smart-wallet/deployments/base-sepolia.json`. All 28 Foundry tests + 27 host-side Rust tests + 8 shared-layout tests pass; `sphincs-c10/tests/gen_test_vectors.rs` regenerated for the unpacked digest. |
| 2026-04-20 | Firmware update subsystem — hash-signature PQ model | New end-to-end signed firmware-update pipeline. Reproducible builds (`.cargo/config.toml` with `--remap-path-prefix` + `--build-id=none`, `make verify-repro` diffs two clean builds, SOURCE_DATE_EPOCH from git, docs/reproducible-builds.md). New workspace members: `fw-manifest/` (no_std manifest layout + CRC32-IEEE + verify chain; 11 unit tests), `fwsign/` (host-side signer: `keygen`/`pubkey`/`sign`/`verify`/`verify-release`/`extract-sig`/`inspect` with Argon2id + XChaCha20-Poly1305 at-rest key encryption), `fsbl/` (immutable 32 KB-budget first-stage bootloader, currently 18 KB with software SHA-256). Secure-world additions: bank-2 (NS flash) write/erase via NSCR in `hw/flash.rs`, OTP rollback counter in `hw/otp.rs` (32×32-bit tally = 1024 commits), boot-state page in `hw/boot_state.rs`, full `fw_update/` state machine with `{begin,chunk,commit,status,abort}` NSC handlers + CMSE veneers. Shared types: `CMD_FW_*` 20..24, `INS_V2_FW_*` 0x70..0x74, seven new `NscStatus::FwUpdate*` variants. USB protocol: 8 KB manifest chained over APDU v2, 1 KB chunks, reuses `FW_STATUS_RESPONSE_LEN` for progress polling. Crypto: **SPHINCS+C10 end-to-end for sign + verify**, entire path PQ-secure; the minimal signed preimage is `SHA-256("PQFW_V1" \|\| fw_version_be \|\| secure_hash \|\| nonsecure_hash)` — 75 bytes reconstructable from `(version, secure.elf, nonsecure.elf)` alone, so independent auditors verify via `fwsign verify-release` without parsing any manifest. One `.pqfw` per release (slot byte is unsigned metadata). Requires PIN unlock on every command (defence in depth). Anti-rollback enforced via OTP fuses (RDP-2-resistant). Power-fail safe: inactive slot fully erased + written + re-hashed before any boot-state flip. Docs: `docs/firmware-update.md` (architecture + verify-it-yourself + PQ inventory). Complete file list: `.cargo/config.toml`, `fw-manifest/{Cargo.toml,src/lib.rs}`, `fwsign/{Cargo.toml,src/{main,keystore,elf,bundle}.rs, src/subcommands/*.rs, tests/sign_verify_roundtrip.rs}`, `fsbl/{Cargo.toml,memory-stm32u585.x,build.rs,src/*.rs}`, `secure/src/{fw_update/*.rs, hw/{otp,boot_state}.rs, nsc/cmd_fw_*.rs}`, `docs/{firmware-update,reproducible-builds}.md`. Remaining: trusted-UI confirm dialog (stubbed until the `secure/src/tx/display/` refactor lands), A/B linker-script split, hardware bring-up, companion updater, WRP1A in ob-configurator, CI signing pipeline. `make verify-repro` passes (byte-identical ELFs). 19 crate tests pass (11 fw-manifest + 4 fwsign keystore/elf + 4 fwsign integration). |
| 2026-04-20 | #24 OPTIGA pairing restructure — OTP-derived PBS + HUK re-root | Stage 1 landed in source: `hw/otp.rs` extended with `read_device_master` / `burn_device_master` / `is_device_master_burned` / `ensure_device_master` over OTP bytes 128..160 (Trezor-style first-boot self-provisioning — no factory target, device burns its own 32 TRNG bytes on first power-up and locks the region). New `hw/secret_keys.rs` exposes HMAC-SHA256 derivations per domain label: `optiga_pairing_secret` / `se050_scp03_enc_key` / `se050_scp03_mac_key` / `tropic01_pairing_key`. `optiga::mod::setup_pbs_no_handshake` rewritten to consume `optiga_pairing_secret` instead of `rng::fill`; `write_pbs` call deleted; LcsO=op bump now additionally refuses to proceed unless `is_device_master_burned()` is true. `optiga::mod::load_pbs` collapsed to a one-liner that runs the HKDF derive + `shield.load_pbs`. `hw/huk.rs::derive_device_key` re-rooted off `measured_boot::firmware_hash()` and onto `otp::ensure_device_master()`; return type bumped to `Result<[u8;32], OtpError>`. `hw/flash.rs` PBS seal infrastructure deleted (`read_pbs` / `write_pbs` / `erase_pbs_page` / `PBS_PAGE_ADDR` / `PbsLoadError` / `PBS_WRAP_DOMAIN` / `PBS_BLOB_LEN` / `is_pbs_blank`). `optiga-bringup-fresh` Cargo feature removed + all feature-gated code paths collapsed (`auth_ref_is_authref_typed` deleted, `lock_oid` / `provision_user_oid` / `store_objects.already_provisioned` unconditionally locked). Makefile `flash-hw-optiga-reset` recipe no longer lists the feature. New `otp-hardcoded-master-key` dev feature returns the ASCII constant `"PQSIGNER-TEST-OTP-MASTER-DNS-v1!"` so the derivation path can be exercised on the bench without consuming real OTP; guarded against production builds (`compile_error!` in `nsc/mod.rs` fires on `stm32u585 + !debug_assertions + !e2e-test`) and against combining with `optiga-lock-operational` (separate `compile_error!` — would lock chips to a shared compile-time PBS). Production-security.md §1.6 + §2.6 document the architecture and the Trezor DHUK/BHK/OTP three-tier model we're adopting in stages. All compile-matrix variants pass (`stm32u585 + dual-se + hardcoded + e2e-test`, `stm32u585 + dual-se + e2e-test`, default QEMU); 50/50 host tests pass. Still pending: validation on a fresh SLS32AIA (item #24 P2) — reserved for last per request. |
| 2026-04-20 | #24 P2 hardware validation — Phase A end-to-end on fresh TRUSTMV3SHIELDTOBO1 | Full Phase-A (write-only, `e2e-skip-unlock`) now passes on a pristine OPTIGA Trust M V3 shield. Confirms every load-bearing claim of #24 on real silicon: (a) HKDF-Expand SHA-256 over the hardcoded master produces the expected 64-byte PBS with fingerprint `8ca52e4bc284d822`; (b) E140 accepts the 64-byte write + metadata at LcsO=Creation (Sta=0x00 both APDUs); (c) hard-RST pulse demonstrably reaches the chip (LA1010 on CH2 sees the 22 ms falling edge); (d) all 6 user OIDs (F1D0 AUTH_REF / F1D1 ENTROPY / F1D2 MASTER_SECRET / F1D3 VK / F1D4 BOOTSTRAP_VK / F1E1 COUNTER) provision cleanly and lock; (e) E140 stays at LcsO=Creation → chip fully recoverable. Fingerprint is stable across multiple reflashes with differing `firmware_hash`, confirming the brick class is gone. Two side fixes dropped during bring-up: (1) RST pin retargeted from PE0 → PE4 after LA-driven pin identification (Arduino D5 on B-U585I-IOT02A routes to PE4 through the SE050 shield's pass-through header). The prior PE0 / PD5 / PA4 guesses were all wrong silkscreen reads; the pin-diag module (`secure/src/pin_diag.rs`) now ships as the hard-reset primitive `OptigaTrustM::hard_reset_and_reinit` invokes, because a minimal-BSRR `reset_pin::hard_pulse` path did not produce a visible edge under a silicon/timing quirk we haven't fully isolated. (2) Canonical user-OID range restored: an earlier bring-up commit had rotated `OID_AUTH_REF`/`ENTROPY`/`MASTER_SECRET`/`VK` into 0xF1DC..0xF1DF, outside the SRM's actual 0xF1D0..0xF1DB type-3 arbitrary-data range. Fresh silicon refused the first SetDataObject with Sta=0xFF; bench chip had appeared to work because of its SetObjectProtected-recovered state. Rotated back to F1D0..F1D4. Commits: `b19fbf7` (Stage-1 core), `30f0e6d` (PE4 RST + pin_diag), `ab8c39f` (OID range fix). Work-todo #24 P2 Phase A is **done**; Phase B (full PRL handshake committing E140 LcsO=op) deferred until the unlock / trusted-UI path is restored. |
| 2026-04-21 | OPTIGA factory_reset roundtrip e2e — validated on real silicon | New `optiga-admin-wipe-e2e` Cargo feature + `make optiga-admin-wipe-e2e` target exercises the OPTIGA wipe primitive end-to-end: provision F1D0..F1D4 + F1E1 with distinct test vectors via `store_objects`, verify `authenticate_and_read` returns the provisioned `master_secret` byte-exact, run `factory_reset`, confirm F1E1 reads `RESET_SENTINEL` (0xFF), confirm a second `authenticate_and_read` returns `OptigaError::NotProvisioned` via the sentinel short-circuit (not via counter-exhaustion), confirm `check_provisioned() == false` (the boot-path contract that triggers the first-boot wizard), and clear the page-125 wipe flag as post-test hygiene. Also hardens `factory_reset` itself with `self.ensure_shield()?;` at the top so the `Conf(E140)` arm of user-OID Change ACs is satisfied regardless of caller ordering. LcsO-safety verified: feature does NOT imply `optiga-lock-operational` → `lock_oid` is a no-op, all metadata builders emit no LCS tag, no OID is promoted to Operational. **PASS on real B-U585I-IOT02A + OPTIGA Trust M V3** (the previously-provisioned bench chip): all 6 steps green + flag cleared. Commit `218a29b`. Scope note: tests the `factory_reset` primitive only — the PIN-lockout-triggers-wipe integration is deferred to a separate test. |
| 2026-04-21 | Dual-SE unlock roundtrip e2e — PASS on real silicon (after v4 range bump + two real-dual-SE unlock-path bug fixes) | New `dual-se-unlock-e2e` Cargo feature + `make dual-se-unlock-e2e` target covers the XOR entropy reconstruction across OPTIGA + SE050 — the unique dual-SE value-add not covered by either single-SE test. Bumped SE050 production OID range from `0x7B06_xxxx` (v3) to `0x7B0C_xxxx` (v4) to bypass the bench chip's stuck-UserID v3 state (same pattern as the earlier v2→v3 bump for legacy firmware residue; old objects now dead-weight at <100 B). After the bump, hardware surfaced two real unlock-path bugs that had never been hit because dual-SE + real OPTIGA is only workable since last week: (1) `DualSecureElement::unlock` cross-verified `master_o.ct_eq(&master_e)` but SE050 doesn't store `master_secret` — it derives `kdf("sphincs-master", half_e, 0)` which is only meaningful in single-SE mode. Removed the cross-verify; the consistency check `kdf(full_entropy) == master_o` further down is strictly stronger. (2) `DualSE::unlock` was decrypting SE050's entropy_blob cache with OPTIGA's `master_o`, but each SE caches its blob under ITS OWN master. Fixed to decrypt SE050's blob with `master_e`. Final status: **PASS on real B-U585I-IOT02A + OPTIGA Trust M V3 + SE050.** All 5 steps green. Diagnostic instrumentation retained in `dual_se.rs::run_unlock_roundtrip` for future bring-up sessions. Scope note: this validates the XOR unlock + cross-chip consistency; the dual-SE `factory_reset_admin` integration remains deferred (needs fresh SE050 whose admin state is in sync with page 125). Also surfaced a latent design gap: `se050/mod.rs:35-42` docstring describes admin-PIN derivation from OPTIGA PBS that was never implemented — item added to work-todo #7 as "Early-adopt: derive SE050 admin PIN from OTP master (pre-DHUK)" since it closes the entire class of "bench chip admin is unrecoverable" bugs without waiting for the full SAES migration. Commits: `218a29b` (OPTIGA hygiene) → `0600395` (initial dual-SE test + OPTIGA hygiene removal) → `3204d57` (scope narrowing to unlock) → `466e745` (defer + three-tier spec) → `227b51c` (v3→v4 OID range bump) → `995c5a3` (unlock-path fixes). |
| 2026-04-22 | OPTIGA silicon PIN counter (E120 + LUC binding) | `optiga-hw-counter-e2e` PASSES on fresh TRUSTMV3SHIELDTOBO1. F1D0 AuthRef's Execute AC bound to `LUC(E120)` via `0x40 OID_HI OID_LO` AC operand. E120 metadata must have `Execute=ALW` (not NEV) for LUC to fire (Trezor parity). The APDU shape that triggers LUC is Trezor's `optiga_set_auto_state` — 16-byte GetRandom nonce + 18-byte DecryptSym — not the 64-byte compound input from Infineon's reference example. Recovery path (`recover_hw_counter_metadata`) handles the broken-Exec=NEV state auto-detected via metadata probe. Memory: `project_optiga_hw_counter_validated.md`. Commits: `987408f` → `5620b06`. |
| 2026-04-22 | Three-way PIN counter lockstep (MCU + E120 + SE050) — validated on silicon | `pin-gate-hw-counter-e2e` now exercises all three counters across 5 phases — provisioned, wrong+correct, MCU-ahead desync, OPTIGA-ahead desync, SE050-ahead desync — and passes end-to-end. Fixed a long-standing "best-effort for now" comment in `dual_se.rs:126-128`: OPTIGA was short-circuiting with `?` on wrong PIN so SE050's UserID silicon counter never advanced via the production unlock path. Rewrote `DualSecureElement::unlock` to call SE050 on both Ok and PinIncorrect from OPTIGA, skip SE050 only on non-PIN errors. Defense-in-depth closed: direct-I2C attacker can no longer burn E120's 32 attempts without touching SE050. Gateway `cmd_get_remaining` now returns `min(MCU_remaining, SE-pair_remaining)` — the MCU counter was previously invisible to UI. SE050 `remaining` field marked as display-only in its doc comment (grep confirmed no control-flow use). Commit: `7574218`. |
| 2026-04-22 | Gap 1 — cross-boot SE050 cache re-sync | New trait method `WalletStore::sync_remaining_with_mcu(used)` that ratchets `self.remaining` DOWN to `min(current, MAX - used)` — idempotent, only lowers. Called once at boot in `main()` right after the wipe-check block. Before this, `SE050.remaining` and `OptigaTrustM.remaining` software mirrors reset to `MAX_ATTEMPTS` on every power-on while MCU page-124 retained the durable count, making both caches lie until the next successful unlock resynced them. Validated via phase-5 of `pin-gate-hw-counter-e2e` (simulated reboot via `_e2e_force_remaining_to_max` test helper, then re-sync, then verify SE-pair min reflects the correct post-reboot remaining count). Commit: `0ecfe69`. |
| 2026-04-22 | Gap 3 — MCU MAX_ATTEMPTS wipe-dispatch combined e2e | New `pin-gate-wipe-e2e` feature + Makefile target. Destructive 10-iteration wrong-PIN burn through `gated_unlock` drives all three counters to saturation (MCU=10, E120=+10, SE050=0). 11th attempt returns `PinLocked` via MCU pre-check. `factory_reset_admin` + `pin_attempts_reset` then wipe both chips. Re-provision succeeds and the clean-unlock that follows returns SE050 `remaining` to MAX — recovery proven. Two empirical findings: (a) SE050 signals the terminal wrong-PIN attempt with the same SW as iter 1..9 (the chip does NOT emit a "locked" SW on the attempt that locks it — only on subsequent attempts, which in production won't happen because MCU wipes at attempt 10), (b) E120 carries state across test runs so per-iteration assertions use delta tracking against a captured baseline rather than absolute values. Commit: `d0dda77`. |
| 2026-04-22 | Gap 6 — E120 counter reset on factory_reset (Trezor transient-auth) | Discovered during Gap 3 validation: E120's silicon LUC counter value survived every `factory_reset` because its Change AC is `Auto(F1D0)` and the user's PIN is gone at wipe time, so we couldn't satisfy that AC from the admin-wipe path. Multi-wipe soft-brick DoS: 3+ cycles of `10-wrong-PIN → wipe` without successful unlock in between saturates E120 at `HW_PIN_CTR_LIMIT=32`, after which the `curr >= limit` pre-check rejects every auth regardless of PIN. Advisor + Trezor research confirmed the fix is Trezor's production pattern (`core/embed/sec/optiga/optiga.c:782-847`): during `factory_reset`, write 32 TRNG bytes as a transient F1D0 secret (Change=ALW lets us without auth), HMAC-verify with it to open F1D0's session, call `reset_hw_pin_counter` to snap E120 to (0, limit), then proceed with the existing wipe that zeros F1D0 anyway. Our metadata matches Trezor's exactly so the pattern is not speculative. Security: transient secret is TRNG-derived, unguessable; attacker with E140 PBS already owns the chip so no new capability. Validated on silicon via new `pin-gate-wipe-e2e` post-wipe E120 assertion — reads 0 after wipe (was baseline+10 before the fix). Commit: `f0ee040`. |
| 2026-04-22 | wipe-for-wizard dev target + idempotent boot | New `make wipe-for-wizard` flashes a dev firmware that wipes OPTIGA user OIDs + SE050 user objects + MCU page 124 on first boot, then drops into the first-boot wizard on the next power-cycle. Preserves OTP master, OPTIGA E140 PBS, and every OID's LcsO=Creation metadata so the chip stays mutable for continued dev iteration. Wraps `DualSecureElement::factory_reset_admin` (inherits the Trezor-parity E120 transient-auth reset from `optiga-hw-counter`). `is_provisioned()` gate added so replugging the device after a successful wipe skips the wipe block instead of re-erasing — previously the wipe looped on every reboot. Paired feature `dev-testkey = ["otp-hardcoded-master-key"]` lets the interactive wizard build bypass OTP programming on bench boards while keeping the real first-boot wizard + PIN entry live (distinct from `e2e-test` which replaces the wizard with the auto-provision fast-path). Commits: `09c7816` (initial), `9a609d9` (idempotency fix). |
| 2026-04-22 | SE050 cold-boot T=1 `interface_reset` retry | Fresh power-on saw `interface_reset` return `Transport` ~15% of the time on the B-U585I-IOT02A bench, then succeed on every subsequent attempt — a T=1 atr-exchange race between the MCU's first SDA edge and the SE050's internal wake-up debounce. Added a 3-attempt retry loop with exponential backoff in `Se050::init`, behind a `cold-boot-t1-retry` inline path (no feature flag — the retry is always-on because it's strictly additive: on a healthy chip the first attempt succeeds, retries only run when needed). Logs per-attempt so a systemic failure still surfaces in semihosting. Commit: `5ce127d`. |
| 2026-04-22 | `CMD_GET_INIT_CODE` for first-deploy gas estimation | New gateway command (CMD 8) that returns the 20-byte CREATE2 factory address + the 66-byte proxy initCode preimage so the companion app can compute accurate `verificationGasLimit` for a first-ever UserOp (before the wallet is deployed, EntryPoint has to deploy it via initCode which adds ~300k gas). Without this, companion apps were estimating conservatively and burning ETH on over-funded deploys. Wire format: `ShortResponse { factory: [u8; 20], init_code_preimage: [u8; 66] }`, response 86 bytes. No secrets touched — all inputs are compile-time constants baked into `shared/src/lib.rs`. Commit: `337feca`. |
| 2026-04-23 | OPTIGA RST wire D5→D6 — eliminates SE050 ENA cross-coupling | Colleague reported "XOR entropy reconstruction works first boot, fails on reboot". Root cause: OPTIGA RST jumper was on Arduino D5 header = STM32 PE4 on B-U585I-IOT02A. The stacked OM-SE050ARD shield routes its D5 header to SE050's ENA (enable) line — every `hard_reset_and_reinit` pulse on PE4 power-cycled the SE050. When a pulse landed mid-NVM-write during provisioning, `ENTROPY_OBJ` partially programmed; `check_exists` still saw the object but read-back returned corrupted bytes → XOR with fresh half_O produced garbage. Hardware fix: moved RST wire to D6 header (no SE050 net on OM-SE050ARD). Firmware: `reset_pin::RST_PIN` PE4 → PE0 (D6 empirically maps to PE0 on this board via `pin_diag::header_sweep` + LA CH2 capture — UM2839 Table 24's "D6 = PB6" is wrong for this silkscreen, `header_sweep` retained gated behind `pin-diag-boot` for future re-verification). `pin_diag::run()` scoped to PA4/PD5/PE0 only — critically drops PE4 so production OPTIGA resets can never re-trigger the cross-coupling. New `OptigaTrustM::init()` pulses RST via `pin_diag::run()` at the top because on cold boot the chip's internal RST pull-up alone isn't reliable on the jumper-wire stack. Validation: new `make dual-se-multi-unlock-e2e` (15 unlocks across 3 cold reboots, master_secret reproduces byte-identical every time) PASSES — stricter proof than dual-se-admin-wipe since Boots 2+3 detect already-provisioned state via probe-unlock and run 5 consecutive unlocks without re-provisioning. Also added `make pin-diag-boot-hw` one-shot Arduino-header identifier + memory `reference_b_u585i_iot02a_arduino_header_mapping.md`. Commit: `2368003`. |
| 2026-04-23 | SE050 admin-wipe — OTP-derived PIN + per-object diagnostics + 6-canary selftest | Four bugs fixed in the admin-wipe path. Dominant root cause (not on advisor's list — surfaced by diagnostic instrumentation): `Se050::factory_reset_admin` trait impl was reading admin PIN from flash page 125, but provisioning writes the chip's admin UserID with an OTP-derived PIN (`hw::secret_keys::se050_admin_pin()`). Page 125's PIN slot is deliberately blank on v6 OTP-derived provisionings, so `is_admin_pin_blank()=true` routed every wipe into `iterative_wipe(None, None)` — unauth sweep can't touch admin-gated user objects, wallet seed survived every supposed wipe. Fix: trait impl now re-derives via `se050_admin_pin()`, matching provisioning. Bug 1 (work-todo #27): `admin_factory_reset` silently swallowed every `delete_object_authed` error via `let _ = ...`; returned `Ok` on total failure. Fix: per-object Ok/Err(status) logging + post-`check_exists` + return Err if any user object survived. Bug 2 (#28): `store_objects` skip-if-exists would silently inherit stale policy shape from prior firmware. Fix: under admin mode (admin_pin.is_some()), any object surviving the pre-write stale sweep is a hard Err (SW=0x6986) — loud signal replaces silent inheritance. Bug 3 (#29): `policy_roundtrip_selftest` only covered 2-canary shape while production's `admin_factory_reset` does 6 deletes under one session. Fix: extended selftest to write 1 UserID + 5 data canaries (0x7B10_00B0..B5), admin-delete all 6 in one session with per-object logging + post-check each — catches session-invalidation-after-Nth-delete regressions that the 2-canary shape couldn't see. `admin_factory_reset` USER_OBJS cleanup list expanded to cover the full 0x7B10_00B0..B5 canary range for stranded-selftest recovery. Validation: `dual-se-admin-wipe-e2e` PASSES all 8 steps on silicon (step 7 "both chips unprovisioned post-wipe OK" now green — was the long-standing failing test). Selftest trace shows 6/6 canary deletes Ok under one session, proving no session-invalidation quirk. Benign expected-failure: canary 0x6985 on `CANARY_{DATA,USERID}_CLEANUP` during admin_factory_reset because selftest's own cleanup already deleted them; post-check confirms they're actually gone. Commits: `1bfb572` (Bug 1 + OTP-derivation), `e6b8c2f` (Bug 2), `38982c7` (Bug 3). |
