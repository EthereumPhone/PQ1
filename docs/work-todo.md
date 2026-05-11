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
- [x] `secure/src/hw/saes.rs`: SAES driver. Init (SHSI-on, AHB2 SAESEN bit 20, peripheral reset, RNG-seed wait), AES-256 **ECB-only** encrypt/decrypt under `KEYSEL=Software|DHUK|BHK|DHUK^BHK`, under the `saes-dhuk` feature (OFF by default). CMAC lands in software (the `cmac` crate — already a secure-crate dep) on top of the ECB primitive; avoids the CHMOD/NPBLB register surface. Register offsets + bit positions cross-checked against the `stm32u5-0.16.0` PAC crate (machine-generated from ST's SVD) AND the STM32CubeU5 HAL `stm32u5xx_hal_cryp.c` + CMSIS `stm32u585xx.h`.
- [x] Boot-time self-test: `saes-self-test` feature runs `hw::saes::init` + `hw::saes::self_test` (software-key round-trip + DHUK-vs-SW domain separation + DHUK round-trip), prints an 8-byte DHUK fingerprint for cross-boot consistency checks, then `SYS_EXIT`s so `probe-rs run` returns. `make saes-self-test-hw` target wires the whole thing up. Self-test feature is added to the production-build `compile_error!` fence in `secure/src/nsc/mod.rs`.
- [x] Validate on real silicon — same-board cross-boot consistency at RDP0: **PASS** on B-U585I-IOT02A. Two consecutive `make saes-self-test-hw` cold-boot runs produced byte-identical DHUK fingerprints (`11 7d 82 2a 62 a5 08 30`).
- [x] Validate on real silicon — per-die uniqueness at RDP0: **EXPECTED COLLISION** — a colleague's independent B-U585I-IOT02A produced the identical fingerprint `11 7d 82 2a 62 a5 08 30`. Per ST documentation (cited in `docs/research-bundles/results/compass_artifact_wf-c249ee53-14d4-4a31-ad60-46a95a371c63_text_markdown.md:74`): *"at RDP0 the DHUK is a known constant (per ST documentation: 'SAES will use a constant value instead of DHUK' at RDP0). [...] The real DHUK activates at RDP ≥ 1."* So the RDP0 fingerprint `11 7d 82 2a 62 a5 08 30` is ST's "RDP0-DHUK-placeholder" value, shared across every STM32U585 in the world. Per-die DHUK cannot be validated until a board is stepped to RDP1+. This finding is a Tier-1 validation *success* — caught the RDP0-constant-DHUK class of mistake before Tier 2 BHK could land against it.
- [x] Validate on real silicon — per-die uniqueness at RDP ≥ 1: **PASS across two B-U585I-IOT02A boards (2026-05-05).** Same firmware image flashed identically; same OB profile applied identically; only the silicon die differs:

  | Board | RDP0 fingerprint | RDP1 fingerprint |
  |-------|------------------|------------------|
  | #1 (ST-LINK SN `0029…3838`) | `117d822a62a50830` | `ea86dbc4586953a6` |
  | #2 (ST-LINK SN `004F…3838`) | `117d822a62a50830` | `002202686b06dcf6` |

  Both boards collapse to ST's substituted constant `117d822a62a50830` at RDP0 (= ST documented behaviour: "SAES will use a constant value instead of DHUK at RDP0"). At RDP1 the two boards produce distinct fingerprints, falsifying the alternative hypothesis that DHUK is a global ST-controlled constant at all RDPs. **Tier-1 security claim — "SAES-CMAC(DHUK, ...) outputs are per-die at production RDP, not the dev-bench RDP0 constant" — empirically validated.** Path to this validation took 10 step-to-RDP1-and-recover cycles on board #1 plus one on board #2, plus building two new diagnostic channels (`hw::boot_pulse` GPIO-toggle on PE13/D13 and OLED stage-indicator prints). At RDP1+TZEN=1+no-OEM-keys: SWD halt is denied (`DEV_TARGET_NOT_HALTED`), UART (PA9) is silent, and a discretionary GPIO toggle on PE13 is silent (root cause not isolated, but I2C1+OLED works on the same chip). The OLED retains its image across resets and is the channel that surfaced the validation. Recovery dance documented thoroughly (BOOT0=HIGH + TAMP_IN8/PE4↔TAMP_OUT8/PE5 wire + USART bootloader `-tzenreg`); 11/11 successful recoveries across both chips. The `boot-pulse` and OLED-instrumentation diagnostic infrastructure is preserved in-tree behind feature flags for future RDP1 bring-up work.
- [x] Rewrite `hw::secret_keys::derive_into` to use `SAES-CMAC(DHUK, info)` for 32-byte outputs, chained CMAC for 64-byte outputs (PBS). Preserve the `otp-hardcoded-master-key` dev feature — under that feature, fall back to the HKDF-over-constant path so QEMU + bench without SAES-DHUK still work. **LANDED (2026-04-24).** Three cfg branches: `otp-hardcoded-master-key` → HKDF over constant (unchanged); `saes-dhuk` alone → `kdf_cmac_counter_generic` (simplified SP 800-108-style CMAC-based counter KDF); neither → legacy HKDF-over-OTP fallback so existing hardware builds don't regress until they opt into `saes-dhuk`. The CMAC core + the counter/packing KDF wrapper both live in `secure/src/cmac.rs` as pure-logic host-testable functions — 4 NIST SP 800-38B AES-256-CMAC KATs + 9 KDF layout/packing/bounds tests (15 pass against the `aes::Aes256` software backend, which proves the device math is byte-identical to NIST). `hw::saes_cmac::cmac_dhuk` is now a thin SAES adaptor around `cmac_generic`.
- [ ] Remove `hw::otp::read_device_master` / `ensure_device_master` / `burn_device_master` once no caller remains. `MASTER_KEY_ADDR..MASTER_KEY_ADDR+32` becomes reserved.

#### Tier 2 — BHK (Boot Hardware Key, flash-stored, software-inaccessible after boot)

**What it is.** 32 bytes of TRNG output generated once at first-boot provisioning, encrypted under DHUK via SAES-ECB, stored in a dedicated secure-flash page. At every subsequent boot: unwrap with DHUK into STM32 TAMP backup registers, then **lock** `TAMP_S->SECCFGR` so only the SAES peripheral can use it (as a second key selector — `SECURE_AES_KEY_BHK`). Firmware can never read BHK bytes after boot lock.

Trezor references: `core/embed/sec/secret/stm32u5/secret.c:426-442` (`secret_bhk_regenerate` — TRNG fill + flash write), `secret.c:593-612` (`secret_prepare_fw` — TAMP load + lock at boot), `secret.c:177-179` (the lock comment quoted above). Layout: `core/embed/models/T3W1/secret_layout.h:57-58` (`SECRET_BHK_OFFSET=0x2000`, `SECRET_BHK_LEN=0x20`). SAES selector: `secure_aes.c:52` (`SECURE_AES_KEY_BHK`).

**Why BHK in addition to DHUK.** Defense-in-depth across two *independent* SAES key selectors. Compromising DHUK alone (hypothetical SAES glitch, or ST errata disclosing DHUK semantics) leaves BHK-wrapped operations sealed — the attacker would also need to read flash *before* `TAMP_S->SECCFGR` lock completes at boot. Compromising BHK alone (e.g. flash dump of wrapped BHK + offline DHUK-ECB crack) does not unlock DHUK-wrapped master-key slots. Neither alone defeats the user PIN path because that also consumes OTP randomness (tier 3).

Quoted from Trezor `secret.c:593-595`:
> "The BHK is copied to the backup registers, which are accessible by the SAES peripheral. The BHK register is locked, so the BHK can't be accessed by the software."

**Which SE goes under which key.** Current split (TROPIC01 deferred — see CLAUDE.md "Backend" notes; the shipping config is `dual-se` = OPTIGA Trust M + SE050 only):
- DHUK → OPTIGA PBS (current derivation), user-PIN storage-wrap (if we ever add one)
- BHK → SE050 SCP03 enc+mac, SE050 admin PIN
- (TROPIC01 pairing key would join the BHK side if/when TROPIC01 is re-enabled — `secret_keys::tropic01_pairing_key()` exists but the TROPIC01 driver currently uses a hardcoded pairing key and the `tropic01-se` backend isn't built into the shipping target.)

That way a compromise of one selector exposes at most one SE's channel. The Tier-2-A fallback (`derive_into_bhk` with neither `bhk` nor `bhk-hardcoded-master-key` → route through `derive_into` (DHUK)) keeps pre-2B builds running; production builds enable `bhk` to flip to the real BHK selector.

**What's needed — P0 (requires Tier 1 landed first):**

**Phase 2A — host-testable cryptographic primitive (no chip burns).** **LANDED 2026-05-05** (commit `630b32e`). Lands the BHK derivation API + dev-hardcoded BHK fallback so callers can be migrated independently. No silicon TRNG burn, no flash write, no TAMP register lock. Fully reversible — a feature-flag flip + flash erase reverts to pre-Tier-2 state.

- [x] `hw::saes_cmac::cmac_bhk(msg, tag)` — parallel to `cmac_dhuk`, switches `KeySel::Dhuk` → `KeySel::Bhk`. Same `cmac_generic` core in `secure/src/cmac.rs` (no math duplication).
- [x] `hw::secret_keys::derive_into_bhk(label, output)` — second derivation path with three cfg branches: `bhk-hardcoded-master-key` → HKDF over the compile-time test constant `"PQSIGNER-TEST-BHK-DHUK-WRAP-v1!!"` (distinct from the OTP-master test constant so dev-build BHK and DHUK paths produce different outputs); `bhk` (production phase 2B+) → `kdf_cmac_counter_generic` over `KeySel::Bhk`; neither feature → fall through to `derive_into` (DHUK) so callers can be added incrementally without breaking pre-2B builds (defense-in-depth split is degenerate until 2B flips it on).
- [x] Cargo features added: `bhk-hardcoded-master-key` (dev) parallel to `otp-hardcoded-master-key`; `bhk` (production, requires `saes-dhuk`). `bhk-hardcoded-master-key` registered in the production-build `compile_error!` fence in `secure/src/nsc/mod.rs`.
- [x] Host tests: 4 NIST SP 800-38B AES-256-CMAC KATs in `cmac.rs` already validate the `cmac_generic` core that both `cmac_dhuk` and `cmac_bhk` delegate to. 105/105 host tests pass.
- [x] **No caller migration in this phase.** `se050_scp03_*`, `tropic01_pairing_key`, `se050_admin_pin` stay on `derive_into` (DHUK). Migrating them to BHK changes the derived bytes, which would force re-pairing of bench SEs (destructive on already-provisioned chips). Migration is staged as Phase 2C with its own rollout plan + re-pairing step.

**Phase 2B — silicon-side BHK on real hardware.** Code landed 2026-05-05 (commit pending), gated behind the `bhk` feature (OFF by default — `hw/bhk.rs` not compiled, no flash writes). The remaining work is the silicon validation pass: enable `bhk`, run on a bench board with the BOOT0+TAMP+`-tzenreg` recovery procedure ready, confirm per-die BHK uniqueness at RDP1, recover.

- [x] `secure/src/hw/bhk.rs`: first-boot generation (`crate::rng::fill` 32 bytes), DHUK-ECB wrap via `hw::saes::encrypt_ecb_block(KeySel::Dhuk, ...)`, flash write to **bank-1 page 126 (`0x0C0F_C000`)** — the page freed by work-todo #24 (former OPTIGA-PBS seal). Subsequent-boot load: read wrapped bytes → DHUK-ECB unwrap → write 32 plaintext bytes into TAMP `BKP0R..BKP7R` (LE, 8 × u32) → enable `RCC_AHB3ENR.RTCAPBEN` + clear `PWR_DBPCR.DBP` first → set `TAMP_SECCFGR.BHKLOCK`. `provision()` refuses if the page is non-blank (re-provision would invalidate any existing SE pairing). `is_provisioned()` / `is_locked()` diagnostics. `self_test()` (gated `saes-self-test`) for the eventual silicon validation — returns an 8-byte per-die BHK fingerprint analogous to the DHUK one.
- [x] `TAMP_SECCFGR.BHKLOCK` lock sequence: `BHKLOCK = bit 30` (verified against the `stm32u5-0.16.0` PAC `tamp/seccfgr.rs:43-44`; description: "cleared by hardware together with the backup registers following a tamper detection event or when RDP is disabled" → reversible). `SECCFGR` at TAMP offset `0x20`, `BKP0R` at `0x100`, TAMP secure-alias base `0x5600_7C00`.
- [x] Boot wiring: `main.rs` runs `bhk::provision()` (first boot, blank page) + `bhk::load_and_lock()` (every boot) right after `hw::saes::init()`, gated `bhk` + `not(otp-hardcoded-master-key)` + `not(bhk-hardcoded-master-key)` + `not(saes-self-test)`. Under `saes-self-test` + `bhk`, `saes_self_test_and_halt` instead calls `bhk::self_test()` (provision-if-blank → load+lock → `KeySel::Bhk` round-trip → fingerprint). Logs each step via `secure_log!` + UART.
- [x] **Lifecycle validated on real silicon (RDP0), 2026-05-05.** On B-U585I-IOT02A board #1, `make`-built `saes-self-test,bhk,uart-console,ui-oled,boot-pulse` firmware: `[S][bhk] self_test PASS  BHK(fp)=9524309a79a30040`, stable byte-identical across two cold-boot resets (2nd boot correctly skips `provision()` — page 126 already holds the wrapped bytes — and `load_and_lock()` re-unwraps the same bytes). Surfaced + fixed two register bugs along the way: (1) `hw/bhk.rs` had `RCC_AHB3ENR.RTCAPBEN` (no such bit) → corrected to `RCC_APB3ENR@+0xA8` bit 21 (`RTCAPBEN`); `PWR_DBPCR@+0x10` (wrong — that's SVMCR) → corrected to `PWR_DBPR@+0x28` bit 0 (`DBP`). Both verified against the `stm32u5-0.16.0` PAC. (2) `hw/saes.rs` didn't latch the BHK for `KeySel::Bhk` ops — fixed by 8 dummy reads of `TAMP_BKP0R..BKP7R` (secure alias `0x5600_7C00 + 0x100`) before the SAES op, mirroring Trezor's `secure_aes_load_bhk()`; the reads return 0 to the CPU when `BHKLOCK` is set but trigger the SAES to pull the real hardware-visible BHK. Without it, `SR.KEYVALID` never asserts → `KeyInvalid` timeout.
- [ ] Per-die BHK uniqueness at RDP ≥ 1: follows logically from the already-validated per-die DHUK (the BHK is DHUK-ECB-wrapped, so a flash dump of page 126 from board A can't be unwrapped on board B's per-die DHUK). A dedicated RDP1 BHK test would just confirm this — it would need the BHK provisioned *while at* RDP1 (the recovery-heavy flow: erase page 126, step to RDP1, boot → `provision()` wraps with the RDP1 DHUK). Low priority; the security property is established.
- [ ] Integration check: a reflash that preserves OTP also preserves the DHUK-wrapped-BHK on flash (same page across updates). If a firmware update would erase that page, restore-from-wrap fails and the chip falls into the same class of brick as the original OPTIGA bug. Treat the BHK page as **write-once-at-provisioning, read-only from firmware** — no firmware-update path may touch it (page 126 is bank 1; the FW-update region is bank 2 only, so `fw_update` already can't reach it — but add an explicit assertion when the FW-update bank-2 page allowlist is next touched).

**Phase 2C — caller migration. CODE LANDED (2026-05-11).** `secret_keys::se050_scp03_enc_key` / `se050_scp03_mac_key` / `se050_admin_pin` now derive via `derive_into_bhk` (the BHK SAES axis). `optiga_pairing_secret` stays on `derive_into` (DHUK). `tropic01_pairing_key` stays on `derive_into` (DHUK) — TROPIC01 is deferred (the `tropic01-se` backend isn't built into the shipping target; the driver uses a hardcoded pairing key). The call-site flip is **behaviorally inert until `bhk` is enabled**: with `bhk` off (the current default), `derive_into_bhk` falls through to `derive_into`, so the SE050 secrets are identical to pre-2C. Verified clean across default-QEMU, `saes-dhuk`-shipping (bhk off), `bhk` on, and `bhk-hardcoded-master-key` builds; 105/105 host tests pass. Kept the `-v1` label suffix — the label-hygiene rule is about not silently changing the *label*; changing the derivation *root* (DHUK → BHK) is the whole point here, and it's documented. (A version bump was considered for log-unmistakability and rejected as churn.)

Trezor-mirror reference: `core/embed/sec/secret_keys/stm32u5/secret_keys.c` — each per-purpose secret key gets a domain-tagged derivation off either the DHUK or BHK SAES selector; the choice of selector-per-purpose is the defense-in-depth axis. Our `secret_keys::*` functions are the direct parallel — Phase 2C just chose `derive_into_bhk` vs `derive_into` per function.

Cost / sequencing: enabling `bhk` re-keys the SE050 channels — an already-provisioned chip has its SCP03 channel + admin UserID keyed to the *old* (DHUK-derived) secrets, so after `bhk` goes on the firmware computes *new* (BHK-derived) secrets that don't match → the SE050 won't authenticate → re-provision (wipe + re-pair). On bench chips that's the `dual-se-admin-wipe-e2e` / `wipe-for-wizard` flow. On production chips there's no migration — they ship with `bhk` on and BHK-derived secrets from first boot. **Caveat (already in `docs/production-todo.md`):** the BHK lives in mass-erasable flash (page 126), so an RDP regression loses it → SE050 must be re-paired afterward — same posture Trezor accepts for Optiga. At RDP0 the BHK isn't per-die anyway (it's DHUK-ECB-wrapped under the RDP0-constant DHUK), so the real two-axis benefit only materialises at RDP ≥ 1.

**Phase 2C activation — silicon-root validation (NEXT STEP after a context compaction; nothing here is started yet).** The Phase-2C *axis routing* is committed (`aa23f05`) and validated with the dev constants (`dual-se-admin-wipe-e2e + bhk-hardcoded-master-key` PASSED on hardware, 2026-05-11). What's NOT done: a build where the SE050 admin PIN is genuinely `SAES-CMAC(silicon-BHK, …)` and the OPTIGA PBS is genuinely `SAES-CMAC(silicon-DHUK, …)`. The pieces are all there (`hw/bhk.rs` lifecycle silicon-validated at RDP0 → `BHK(fp)=9524309a79a30040`; the `main.rs` boot wiring runs `bhk::provision()` + `bhk::load_and_lock()` when `bhk` is on and `otp-hardcoded-master-key`/`bhk-hardcoded-master-key`/`saes-self-test` are off) — they just haven't been wired into a single buildable recipe and run together. Checklist:

- [ ] **CRITICAL pre-flight (do this BEFORE any silicon flash): confirm the no-OTP-burn path.** A build with `saes-dhuk` + `bhk` + `otp-hardcoded-master-key` OFF must NOT trigger `hw::otp::ensure_device_master()` (which programs OTP on a blank MCU — irreversible). Audit: with `saes-dhuk` on, `secret_keys::derive_into` routes to `derive_into_saes_kdf` (SAES-CMAC DHUK), not the legacy `HKDF(OTP_master, …)` — so `ensure_device_master` shouldn't be called from `secret_keys`. But also check: any boot-time call to `ensure_device_master` in `main.rs`; `hw::huk::derive_device_key` (calls `otp::ensure_device_master`) — is it invoked at boot? `hw::otp::ensure_device_master` callers generally. If ANY path on the boot/provision flow calls it, the build would burn OTP on a bench board (and some bench U5s can't program user OTP at all — see `docs/production-todo.md` "STM32 OTP master-key burn" note). If confirmed clean → proceed. If not → either land an `otp-master-noburn` guard or stay on `otp-hardcoded-master-key` (which keeps the OTP path a constant, but then the DHUK/BHK aren't the silicon HUKs — defeating the test).
- [ ] Add a Makefile recipe — e.g. `dual-se-bhk-e2e` — building `--features dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,saes-dhuk,bhk` (note: NO `otp-hardcoded-master-key`, NO `bhk-hardcoded-master-key`). Same flash + OB + `probe-rs run` shape as `dual-se-admin-wipe-e2e`. (The `e2e-test` flag stays — it's the "not shippable" marker + fixed-mnemonic provider, independent of the key-substitution flags.)
- [ ] Flash + run on bench board #1 (OPTIGA shield + SE050 shield + OLED attached). Expect: boot logs show `[S] SAES initialised (Tier-1 DHUK path)` then `[S] BHK provisioned (first boot)` (first run) / `[S] BHK loaded + BHKLOCK set`, then the `dual-se-admin-wipe-e2e` 8-step roundtrip with the SE050 admin object keyed to the silicon-BHK-derived PIN and the OPTIGA PBS to the silicon-DHUK. Roundtrip PASS = the real-HUK Phase-2C config works.
- [ ] (Optional, low priority) Per-die check: step to RDP1 (BOOT0+TAMP+`-tzenreg` recovery ready), confirm the SE050 admin PIN + OPTIGA PBS change vs RDP0 (per-die HUKs). Follows logically from the already-validated per-die DHUK + the BHK-wrapped-under-DHUK chain — a dedicated test is confirmation, not a gate.
- [ ] Once validated: decide whether `bhk` joins the shipping build profile (parallel to `saes-dhuk`); update the production smoke-gate / `make prod-check` enumeration accordingly.
- [ ] Note in the refurbishment/RMA flow that an RDP regression on a `bhk`-enabled (Phase-2C-active) device requires an SE050 re-pair (the BHK lives in mass-erasable flash page 126 → regression loses it → SE050 SCP03/admin re-key).

(`se050_scp03_enc/mac_key` are still defined-but-never-called — the SE050 driver uses the AN12436 default SCP03 keys (`KEY_VERSION=0x0B`); wiring those through SCP03 PUT KEY is work-todo #20, separate from Phase 2C.)

#### Early-adopt: derive SE050 admin PIN from OTP master (pre-DHUK)

**Status:** **CORE PATH DONE (2026-04-23).** Both `Se050::store_objects` (provisioning) and `Se050::factory_reset_admin` (wipe) now derive the 16-byte admin PIN via `hw::secret_keys::se050_admin_pin()` → HKDF-Expand over the OTP master. The flash page 125 PIN slot is no longer consulted on the production provision/unlock/wipe paths. `dual-se-admin-wipe-e2e` PASSES all 8 steps on real silicon with the new derivation (commits `1bfb572` + `e6b8c2f` + `38982c7`).

**Cleanup DONE (2026-05-11).** The whole pre-v6 page-125 admin-PIN flash mechanism is removed: `hw::flash::write_admin_pin`, `read_admin_pin`, `is_admin_pin_blank`, and `ADMIN_PIN_OFFSET` are all gone. The SE050 admin PIN is re-derived on demand via `secret_keys::se050_admin_pin()` — `SAES-CMAC(DHUK, ...)` on a shipping build, `HKDF(OTP_master, ...)` on the legacy fallback — and never touches flash, so it survives reflashes and flash mass-erase (the property that closes the "lose the flash, lose the pairing" brick class). The `se050-crash-safety-e2e` test's cross-phase admin PIN is its own compile-time literal (`*b"crashsafetypin00"`), used directly in both phases (no flash round-trip). The three e2e pre-clean cascades (`dual_se.rs` `[DUAL-E2E-ADMIN]` + `[DUAL-MULTI]`, `main.rs` `[S][e2e]`) now call `Se050::factory_reset_admin()` (the v6 path → arm wipe flag → admin-auth wipe → conditional page-125 erase) instead of reading a pre-v6 flash PIN; stages (b) user-PIN candidates + (c) unauthenticated sweep stay as fallbacks. Page 125 still holds the wipe-in-progress flag at `WIPE_FLAG_OFFSET=16` (a separate slot from the now-dead QW0). The 2026-04-21 footgun (page-125 erase bricked the bench SE050) is structurally impossible now — nothing reads the page-125 admin-PIN slot. Verified: `dual-se-admin-wipe-e2e` / `dual-se-multi-unlock-e2e` / default-QEMU builds clean, 105/105 host tests pass. Bench re-validation of the e2e pre-clean cascades is the only thing left (the recovery behavior changed from flash-PIN to OTP/DHUK-derived) — low priority since the v6 path is what current chips need anyway.

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

### 27. ~~`bench-key-speed` NS test regression in HEAD~~ — RESOLVED

**Resolved 2026-05-06.** Root cause was build-hygiene, not a code bug. The two observed failure modes (`[NSC] sign_offchain (len=46)` returning `NotInitialized`, and the `u64_div_rem` exception in NS bench init) were both **stale NS veneer addresses** in a manual build flow.

**Mechanism.** Each secure-side build with a different feature set produces a different `target/veneers.o` because the secure binary's veneer thunks are placed at addresses that depend on the surrounding code layout. The NS-side build links against `target/veneers.o` to resolve `extern "C" { fn nsc_sign_userop(...); ... }` declarations to specific veneer addresses.

If the NS ELF is older than the current `veneers.o`, its thunks point to STALE addresses. Calling `nsc_sign_userop` from NS lands at the address that was the userop veneer **at NS build time** — but in the freshly-flashed secure binary, that same address might now be the offchain veneer or the middle of an unrelated function. Result: silent dispatch to the wrong handler.

**Concrete trace.** Verified by comparing `arm-none-eabi-nm target/veneers.o | grep nsc_sign_userop` (`0x0c0673b8`) against the NS ELF's veneer-thunk target (`.word 0x0c0675f9` — Thumb bit included → `0x0c0675f8`). 1088-byte mismatch → calls land 8 entries downstream in the veneer table.

**Fix.** Always rebuild NS with the same `veneers.o` it'll be running against. The Makefile `test-key-speed` target already does this:

```make
rm -f $(NONSECURE_ELF) target/nonsecure/$(TARGET)/release/deps/sphincs_tz_nonsecure-*
$(RUSTFLAGS_VAR)="$(RUSTFLAGS_NONSECURE_HW)" cargo build ... -p sphincs-tz-nonsecure ...
```

The pre-build `rm` of the NS ELF + dep files forces cargo to relink against the current `veneers.o`. **As long as you use `make test-key-speed`, this works.** Manual builds (`cargo build -p sphincs-tz-secure ... && cargo build -p sphincs-tz-nonsecure ...`) need the same `rm`-then-rebuild discipline if the secure side's feature set changed since the last NS build.

**Validation post-fix.** Bench passes cleanly with TAMP IRQ-mode + tamp + e2e-test (commit `f5e6a8a` + fresh NS link):

```
[S] TAMP initialised (IRQ, log-only)
[NS][bench] A) chain=1 first-sign:    9,159 ms
[NS][bench] B-avg) type2-only:        4,001 ms
[NS][bench] C) chain=2 first-sign:   10,282 ms
[NS][bench] === PASS ===
```

Within ±2% of polled-mode baseline. No spurious `[TAMP] irq:` or `[IRQ] unexpected:` lines across the entire bench — IRQ-mode passes through thousands of SAES + RNG operations cleanly.

**Documentation tightening that fell out of this:** any future secure-side feature-flag matrix CI / dev-board run that builds secure separately from NS should treat them as a single build unit (rebuild both, in lockstep). A bare `cargo build -p sphincs-tz-secure` followed by `probe-rs run` on a previously-flashed-NS chip will silently invoke wrong veneers and look like an arbitrary firmware regression. Worth a sentence in `docs/dev-board-setup.md` once that file gets a refresh.

**Second build-hygiene gotcha surfaced 2026-05-06 during tamp-irq soak.** `cargo build -p sphincs-tz-secure --features <new-set>` does NOT always rebuild the secure ELF — Cargo's incremental cache may keep the previous feature set's binary when the only change is a CLI feature flag. Symptom: `cargo build` reports "Finished in 0.06s", the secure ELF stays at the OLD timestamp, and `probe-rs download` flashes the OLD binary. Combined with a fresh NS rebuild (which links against the FRESH `veneers.o`), the chip runs an old secure with new NS thunks → arbitrary handler dispatch failures that look like new-feature regressions but are actually stale builds. Fix: `rm -f target/secure/<target>/release/sphincs-tz-secure target/secure/<target>/release/deps/sphincs_tz_secure-*` before `cargo build -p sphincs-tz-secure` whenever the feature set changes. The `make` targets do this implicitly via the `rm` of the NS ELF triggering a full rebuild graph; bare `cargo build` does not.

---

### 26. TAMP polled → IRQ migration (Trezor-parity latency)

**Status:** Polled-mode landed in commit `aecc1cc` (2026-05-05). IRQ-mode landed behind `tamp-irq` feature in `f5e6a8a` (2026-05-06) + soak-validated 2026-05-06. Default-on flip remains deferred until production-hardening branch (per "When to do this" below).

`secure/src/hw/tamp.rs` currently runs in polled mode: `tamp::init()` arms `TAMP_CR1` (detection) but leaves `TAMP_IER` masked, and `tamp::poll()` from the SysTick handler drains `TAMP_SR` ~1 kHz. Validated on real STM32U585 — no spurious triggers across `make test-key-speed`-shape runs.

**Why polled today, not IRQ.** PQSigner has zero peripheral-IRQ infrastructure today (no PAC crate, no `#[interrupt]` handler scaffold). An unmasked TAMP IRQ would land in cortex-m-rt's WEAK `DefaultHandler` and HardFault. Polling is dev-board-safe; IRQ-mode is a production hardening item.

**Migration path: `DefaultHandler` dispatch (~30 LOC, recommended).**

```rust
// secure/src/main.rs
#[cortex_m_rt::exception]
unsafe fn DefaultHandler(irqn: i16) {
    match irqn {
        #[cfg(all(feature = "stm32u585", feature = "tamp"))]
        2 => hw::tamp::on_tamp_irq(),  // already in tree, gated `_unused`
        _ => panic_unexpected_irq(irqn),
    }
}
```

Plus three lines added to `tamp::init()`: `write_volatile(TAMP_IER, ITAMP_FLAG_MASK); write_volatile(NVIC_ICPR0, 1 << TAMP_IRQN); write_volatile(NVIC_ISER0, 1 << TAMP_IRQN);`. The `tamp::on_tamp_irq()` function is preserved in tree (renamed to `_*_unused` + `#[allow(dead_code)]`) so re-introducing it is a single uncomment.

**Why this matters.** IRQ latency (~hundreds of cycles) beats SysTick polling (~1 ms) by an order of magnitude. Doesn't matter in dev (log-only) but matters in production where the wipe is racing an attacker reading residual-power side-channels off the backup SRAM.

**Why not default-on yet.** Two reasons remaining (the "operational soak" one is satisfied; see below):

1. **DefaultHandler picks up every IRQ source we accidentally unmask, not just TAMP.** Without a firmware-wide audit of "which peripherals have IER bits set right now," that's a footgun. The audit must land in the same diff as the default-on flip.
2. **Production should flip the wipe trigger in the same commit as the default-on flip.** Migrating polled→IRQ while still log-only is half a change; we'd then have to re-validate the trigger surface again when production wipe lands. Bundle them.

**Operational-soak criterion: SATISFIED 2026-05-06.** Test plan was "a few clean `make e2e-hw` + `dual-se-multi-unlock-e2e` runs with no spurious `[TAMP] irq:` or `[IRQ] unexpected:` lines." Results on B-U585I-IOT02A:

| Test | Build features | Spurious IRQ events | Result |
|---|---|---:|---|
| dual-se-multi-unlock-e2e — boot 1/3 | `dual-se-multi-unlock-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key,tamp,tamp-irq` | 0 | 5/5 unlocks PASS |
| dual-se-multi-unlock-e2e — boot 2/3 | (same) | 0 | 5/5 unlocks PASS |
| dual-se-multi-unlock-e2e — boot 3/3 | (same) | 0 | 5/5 unlocks PASS |
| e2e-hw (full unified-sign suite + PIN-lockout brute-force) | `mock-se,debug-log,ui-semihosting,e2e-test,stm32u585,tamp,tamp-irq` | 0 | `=== All scenarios passed! ===` |

Total: **15 unlocks, 1 multi-scenario sign suite, 1 PIN-lockout brute-force test, 0 spurious IRQ events.** TAMP-IRQ passes through thousands of SAES + RNG accesses + CMSE veneer crossings cleanly. `DefaultHandler` dispatch invariant holds (no `[IRQ] unexpected irqn=N` lines).

**Build hygiene gotcha surfaced during validation.** Cargo's incremental build does NOT always rebuild the secure ELF when the secure-side feature set changes via CLI args alone. The symptom is identical to a "tamp-irq regression" — secure ELF is from an older feature set, NS is built fresh against current `veneers.o`, and the chip ends up running a secure binary whose veneer addresses don't match what NS expects. Fix: `rm` the secure ELF + deps directory before each rebuild, not just the NS one. Documented in #27.

**Alternative paths considered + rejected:**
- **Adopt PAC crate (`stm32u5`).** Would let us use `#[cortex_m_rt::interrupt] fn TAMP() { ... }` directly. Rejected: PQSigner has historically refused PAC adoption (raw-register pattern everywhere — see `hw/rcc.rs`, `hw/usb_hw.rs`, `hw/saes.rs`). Architectural drift the codebase actively avoids.
- **Hand-rolled `__INTERRUPTS` array with linker-script trick.** ~100 LOC of boilerplate. Fragile. Skip unless cortex-m-rt drops `DefaultHandler` support.

**When to do this:** during the production-hardening branch, alongside the parallel `production-todo.md` item ("TAMP escalation: log-only → `trigger_lockout_wipe()`"). Both flips MUST land together so review can verify the trigger surface end-to-end.

**Files to change for default-flip (when):** Remove `tamp-irq` feature gate and make IRQ-mode unconditional under `tamp`. The `DefaultHandler` fn in `secure/src/main.rs` and `enable_tamp_irq()` + `on_tamp_irq()` in `secure/src/hw/tamp.rs` are already in tree (commit `f5e6a8a`); the default-flip is a Cargo.toml + cfg-gate cleanup, not a behavioral change.

---

## Modularity refactor — baseline (2026-04-30)

State snapshot taken at the start of the modularity refactor described in
`/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`. Numbers
recorded here so subsequent phases can detect regressions.

### Per-crate Rust line counts

| Crate | LOC | files |
|---|---:|---:|
| shared | 2 550 | 3 |
| secure | 43 981 | 134 |
| nonsecure | 4 607 | 14 |
| bip39 | 2 453 | 2 |
| fwmeasure | 171 | 1 |
| sphincs-c10 | 1 616 | 8 |
| fw-manifest | 921 | 1 |
| fwsign | 1 507 | 11 |
| fsbl | 534 | 8 |
| bls12_381_pka | 14 314 | 19 |
| dbgen | 2 745 | 8 |
| zk-test | 308 | 1 |
| **total** | **~75 700** | **210** |

### Cross-cutting metrics

| Metric | Value |
|---|---:|
| Feature flags declared in `secure/Cargo.toml` | **50** |
| Total `#[cfg(feature = "...")]` blocks in `secure/src/` | **291** |
| `cfg` density in `secure/src/se050/mod.rs` | 50 |
| `cfg` density in `secure/src/main.rs` | 37 |
| `cfg` density in `secure/src/optiga/mod.rs` | 36 |
| `cfg` density in `secure/src/nsc/mod.rs` | 25 |
| `cmd_sign_userop.rs` total lines | 1 241 |
| `secure/src/hw/*.rs` driver count | 22 |
| `shared/src/lib.rs` total lines | 1 484 |

### Solidity

| Contract | LOC |
|---|---:|
| `PQSmartWallet.sol` | 435 |
| `PQSmartWalletFactory.sol` | 138 |
| `PQMultiOwnable.sol` | 263 |
| `verifiers/SPHINCsC10Asm.sol` | 202 |
| **total** | **1 038** |

### Boundaries-of-truth (constants duplicated across Rust ↔ Solidity)

These identifiers exist on **both** sides today and are therefore drift-prone
until Phase 4's codegen lands:

- `C10_SIG_LEN = 4008`
- `MAX_BOOTSTRAP_USES = 65_536`, `MAX_SLOT_USES = 65_536`
- `MAX_OFFCHAIN_GAP = 5`
- `OWNER_BYTES_LEN = 64`
- `SIG_WRAPPER_LEN = 4128`
- `FACTORY_ADD_SLOT_DOMAIN`
- `EXECUTE_SELECTOR = 0x14443c57`, `EXECUTE_BATCH_SELECTOR = 0x7a389933`
- `SAFE_DOMAIN_TYPEHASH`, `SAFE_TX_TYPEHASH`
- `COWSWAP_EIP712_SENTINEL`, `GPV2_SETTLEMENT_ADDRESS`,
  `SET_PRE_SIGNATURE_SELECTOR`

### Targets after refactor

After Phase 11 lands the same metrics should read:

- Feature flags: **25–35** (5 axes + ~10 sub-features). Declared in axes,
  not free-form names.
- `#[cfg(feature = "...")]` outside `platform.rs` + `compile_error!` fences
  + sub-feature gates: **0**.
- `secure/src/hw/*.rs` count: **0** (moved to `hal-stm32u5/`).
- `cmd_sign_userop.rs` total lines: ≤ 200 (the rest is split across 8
  submodules under `secure/src/nsc/sign_userop/`).
- Solidity ↔ Rust shared constants exist in **one** place (Rust) and
  Solidity gets them via `cargo xtask gen-solidity-constants`.

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
| 2026-04-16 | all-C10 slot cutover (phases 1-7) | Collapsed the multi-signer architecture to a single the legacy FORS+C signing path behind one `CMD_SIGN_USEROP`. Flash-backed `SlotState` persists `next_q` across power cycles (phase 1). Added SPHINCS+C11 master key derivation matching the SPHINCs- reference byte-for-byte (phase 2, 7 unit tests + BIP-39 vector). Unified Type 1 / Type 2 state machine emits a `[type1_len \| t1 \| type2_len \| t2]` bundle the companion submits as up to two EntryPoint v0.9 UserOps (phase 3). USB layer cut from 14 INS codes + v1 Keycard Shell compat to 7 native v2 instructions; webhid tool rewritten for the unified bundle (phase 4). `PQSmartWallet` + `PQSmartWalletFactory` contracts replace the multi-signer wallet; 14 new Foundry tests pass; EntryPoint v0.9 via `account-abstraction` submodule update to `releases/v0.9`; CREATE2 salt = `keccak256(masterPkSeed \|\| masterPkRoot)` (phase 5). ERC-20 metadata bundle + Groth16 ZK clear-sign preserved as optional trailer sections on the unified sign payload, verifying against the firmware-embedded Merkle-rooted DBs just like before. Fixed a latent sphincs-c7 bug where `extract_ht_index` used C7 parameters (24-bit mask at bit 128) instead of C11 (16-bit mask at bit 143); self-verification now passes keygen → sign → verify roundtrip. |
| 2026-04-16 | OPTIGA Trust M silicon bring-up | TRUST-M-SHIELD on B-U585I-IOT02A via breadboard wired to I2C1. Rewrote `secure/src/optiga/apdu.rs` for correct wire format (positional InData not TLV, CMD bytes with 0x80 CLEAR_LAST_ERROR flag, access-condition tags AutoRef=0x23/Conf=0x20, data-type tag 0xE8, AUTHREF type 0x31), added `get_random` + `hmac_verify` primitives. Switched `authenticate_and_read` to proper HMAC challenge-response protocol (chip-side verify via DecryptSym CMD 0x95 + tag 0x43). Added admin factory-reset via shielded-connection Conf(E140) path — avoids SE050-style permanent lockout by making every user OID's Change AC `Auto(F1D0) OR Conf(E140)`. Physical fixes validated on real hardware: CTL→3V3 jumper required, 50µs guard time between register-write/read transactions required, ReSynch is fire-and-forget. OpenApplication now returns valid response. Saved bring-up quirks to memory (`project_optiga_bringup.md`). |
| 2026-04-17 | C10 bootstrap cutover | Replaced SPHINCS+C11 bootstrap identity with **SPHINCS+C10** (`h=18 d=2 a=11 k=13 w=8 l=43 target_sum=205 sig=4008`, 4073-byte Type 1 wire frame). New `sphincs-c10/` crate with correct portable `extract_ht_index` (4-byte load for H=18 vs 3-byte for H=16) replaces the old `sphincs-c7/` directory; firmware/crypto/sign-state-machine/shared wire formats all ported. New on-chain `SPHINCsC10Asm.sol` SHA-256-precompile verifier (subtree_h=9, 9-level Merkle auth, target_sum=205) replaces `SPHINCsC11Asm.sol`. Added per-chain `bootstrapUses` counter in `PQOwnable` storage (ERC-7201 slot+1), `MAX_BOOTSTRAP_USES = 65_536` cap enforced in `PQSmartWallet._validateSignature` pre-check and bumped via `_bumpBootstrapUses(cap)` after successful Type 1. Added `BootstrapKeyUsed(newCount)` event and `bootstrapUses()` view. Factory `createAccount` salt still `sha256(masterPkSeed || masterPkRoot)`, so the C11→C10 change re-bases every wallet address for a given seed — acceptable since no live deployments exist. 5 new `SPHINCsC10AsmTest` Foundry tests driven by a Rust-generated `c10_test_vectors.json` (keygen + sign + self-verify runs under `cargo test -p sphincs-c10 --test gen_test_vectors --release`), 4 new bootstrap-counter tests in `PQSmartWalletTest` covering success bump, failure no-bump, cap-rejects-overflow, and post-exhaustion Type 2 still works. All 33 Foundry tests pass. SHA-256 stays throughout; no keccak256 regressions. |
| 2026-04-16 | OPTIGA OID recovery + provisioning workaround | Added SetObjectProtected (CMD 0x83) to the Rust driver — `protected_update_start/continue/final` + chunking helper in `optiga/apdu.rs`, plus new `optiga/reset.rs` (CBOR-signed manifest blob + iter helper) and `optiga/reset_pin.rs` (PE0 = Arduino D5 GPIO toggle for the chip's RST line). Generates 16 manifests via the Infineon `protected_update_data_set` tool (now buildable on Linux via cloned mbedtls 2.28.8 + CRLF/include-separator/buffer-overflow patches) signed by Infineon's sample EC P-256 key, embedded via `include_bytes!`. New `optiga-reset-oids` feature + `make flash-hw-optiga-reset` target. **Validated 16/16 OIDs reset on real silicon.** Same `hard_reset_and_reinit` (RST low ~10 ms + OpenApp) wired into `store_objects` between every provisioning step — works around the chip's "after 2 SetData ops the next APDU never gets a RESP_READY" wedge. End-to-end wallet provisioning succeeds on both OPTIGA and SE050 halves. Shielded Connection handshake remains the next blocker — see `docs/optiga-bringup-status.md` for the open list. |
| 2026-04-21 | #24 Phase-A Shielded Connection + PIN unlock end-to-end | Five commits: (1) `fa06a4f` drop unneeded LcsO=op bump from `ensure_shield`. (2) `43b6937` fix the MasterFinished handshake rejection — PRF seed was `random_M‖random_S` but reference uses only `random_S`, MasterFinished plaintext must be `random_S‖slave_seq`, and header/nonce/AAD seq must be `slave_sequence_number` from SlaveHello (not zero). (3) `a1ac0cd` provisioning-through-shield fixes: `send_command` now uses `transceive_prl` (PRESENCE_BIT) so records reach the PRL layer; `hard_reset_and_reinit` clears `shield.active`; `store_objects` threads `ensure_shield` after PBS write and after every hard-reset. (4) `635e018` skip `set_metadata`+`lock_oid` on OIDs already at LcsO=Operational (one-way ratchet blocker from pre-0b412b4 runs). (5) `3d34101` PIN unlock via AUTHREF HMAC — `PARAM_HMAC_MODE` was 0x02 but must be `OPTIGA_HMAC_SHA_256 = 0x20` per `optiga_lib_common.h:213`; added `generate_auth_code` APDU (`GetRandom` with `store_in_session=TRUE`) required for `hmac_verify` to find a valid session. Full flow reaches `hmac_verify OK → Unlocked: entropy + VKs cached → gateway pre-unlocked, ready for tests` on real B-U585I-IOT02A + OPTIGA Trust M V3. New `flash-hw-optiga-unlock-test` + `flash-hw-optiga-shield-handshake-only` Makefile targets. |
| 2026-04-17 | All-C10 slot cutover + stateless firmware | Per-slot signing key is now SPHINCS+C10 instead of the legacy FORS+C — one primitive, one verifier, no variable-length Type 2. The firmware is **stateless** for slot selection: the companion supplies `(chain_id, slot_index, flags)` on every `CMD_SIGN_USEROP`; `FLAG_REGISTER_SLOT` (bit 30 of flags) tells the firmware when to emit a Type 1 ahead of Type 2. Deleted `legacy-fosc/` crate (root + workspace refs), `secure/src/nsc/legacy_flash.rs` (flash pages 123-124 no longer used for slot state), `secure/src/nsc/cmd_get_slot_info.rs` (CMD 17 retired), `contracts/.../LegacyForsCVerifier.sol` and `ILegacyVerifier.sol`. `PQSmartWallet` gains a second on-chain counter `slotUses[slotKey]` capped at `MAX_SLOT_USES = 65_536`, bumped by `_bumpSlotUses` inside the Type 2 path; `PQOwnable` extends its ERC-7201 struct with the mapping and a `SlotKeyUsed(slotKey, newCount)` event. Single `c10Verifier` now handles both Type 1 and Type 2 (same stateless SHA-256-precompile verifier, different `(pk_seed, pk_root)` per call). Slot C10 keys are derived deterministically from `(slot_master_entropy, slot_index)` via new domain tags `"slot_c10_sk_seed"` / `"slot_c10_pk_seed"` and cached in SRAM across the unlock session only. New `secure/src/crypto.rs::derive_c10_slot_keypair_with_progress` helper mirrors the master path; `SecureState::SLOT_CACHE: Option<CachedSlot>` replaces the FORS+C slot cache. Wire formats: Type 2 is now fixed at 4073 bytes (C10 sig); `SIG_TYPE2_LEN = 4073`; `MAX_SIGN_RESPONSE_LEN = 8246`; removed `FORSC_BODY_LEGACY`, `SIG_MIN/MAX_LEGACY`, `Q_MAX_LEGACY`, `LEGACY_WRAPPER_*`, `NscStatus::SlotExhausted`, `CMD_GET_SLOT_CACHE_INFO`, `CMD_SIGN_SLOT_LEGACY`, `CMD_REGISTER_SLOT_CACHE`, `INS_V2_*LEGACY*`. Master C10 derivation unchanged → every seed still maps to the same CREATE2 wallet address. CLAUDE.md invariants updated (old #6 `next_q`-before-flash removed; #7 now covers both use caps; new #8 for the stateless firmware property). Builds clean for `thumbv8m.main-none-eabi` across all feature combos (`mock-se`, `e2e-test`, `bench-key-speed + stm32u585`, `usb`). 4-scenario QEMU e2e runner exercises register/repeat/rotate/second-chain; bench exercises cold first-sign / N cached Type 2 / second-chain cached-slot. |
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
| 2026-04-24 | #7 Tier 1 — SAES driver (hw/saes.rs) landed + silicon-validated same-board | New `secure/src/hw/saes.rs` under the `saes-dhuk` feature (OFF by default). Init sequence: RCC.CR SHSION (bit 14) + SHSIRDY poll, RCC.AHB2RSTR1 SAESRST pulse (bit 20, offset **0x64** not 0x60 — AHB1RSTR is at 0x60), RCC.AHB2ENR1 SAESEN (bit 20), SAES.SR.BUSY wait, SAES.ISR.RNGEIF check. AES-256 ECB encrypt/decrypt primitive under `KeySel::{Software, Dhuk, Bhk, DhukXorBhk}`, with KEYSEL raw values `{0b000, 0b001, 0b010, 0b100}` matching the STM32 HAL `CRYP_KEYSEL_*` macros byte-for-byte. Decrypt path runs MODE=01 key-derivation pass before MODE=10 block decrypt (HAL pattern). Register offsets + bit positions cross-checked against **two** authoritative sources: (1) `stm32u5-0.16.0` PAC crate (machine-generated from ST's SVD — `saes/cr.rs`, `saes/sr.rs`, `rcc.rs`) and (2) STM32CubeU5 `stm32u585xx.h` CMSIS header + `stm32u5xx_hal_cryp.c` HAL flow. Hardware CMAC mode intentionally NOT used — the `cmac` crate will wrap the ECB primitive in software when `secret_keys::derive_into` flips over in task #31. Boot-time self-test under the new `saes-self-test` feature: software-key round-trip, DHUK-vs-SW domain separation, DHUK round-trip, 8-byte DHUK fingerprint log, clean `SYS_EXIT`. `make saes-self-test-hw` flash + run. `saes-self-test` added to the production-build `compile_error!` fence in `secure/src/nsc/mod.rs`. Pure-additive — does NOT change any existing call site; no OTP burn, no flash writes, no TAMP access, no SE I/O. **Silicon bring-up surfaced two real bugs the host compile couldn't catch**: (a) first `make saes-self-test-hw` returned `KeyInvalid` because the DHUK `SR.KEYVALID` check was instantaneous, racing the silicon's key pull-in delay — fix: spin-wait with `TIMEOUT_ITERS` ceiling, mirrors HAL `CRYP_AES_Encrypt`'s `while HAL_IS_BIT_CLR(SR, CRYP_FLAG_KEYVALID)` pattern. (b) Second run hit `CcfTimeout` on step-3 DHUK decrypt because the decrypt-mode KD pre-pass fired BEFORE waiting for KEYVALID — fix: restructure run_ecb_block so KEYVALID wait precedes KD, MODE toggles happen with EN kept set across the KD→DECRYPT switch (dropping EN between phases would lose the derived last-round key). Post-fix: **PASS** two runs on the same B-U585I-IOT02A bench board, DHUK fingerprint byte-identical (`11 7d 82 2a 62 a5 08 30` → `11 7d 82 2a 62 a5 08 30`). Per-die uniqueness check still pending (needs a second board). All compile-matrix variants pass: default QEMU, `saes-dhuk` alone, `saes-self-test` full. |
| 2026-04-23 | SE050 admin-wipe — OTP-derived PIN + per-object diagnostics + 6-canary selftest | Four bugs fixed in the admin-wipe path. Dominant root cause (not on advisor's list — surfaced by diagnostic instrumentation): `Se050::factory_reset_admin` trait impl was reading admin PIN from flash page 125, but provisioning writes the chip's admin UserID with an OTP-derived PIN (`hw::secret_keys::se050_admin_pin()`). Page 125's PIN slot is deliberately blank on v6 OTP-derived provisionings, so `is_admin_pin_blank()=true` routed every wipe into `iterative_wipe(None, None)` — unauth sweep can't touch admin-gated user objects, wallet seed survived every supposed wipe. Fix: trait impl now re-derives via `se050_admin_pin()`, matching provisioning. Bug 1 (work-todo #27): `admin_factory_reset` silently swallowed every `delete_object_authed` error via `let _ = ...`; returned `Ok` on total failure. Fix: per-object Ok/Err(status) logging + post-`check_exists` + return Err if any user object survived. Bug 2 (#28): `store_objects` skip-if-exists would silently inherit stale policy shape from prior firmware. Fix: under admin mode (admin_pin.is_some()), any object surviving the pre-write stale sweep is a hard Err (SW=0x6986) — loud signal replaces silent inheritance. Bug 3 (#29): `policy_roundtrip_selftest` only covered 2-canary shape while production's `admin_factory_reset` does 6 deletes under one session. Fix: extended selftest to write 1 UserID + 5 data canaries (0x7B10_00B0..B5), admin-delete all 6 in one session with per-object logging + post-check each — catches session-invalidation-after-Nth-delete regressions that the 2-canary shape couldn't see. `admin_factory_reset` USER_OBJS cleanup list expanded to cover the full 0x7B10_00B0..B5 canary range for stranded-selftest recovery. Validation: `dual-se-admin-wipe-e2e` PASSES all 8 steps on silicon (step 7 "both chips unprovisioned post-wipe OK" now green — was the long-standing failing test). Selftest trace shows 6/6 canary deletes Ok under one session, proving no session-invalidation quirk. Benign expected-failure: canary 0x6985 on `CANARY_{DATA,USERID}_CLEANUP` during admin_factory_reset because selftest's own cleanup already deleted them; post-check confirms they're actually gone. Commits: `1bfb572` (Bug 1 + OTP-derivation), `e6b8c2f` (Bug 2), `38982c7` (Bug 3). |
| 2026-04-24 | #7 Tier 1 — `hw::secret_keys::derive_into` flipped to SAES-CMAC(DHUK, …) under `saes-dhuk` (task #31) | `derive_into` now dispatches on three cfg paths: (a) `otp-hardcoded-master-key` ON → unchanged HKDF-Expand-SHA256 over the ASCII test constant (byte-for-byte bench compat preserved); (b) `otp-hardcoded` OFF + `saes-dhuk` ON → simplified SP 800-108-style CMAC-based counter KDF driven by `SAES-CMAC(DHUK, label ‖ counter)`; (c) neither feature → legacy HKDF-over-OTP-master path retained so existing hw builds don't regress until they opt into `saes-dhuk`. Pulled the CMAC algorithm out of the SAES-DHUK backend into a new pure-logic module `secure/src/cmac.rs` — `cmac_generic<E, F>(msg, aes_encrypt, tag)` takes an AES encrypt closure, and `kdf_cmac_counter_generic<E, F>(label, scratch, aes_encrypt, output)` wraps it with the counter/packing logic. `hw::saes_cmac::cmac_dhuk` and `hw::secret_keys::derive_into_saes_kdf` both collapse to thin SAES adaptors. Host tests (`cargo test -p sphincs-tz-secure --bins`): 4 × NIST SP 800-38B Appendix D.3 AES-256-CMAC KATs (empty / 16B / 40B / 64B — covers empty-message K2 pad, complete-block K1 path, partial-block K2 path), 2 × `double_l` sanity checks, 9 × KDF layout/packing/bounds tests that pin down the exact `label ‖ counter` byte placement with counter=1 start + multi-block concatenation + 255-block upper bound — 15/15 PASS. Full host suite 86/86 PASS. Five ARM compile-matrix variants build clean (`saes-self-test`, `saes-dhuk` alone, legacy default-less, `saes-dhuk + otp-hardcoded`, `saes-self-test + uart-console`). Docstring truthful about SP 800-108 — explicitly says "simplified SP 800-108-style" rather than claiming full compliance (no `0x00 ‖ Context ‖ L_be` suffix, safe here because each label is fixed-purpose and produces a fixed-length output). Counter-wrap off-by-one fixed — `n_blocks ≤ 255` capped up front; the in-loop wrap bump skips when no more output is needed so the `counter==0 ⇒ Err` guard is now a pure `debug_assert`. Silicon re-run pending — `make saes-self-test-hw` still green from the prior `hw/saes.rs` landing; the CMAC KDF path will be exercised end-to-end under `dual-se-*-e2e` after commit. |
| 2026-04-24 | Trezor audit landed — `docs/trezor-comparison.md` + 5 dev-board-safe adoptions | New `docs/trezor-comparison.md` (298-line comparative audit of PQSigner vs Trezor T3W1/STM32U5A9 + Optiga Trust M, organised by adoption priority). Five dev-board-safe, reversible code deltas landed in parallel: (1) **FI helpers** (`secure/src/fi.rs`) — ported Trezor's `wait_random()` `i+j==wait` glitch sentinel (`core/embed/sec/random_delays/stm32/random_delays.c:186-202`) + a `check_true` double-eval helper with `OK_SENTINEL`/`FAIL_SENTINEL` hamming-distant constants. No-op under `e2e-test`. Wired into: `crypto::c10_sign_verified_with_progress` (single-verify + FI-gated boolean check, same cost as before), `cmd_sign_userop.rs` external slot-sign double-verify (`wait_random` between the two verifies, sentinel gate), `hw::flash::pin_attempts_bump` (post-bump delay + double-readback via `check_true`), `dual_se::unlock` master-secret cross-verify (two `ct_eq` compares gated through `check_true`). 4 new host tests. (2) **proptest fuzz harness** (`secure/src/fuzz_props.rs`) — 7 property tests asserting no panic on arbitrary `&[u8]` for `tx::eip1559::parse`, `tx::rlp::decode_item`, `erc20::bundle::verify_erc20_bundle`, `erc20::calldata::parse_erc20_calldata`, `names::verify_name_bundle`, `aa::userop::parse_header`, + a composed-pipeline test. PQSigner's narrower answer to Trezor's libFuzzer harnesses (`crypto/fuzzer/`); cargo-fuzz setup would need a `[lib]` target on `sphincs-tz-secure` and is deferred. 71/71 host tests PASS. (3) **TAMP driver** (`secure/src/hw/tamp.rs`) — feature-gated `tamp` flag. Register-level port of Trezor's `core/embed/sec/tamper/stm32u5/tamper.c:100-207` with two deliberate deltas: log-only IRQ handler (WFE halt, no `trigger_lockout_wipe` — prevents probe-rs false-trigger bench-chip brick), and LSI-only RTC clock init (no LSE dependency). Enables ITAMP1/2/3/5/6/7/8/9/11/12/13 + CR3=0 confirmed mode. Not wired into `main()` yet — `init()` + `on_tamp_irq()` are available for opt-in. (4) **UI screenshot-hash regression harness** (`secure/src/ui/capture.rs` + `tools/ui_fixture.py`) — `ui-capture` feature emits `[UI-FP] <frame-idx> <sha256>` per `Display::flush()` over `secure_log!`. Both semihosting and OLED backends hashed. Host tool has `--regenerate` + `--check` subcommands matching Trezor's `tests/ui_tests/common.py:131-132` fixture model. Smoke-tested end-to-end with fake input. (5) **consumption_mask PWM** (`secure/src/hw/consumption_mask.rs`) — simplified (no-DMA) port of Trezor's `core/embed/sec/consumption_mask/stm32u5/consumption_mask.c`. TIM2 CH1 PWM on PA5 at 10 kHz, duty randomised via `randomize()` called from caller's periodic path. Feature-gated `consumption-mask`; full GPDMA linked-list port deferred. All changes pure-additive — default feature set produces byte-identical firmware to pre-audit commit. Full matrix builds pass (`mock-se`, `stm32u585+dual-se+usb+ui-oled`, + all new features stacked). Host tests 71/71 PASS. QEMU e2e validation in flight at commit time — log-only tamp + feature-off consumption_mask + ui-capture guarantee no boot-path behavioural change without the respective feature flag. See `docs/trezor-comparison.md §§1.1, 2.3–2.6, 3.1`. |
| 2026-04-26 | Safe-multisig `approveHash` clear-sign trailer (`safe_v1`) | Mirror of the CowSwap v3 clear-sign architecture, but without Groth16. The `approveHash(bytes32)` selector puts the EIP-712 digest *in the calldata*, so the firmware brings the canonical SafeTx (281 B) plus the raw inner-call data (≤ 4 KB) on-device in a new optional trailer and natively re-keccaks both chains: `keccak(raw_data) == canonical.data_hash` and `safeTxHash(canonical) == inner_data[4..36]`. Plus chain pinning (`canonical.chain_id == userop.chain_id`), Safe-address pinning (`canonical.safe_address == userop.to`), and a v1 DelegateCall refusal (`operation == 1` rejected outright). Symmetric downgrade gate to CoW: if `inner_data` looks like `approveHash`, the trailer is mandatory — without it the sign aborts with `"Safe needs trailer"` so a hostile NS cannot strip it and coerce blind-signing. The renderer (`secure/src/tx/display/safe_display.rs`) shows three Safe-level header pages (banner+chain / safe address / SafeTx nonce + Op + inner-kind hint) followed by inner-tx pages dispatched on `raw_data` shape — empty-call / plain-ETH / ERC-20 known / ERC-20 unknown / blind-sign — and a confirm prompt. Reuses every existing display primitive (`write_addr_full_or_name`, `write_token_amount_two_rows`, `write_calldata_hash_rows`, etc.). Inner ERC-20 metadata only applies when the bundle's contract address matches `canonical.to`, so a Safe call to USDC carries USDC metadata and not the Safe contract's. New files: `secure/src/tx/eip712/safe/{mod.rs,verify.rs,test_vectors.rs}`, `secure/src/tx/display/safe_display.rs`. Wire format: `shared/src/lib.rs` adds `APPROVE_HASH_SELECTOR` (0xd4d9bdcd), `APPROVE_HASH_CALLDATA_LEN` (36), `SAFE_DOMAIN_TYPEHASH` + `SAFE_TX_TYPEHASH` (Safe v1.3.0+), `SAFE_V1_CANONICAL_LEN` (281), `SAFE_V1_RAW_DATA_MAX` (= MAX_TX_LEN), `SAFE_V1_PAYLOAD_MAX`, and 12 `SAFE_OFF_*` field offsets. SNAP_LEN bumped by 4 380 B; total ~16 KB, well inside the U585's 256 KB SRAM. Tests: 14 new host unit tests cover both typehash preimage round-trips + happy path + 9 cross-check failure modes (wrong selector / wrong calldata len / chain mismatch / safe-address mismatch / DelegateCall reject / data_hash mismatch / safeTxHash mismatch / truncated bundle / oversized raw_data_len / empty raw_data with non-zero data_hash / decoder rejects op>1). Full host suite 100/100 PASS. New e2e Scenario 5 in `nonsecure/src/e2e_test.rs` builds a synthetic Safe `transfer(0xRECIPIENT, 250 USDC)` and signs it through QEMU end-to-end — OLED renders `"Approve Safe TX / SafeTx Nonce: 17 / Op: Call / Inner: ERC-20?"` and the firmware emits a 4128-byte Type 2 SLH-DSA wrapper. New `sha3` dep on the NS side for assembling the trailer (companion-side equivalent). Targets Safe v1.3.0+; older Safes self-police via cross-check failure (different domain separator → recomputed `safeTxHash` won't match calldata). Out of scope for v1: DelegateCall (refused), `multiSend` recursive decoding (renders via blind-sign fallback), companion-side trailer assembler in `~/Documents/pq1-companion`. Scenario 6 (PIN-lockout brute-force) shows a pre-existing FAIL on master, unrelated to this work — confirmed by stashed-baseline rerun. |
| 2026-04-28 | EIP-1271 off-chain signing + on-chain combined-cap (CMD_SIGN_OFFCHAIN / CMD_OFFCHAIN_STATUS / `executeWithOffchainCount`) | Adds the wallet-side EIP-1271 surface (`isValidSignature`) via Solady `ERC1271` + `EIP712` mixins (nested EIP-712 replay protection, ERC-6492 counterfactual unwrap) and a per-slot durable off-chain sig counter that ensures the slot key never exceeds its SPHINCS+C10 hypertree usage budget across a seed-restore. **On-chain:** new `offchainSigCount[ownerIndex]` mapping in `PQMultiOwnable` ERC-7201 storage; `_setOffchainSigCount(ownerIndex, newCount, slotUsesNow, cap)` enforces monotonic + the *combined* invariant `slotUses + offchainSigCount <= MAX_SLOT_USES = 65_536`. `PQSmartWallet.execute` / `executeBatch` are replaced by `executeWithOffchainCount(ownerIndex, newOffchainCount, target, value, data)` (and the batch variant) — every Type 2 UserOp now publishes the firmware's local off-chain count durably, so a fresh-from-seed firmware reads on-chain `offchainSigCount[i]` and reasons correctly about remaining budget. Type 2 `validateUserOp` enforces the combined cap pre-bump. EIP-1271 path is `view`-only (never bumps a counter), wraps the input hash via `replaySafeHash` (so a sig captured against wallet A on chain X cannot replay against wallet B / chain Y), and forbids the bootstrap key (`ownerIndex == 0`). `_isSlotAllowedSelector` updated. **Firmware:** new flash-resident counter on bank-1 page 123 — log-structured journal with two entry types (`offchain_count`, `last_userop_count`) keyed on `slot_key = sha256(account_index ‖ chain_id ‖ slot_index)[..8]`, 16 B per QW, in-place compaction when the page fills. Wear estimate ~6 500 erases at 50 active slots × 65 536 sigs each — within STM32U5 datasheet 10 000-cycle floor. New `secure/src/offchain_state.rs` facade routes to flash on `stm32u585`/`pka-accel` and to a 128-slot SRAM mock on QEMU/host. New gateway commands `CMD_SIGN_OFFCHAIN = 16` (45 B in: account/chain/slot/hash; 4016 B out: count + 4008 B sig) and `CMD_OFFCHAIN_STATUS = 17` (read local + last_userop + registered). `cmd_sign_offchain` enforces three refusals: unregistered slot (post-restore), gap > `MAX_OFFCHAIN_GAP = 5`, combined cap. Verify-before-release FI guard mirrors `cmd_sign_userop`. `cmd_sign_userop` modified: builds calldata as `executeWithOffchainCount(ownerIndex, local_offchain_count, ...)`, writes the registered-flag on Type 1 (forces post-restore Type 1 + Type 2 retry instead of resuming an old slot), snapshots `last_userop_count` post-sign, prepends 8-byte `new_offchain_count` to the response. **Wire format:** new selector `0x14443c57` for `executeWithOffchainCount(uint256,uint256,address,uint256,bytes)`. Test vectors regenerated; `SIG_TYPE2_LEN = 4128` unchanged. Three new `NscStatus` variants (`OffchainSlotUnregistered = 17`, `OffchainGapExceeded = 18`, `OffchainCapExceeded = 19`) mapped to `SW_CONDITIONS_NOT_SATISFIED`. **Tests:** 6 new Foundry tests (combined cap, monotonic, idempotent, EIP-1271 happy path, bootstrap rejection, no counter bumps, cross-wallet domain separation); 43/43 forge PASS, 157/157 secure host tests PASS, 5 QEMU e2e sign scenarios PASS with the new wire framing (scenario 6 PIN-lockout pre-existing FAIL, unchanged). **CLAUDE.md** invariant #8 amended to permit the off-chain counter as a bounded exception, new invariant #9 codifies the combined-cap + recovery semantics, "Do not reintroduce per-signature flash state" rule narrowed accordingly. Companion-side dapp integration (`replaySafeHash` wrapping, response decode) is out of scope and tracked separately. |
| 2026-04-30 | Modularity refactor — Phases 5.1-5.4 + 6 PR 1 + 8 PR 1 + 10 PR A/B/D | Picked up the deferred phases from the earlier 2026-04-30 row in this log. **Phase 5 PR 5.1** — new `tx-core/` workspace member (`pqsigner-tx-core`, `no_std`, deps: `pqsigner-proto` + `sha3`) carrying `eip1559`, `hash`, `rlp`. `secure/src/tx/{eip1559,hash,rlp}.rs` deleted; `secure/src/tx/mod.rs` shimmed via `pub use pqsigner_tx_core::*;`. **Phase 5 PR 5.2** — new `aa/` workspace member (`pqsigner-aa`, deps: `pqsigner-proto` + `pqsigner-tx-core` + `sha2` + `sha3`) carrying `userop` + `eip1271`. Resolved gotcha §3.5 — local `EXECUTE_SELECTOR = [0x14, 0x44, 0x3c, 0x57]` deleted, now `pub use pqsigner_proto::EXECUTE_SELECTOR;`. `secure/src/aa/mod.rs` becomes `pub use pqsigner_aa::{eip1271, userop};`. **Phase 5 PR 5.3** — new `domain/` workspace member (`pqsigner-domain`, deps: `pqsigner-proto`, `pqsigner-bip39`, `sphincs-c10`, `aes-gcm`, `sha2`, `hmac`, `zeroize`). All pure-logic key derivation + AES-GCM wrap moved out of `secure/src/crypto.rs`; the secure-side file becomes a re-export shim that keeps only the FI-bound `c10_sign_verified*` (uses `crate::fi::wait_random` / `check_true`) and the `WalletStore`-bound `provision_from_mnemonic` / `store_macd_encrypted` (use `crate::secure_element::*`). **Phase 5 PR 5.4 (partial)** — new `tx/` workspace member (`pqsigner-tx`, deps: `pqsigner-proto` + `pqsigner-tx-core` + `sphincs-tz-shared` for `db_format` + `sha2`) carrying `erc20/{bundle,calldata,dispatch,merkle,mod}`, `names/{bundle,resolver,mod}`, `selectors/{bundle,mod}`. The `verify_*_bundle` functions take a `root: &[u8; 32]` parameter so they're reusable by future host-side reference signers; `secure/src/{erc20,names,selectors}/mod.rs` shims pass the embedded `db_roots::*` constants. `tx/typed_call/` and `tx/eip712/{cowswap,safe}/` stay in `secure/` for now — their fixture-roundtrip tests reference `secure/data/` paths via `CARGO_MANIFEST_DIR`. **Phase 6 PR 1** — new `hal/` workspace member (`pqsigner-hal`, no deps, trait-only crate) defining `Rng` / `Sha256` / `Saes` / `Flash` / `Otp` / `BootState` / `Tamp` / `ConsumptionMask` / `I2cBus` / `SpiBus` / `Buttons` / `Uart` plus the aggregate `Platform` and a `BootStage` enum. PRs 2–4 (move `secure/src/hw/*` into `hal-stm32u5/`, build `hal-mock/`, wire a `Platform` adapter into `secure/src/main.rs`) deferred — no impl moves yet, the trait crate is the architectural specification new code can lean on. **Phase 8 PR 1** — `secure/Cargo.toml` `[features]` now exposes the five-axis aliases (`platform-*`, `secure-element-*`, `ui-mode-*`, `mode-*`, `accel-*`). Each is a thin alias over the existing legacy flag so Makefile recipes keep working unchanged. PR 2 (flip every Makefile recipe + delete legacy aliases + add cross-axis `compile_error!`s) deferred. **Phase 10 PR A** — `pub trait Ui { fn clear, draw_line, flush, splash }` added to `secure/src/ui/mod.rs` with per-backend `impl Ui for Display { ... }` blocks that delegate to the existing inherent methods (no recursion — Rust's method resolution prefers inherent over trait for `self.method()` syntax). Future code can take `&mut impl Ui` instead of being implicitly tied to whichever backend the active feature gate selects. **Phase 10 PR B** — new `secure/src/nsc/ns_ptr.rs` defines `NsPtr<T>` / `ReadPtr<T>` / `WritePtr<T>` typestate. `validate_read(len)` / `validate_write(len)` produce the proof types — forgetting to validate becomes a type error. Adoption is incremental (next-write-the-cmd_*.rs migration); full thread-through is sequenced under Phase 7. **Phase 10 PR D** — `MockSecureElement` gains `simulate_glitch()` (one-shot fault injection on the next `mac_and_destroy` call) plus a host test suite covering: provisioning populates slots; correct PIN unlocks + resets counter; wrong PINs decrement remaining; **10-wrong-PIN brick path** (entropy slot erased, subsequent unlocks fail); glitch propagation through `pin::verify_pin`. Six new tests, all PASS. **Deferred** to a follow-up run: Phase 6 PRs 2–4 (HAL impl moves), Phase 7 (`cfg → trait` migration), Phase 8 PR 2 (Makefile flip + legacy delete + cross-axis fences), Phase 9 (decompose `cmd_sign_userop.rs` 1241→~150 LOC), Phase 10 PR C (phased boot — depends on Phase 6 PRs 2-4), the rest of Phase 11 (testing-matrix doc + how-tos + `xtask doc-check`), Phase 12 (optional domain-tag rename). Existing CLAUDE.md "Key File Map" updated with a leading note pointing at the six new pqsigner-* crates and the new `nsc/ns_ptr.rs` + `ui::Ui` trait. **Gates**: 173/173 host tests (was 167; +6 mock-SE realism), 49/49 Solidity, drift-check passes; canonical hardware-bringup `cargo check -p sphincs-tz-secure --target thumbv8m.main-none-eabi --features dual-se,ui-oled,stm32u585,debug-log,e2e-test,otp-hardcoded-master-key` green. |
| 2026-04-30 | Modularity refactor — Phases 0 + 2 + 3 + 4 + Phase 10 PR E | Audit identified the codebase as having the right *boundaries* (S↔NS split, dual-SE entropy, `ISPHINCSVerifier`) but the wrong *interfaces between them* (`cfg`-only polymorphism, no Rust↔Solidity IDL, no Rust CI). Approved plan at `/home/markus/.claude/plans/ok-make-a-plan-logical-lobster.md`. **Phase 0** — baseline snapshot (LOC per crate, 50 feature flags, 291 `cfg(feature)` blocks across `secure/src/`, file-level metrics) committed under "Modularity refactor — baseline" header in this doc. **Phase 1 (Rust CI matrix) NOT landed** — authored as `.github/workflows/rust.yml` and removed at user request before commit; shared CI infrastructure (third-party actions trust, runner-minute spend, root-level workflow surface) is a different category of change and needs its own deliberate decision. Re-author when ready. **Phase 2** — `secure/src/nsc/mod.rs` `compile_error!` fence expanded: added `debug-log` + `ui-capture` to forbidden-in-prod list (were missing), added pairwise UI-axis exclusivity (`ui-semihosting`/`ui-oled`/`ui-noop`), added pairwise SE-axis exclusivity (`mock-se`/`tropic01-se` × `se050`/`optiga-trust-m`), added "must select one" gates for hardware/QEMU builds. `secure/Cargo.toml` flipped `default = []` so manual `cargo build -p secure` now fails informatively at the fence instead of silently producing a dev-mode build. `make test-unit` updated to pass explicit `--no-default-features --features mock-se,debug-log,ui-semihosting`. Negative tests verify each fence fires on the wrong combo. **Phase 3** — new `proto/` workspace member as `pqsigner-proto` crate (zero-dep, `no_std`, single source of truth for every protocol-level constant + enum + wire size that crosses TrustZone, on-chain, or USB boundaries). `shared/src/lib.rs` rewritten as a thin `pub use pqsigner_proto::*;` re-export shim — 67 existing `sphincs_tz_shared::*` import sites compile unchanged. `shared/Cargo.toml` forwards `stm32u585` feature to `pqsigner-proto`. Added `MAX_BOOTSTRAP_USES`, `OWNER_BYTES_LEN`, `FACTORY_ADD_SLOT_DOMAIN`, and `EXECUTE_SELECTOR` constants to proto (these previously lived only on the Solidity side or in per-file consts). **Phase 4** — new `xtask/` workspace member (`pqsigner-xtask`) with `gen-solidity-constants` subcommand that renders `contracts/smart-wallet/src/generated/PqsignerProto.sol` from `pqsigner-proto`'s public constants. Solidity contracts updated to import from the generated library: `PQSmartWallet.sol` uses `PqsignerProto.{C10_SIG_LEN, MAX_BOOTSTRAP_USES, MAX_SLOT_USES}`; `PQMultiOwnable.sol` uses `PqsignerProto.OWNER_BYTES_LEN`; `PQSmartWalletFactory.sol` uses `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN`. `--check` mode emits the rendered library to stdout — discipline gate for now (run locally before commit); CI automation deferred with Phase 1. **Phase 10 PR E** — `proto/src/lib.rs` now declares `CMD_BASE_*` range markers (CORE/WALLET/OFFCHAIN/FW/BATCH/TEST) and a `const _: () = { ... }` compile-time CMD-collision check that pairwise-asserts every `CMD_*` value is unique — verified to fire correctly on a synthetic duplicate. **Drive-by fix**: `zk-test/src/main.rs` had a stale path `../../secure/src/zk/poseidon_constants.rs` (file moved to `generated/` subdir on master) — now points at `../../secure/src/zk/generated/poseidon_constants.rs`. **All gates green**: 167/167 host tests, 49/49 Solidity tests, drift-check passes. Phases 1 (CI), 5 (extract `pqsigner-aa`/`-tx`/`-domain`), 6 (`pqsigner-hal` traits), 7 (`cfg → trait` migration), 8 (95→5 feature axes), 9 (decompose `cmd_sign_userop.rs`), Phase 10 PRs A/B/C/D, and Phase 11 (doc cleanup) tracked in the plan + `docs/handoff-modularity-refactor.md`; deferred to focused follow-up sessions. |
| 2026-05-05 | #7 Tier 1 per-die DHUK — empirically validated across two B-U585I-IOT02A boards | Closes the long-deferred Tier-1 security claim. Captured fingerprints from `hw::saes::self_test`'s 8-byte DHUK round-trip output: board #1 (ST-LINK SN `0029…3838`) RDP0 = `117d822a62a50830`, RDP1 = `ea86dbc4586953a6`; board #2 (ST-LINK SN `004F…3838`) RDP0 = `117d822a62a50830` (matches — ST's substituted constant), RDP1 = `002202686b06dcf6` (distinct from board #1). Empirically falsifies the alternative "DHUK is a global ST-controlled constant at all RDPs". Path took 11 step-to-RDP1-and-recover cycles across both chips. At RDP1+TZEN=1+no-OEM-keys, SWD halt is denied (`DEV_TARGET_NOT_HALTED`), UART (PA9) is silent, and a discretionary GPIO toggle on PE13 is silent — but I2C1+OLED works, so the fingerprint surfaced via `Display::draw_line` at line 3 of the SSD1306. Diagnostic infrastructure preserved in-tree behind feature flags: `hw::boot_pulse` (PE13/D13 GPIO bisection) + OLED stage prints. Recovery dance: BOOT0=HIGH + TAMP_IN8/PE4↔TAMP_OUT8/PE5 wire + USART bootloader `-tzenreg` (board #1) / USB DFU `-tzenreg` (board #2 — board ships with a JP3 layout that latched into DFU mode rather than USART boot; needed `port=USB1` + sudo for udev). 11/11 successful recoveries across both chips. Commits: `21a3cfc` (Tier-1 KDF flip + NIST KATs), `bc2b364` (SAES driver landed), `fb30d10` (per-die validation board #1), `2feac35` (per-die confirmation board #2). |
| 2026-05-05 | #7 Tier 2 BHK Phase 2A — host-testable cryptographic primitive | Lands the BHK derivation infrastructure with no chip burns. New `hw::saes_cmac::cmac_bhk(msg, tag)` (parallel to `cmac_dhuk`, drives `KeySel::Bhk` instead of DHUK; both share the same `cmac_generic` core in `secure/src/cmac.rs` so the existing 4 NIST SP 800-38B AES-256-CMAC KATs validate both paths). New `hw::secret_keys::derive_into_bhk` with three cfg branches: `bhk-hardcoded-master-key` → HKDF over compile-time test constant `"PQSIGNER-TEST-BHK-DHUK-WRAP-v1!!"` (distinct from OTP-master test constant so dev-build BHK and DHUK paths produce different outputs — preserves defense-in-depth shape under dev); `bhk` (production phase 2B+) → `kdf_cmac_counter_generic` over `KeySel::Bhk`; neither → fall through to `derive_into` (DHUK) so callers can be added incrementally without breaking pre-2B builds. Two new Cargo features (`bhk-hardcoded-master-key` dev, `bhk` production); `bhk-hardcoded-master-key` registered in the production-build `compile_error!` fence in `secure/src/nsc/mod.rs`. **No silicon writes**: no TRNG burn, no flash write, no TAMP register lock — all of those are Phase 2B. **No caller migration**: `se050_scp03_*`, `tropic01_pairing_key`, `se050_admin_pin` stay on DHUK so bench chips don't need re-pairing — that's Phase 2C with its own rollout plan. Compiled clean across three new cfg combos (bhk-hardcoded alone, bhk alone, neither) on the saes-dhuk + dual-se feature axis; 105/105 host tests pass. Fully reversible — feature-flag flip + flash erase reverts to pre-Phase-2A state. Commit: `630b32e`. |
| 2026-05-06 | Trezor-audit modules end-to-end on silicon — TAMP polled + IRQ, consumption_mask, build-hygiene gotchas | Three Trezor-audit modules (TAMP, consumption_mask, ui-capture) had landed feature-gated in `8705fa5` (2026-04-24) but were never wired into `main()`. This arc activates them on real STM32U585 + validates each. **TAMP polled-mode** (`aecc1cc`): `tamp::init()` arms LSI/RTC + TAMP_CR1 detection, `tamp::poll()` from SysTick drains TAMP_SR @ 1 kHz. Polled because PQSigner has no peripheral-IRQ scaffolding (no PAC); arming TAMP_IER without a handler routes to cortex-m-rt's WEAK fallback → HardFault. Validated on `make test-key-speed` shape: `[S] TAMP initialised (polled, log-only)`, `=== PASS ===`, 0 spurious `[TAMP] poll:` lines across 30+s runtime. **consumption_mask** (`6b55502`): `init()` configures TIM2 CH1 PWM on PA5, `randomize()` from SysTick re-randomises duty cycle. Original `randomize()` called `rng::byte()` 2× per tick — at 1 kHz SysTick that meant 2000 RNG entries/sec, and `hw/rng.rs` emits a `secure_log!("[S] rng::fill entry: ...")` line per call → semihosting BKPT storm choked the firmware. Refactored to xorshift32 PRNG seeded once from TRNG at boot (4 byte reads observed in log; period 2³²-1 with uniform output is ample for power-mask use; Trezor's own implementation uses a DRBG also not crypto-strength for this purpose). **`tamp-irq` feature** (`f5e6a8a`): polled→IRQ migration via `DefaultHandler(irqn: i16)` exception-fn dispatch in `main.rs` (no PAC needed) + `enable_tamp_irq()` arming TAMP_IER + NVIC.ISER0 bit 2. IRQ handler maintains same log-only semantics as polled (read SR → log → write-1-clear → return); production wipe-flip is deferred to hardening branch alongside firmware-wide IER audit. Latency drops from ~1ms (polled) to ~hundreds-of-cycles (IRQ). **Operational soak SATISFIED** (`a2200fe`): `dual-se-multi-unlock-e2e` × 3 cold reboots = 15 unlocks, all PASS, 0 spurious IRQ; `e2e-hw` full unified-sign suite + PIN-lockout brute-force PASS, 0 spurious IRQ. TAMP-IRQ default-on flip remains deferred to production-hardening branch per architectural-bundling commitment. **Build-hygiene gotchas surfaced + documented in #27** (`a3c655b`, `8cd39d5`): (a) NS-side ELF must be `rm`-then-rebuilt against current `target/veneers.o` whenever secure-side feature set changes (CMSE veneer addresses are layout-dependent → stale NS thunks land in wrong handlers); (b) `cargo build -p sphincs-tz-secure --features <new-set>` does NOT always rebuild — incremental cache may keep previous artifact. Both gotchas falsely manifested as "code regressions" before being identified as build-hygiene. The `make` targets do this correctly via NS `rm` triggering full rebuild; bare `cargo build` flows need extra care. Files: `secure/src/hw/{tamp,consumption_mask}.rs` (modules), `secure/src/main.rs` (boot wiring + DefaultHandler), `secure/Cargo.toml` (`tamp`, `tamp-irq`, `consumption-mask` features), `docs/work-todo.md` (#26 #27 closed), `docs/production-todo.md` (TAMP escalation + test-key-speed release-gate + reference timings). All work reversible — register state only, no OTP / LcsO / WRP / RDP. Commits: `aecc1cc` → `6b55502` → `a3c655b` → `f5e6a8a` → `8cd39d5` → `a2200fe`. |
| 2026-05-11 | Negative-security E2E — admin PIN cannot extract user-PIN-gated secrets | Falsifiable hardware test backing the claim that a DHUK leak (or post-Phase-2C BHK leak) does **not** drain funds: even an attacker with the SE050 admin PIN cannot read half_E, because the chip enforces the two-entry `TAG_POLICY` (user → `READ\|WRITE\|DELETE`, admin → `DELETE` only) in silicon, not in the driver. New `Se050::run_admin_extract_attempt()` on isolated OID range `0x7B0B_xxxx` (clear of production `0x7B10_xxxx`, admin-wipe `0x7B09`, crash-safety `0x7B0A`, and all retired ranges per the version-history comment in `se050/mod.rs:23-50`): provisions admin UserID + user UserID + 32-B sentinel data object → (3) user-auth READ must match sentinel byte-for-byte (test-setup sanity, else `Status(0xDEA{D,E,F})` bail) → (4) admin-auth READ must be refused (success here returns `Status(0xBAD0)` = "admin extracted user-gated secret" — the security-violation signal, with a `sentinel leaked: true/false` log so a partial-data leak doesn't hide as `success` in the result code) → (5) same admin session DELETEs all three objects (rules out the false-positive "admin auth was bogus, that's why read failed" — the chip must accept admin for DELETE but deny for READ) → (6) chip empty. New `se050-admin-extract-attempt-e2e` feature in `secure/Cargo.toml`; new boot hook in `secure/src/main.rs` between the existing `se050-admin-wipe-e2e` and `dual-se-admin-wipe-e2e` hooks; new Makefile target `se050-admin-extract-attempt-e2e` (uses `e2e-test,otp-hardcoded-master-key` like `optiga-admin-wipe-e2e`, satisfying the `compile_error!` fence in `secure/src/nsc/mod.rs`). **Validated on B-U585I-IOT02A board #1** (ST-LINK SN `0029…3838`) 2026-05-11: step 4 returned `SW=0x6986` ("security status not satisfied" — exactly the right ISO-7816 refusal code; not a transport error, not "object missing", but the SE secure OS walking the policy entries and finding no `ALLOW_READ` on the admin entry), step 5 returned `SW=0x9000` × 3 (deletes succeeded). Trace ends: `[E2E-EXTRACT] PASS: admin can DELETE but NOT READ user-PIN-gated secrets`. Operational implication: an attacker with the admin PIN can **brick** a stolen wallet (DoS) but not **extract** funds — the user-PIN gate still holds, with 1-in-10^6 attempts capped at 10 by silicon. CI should run this on any commit touching `secure/src/se050/apdu.rs` so an accidental `AR_ALLOW_READ` added to `apdu::build_policy:357` fails the build loudly. **Incidental finding**: `make se050-admin-wipe-e2e` (the existing target) is now stale — the fence was tightened to require `e2e-test` after the target was written, so the old flag list `se050-admin-wipe-e2e,ui-noop,stm32u585,debug-log` no longer compiles. The new target uses the working `optiga-admin-wipe-e2e`-style flag list; fixing the wipe target is a separate one-line job. **Scope caveat**: this covers SE050 only. OPTIGA half_O (gated by `Auto(F1D0)` AuthRef, where E140/PBS authenticates the channel but does not satisfy the read AC) uses a different mechanism with the same property and is not yet covered by an analogous E2E — open follow-up. Files: `secure/src/se050/mod.rs`, `secure/Cargo.toml`, `secure/src/main.rs`, `Makefile`, `docs/production-security.md` (added "Empirically validated: SE PIN gate survives a DHUK/BHK leak" subsection). |
| 2026-05-11 | Verity formal-verification port — initial skeleton (Part A) + handoff for C10 verifier (Part B) | Lifts CLAUDE.md invariants #6 (immutable bootstrap → same address on every chain) and #7 (monotonic per-chain caps) from "enforced by Solidity `require` + Foundry unit tests" to "stated as machine-checked Lean theorems". Plan: `/home/markus/.claude/plans/ok-implement-the-smart-cached-matsumoto.md`. **Part A** — new `contracts/verity/` Lean 4 project pinned to [Verity v0.1.0](https://github.com/lfglabs-dev/verity) (Lean 4.22.0). Ports `PQMultiOwnable.sol` (storage + 5 writers), `PQSmartWalletFactory.sol` (salt + addSlot0Digest), and `PQSmartWallet.sol` (validateUserOp dispatch + executeWithOffchainCount + isValidSignature). 13 theorems stated in `PQSigner/Theorems.lean`; #4 (`removeOwnerAtIndex_zero_reverts`), #7 (`salt_chain_independent`), and #8 (`createAccount_idempotent`) close definitionally (`rfl`/`rw`); the remaining 10 are `sorry`-stubbed pending Step 0 spike. **Step 0 prerequisites** (3-5 day time-box): P1 ERC-7201 namespaced storage, P2 ABI-decode of `(uint256, bytes)` SignatureWrapper, P3 external `call` with frame-separation axiom — P3 is the most likely show-stopper for v0.1.0; if it fails, the hybrid pivot ships Verity-verified storage + factory and keeps `validateUserOp` in Solidity (still gives 10 of 13 theorems including all the #6/#7 coverage). C10 verifier modelled as opaque oracle; trust boundary documented in `contracts/verity/TRUST_ASSUMPTIONS.md` (inherits Verity's 3-axiom list, adds C10 oracle + Solady `LibClone` + EntryPoint v0.6 + firmware wire format). Differential testing strategy: parameterise existing Foundry tests over `(implementation, factory)`, run twice (Solidity vs Verity build), compare return-data/events/storage/revert bytes (NOT gas — Verity's Yul has different access patterns and gas will legitimately diverge). **Part B** — `docs/handoff-verity-c10-verifier.md` for the `SPHINCsC10Asm.sol` (202-line hand-tuned Yul) Verity port. Deferred to multi-quarter follow-up because the verifier needs ~170-400 SHA-256 staticcalls per verify + branchless Merkle swap + 3-bit base-8 digit unpack + custom ADRS bit-layout, none of which are in v0.1.0's 635-line core EDSL fragment. Phased plan: Phase 0 upstream EDSL extensions (precompile.sha256, calldata.read, bits.{shl,shr,and}, memory.scratch) → Phases 1-7 port `sphincs-c10/` Rust ref impl module-by-module → final theorem `verify_byte_equivalent_to_rust`. Pre-condition: Part A merged and stable + Verity v0.2.x with Phase 0 landed. Estimated effort: 6-12 person-months. **What this PR doesn't do**: run `lake build` (toolchain not yet installed in this branch — that's the Step 0 spike). Files: `contracts/verity/{README.md,TRUST_ASSUMPTIONS.md,lakefile.lean,lean-toolchain,Makefile,PQSigner/Common.lean,PQSigner/PQMultiOwnable.lean,PQSigner/PQSmartWalletFactory.lean,PQSigner/PQSmartWallet.lean,PQSigner/Theorems.lean}`, `docs/handoff-verity-c10-verifier.md`. |
