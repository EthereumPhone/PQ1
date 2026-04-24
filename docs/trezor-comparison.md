# Trezor Firmware → PQSigner OS: Adoption Audit

Date: 2026-04-24
Scope: `/home/nicola/repos/trezor-firmware` (monorepo, all models) vs `/home/nicola/repos/PQSigner_OS`
Primary architectural twin: **T3W1 ("Trezor Safe 7") — STM32U5A9 + Optiga Trust M** — same MCU family, same SE chip, same TrustZone-M substrate.

## TL;DR

Trezor has shipped three hardware generations on ARMv8-M + Optiga Trust M. Their firmware carries ~7 years of post-mortem scar tissue that PQSigner can inherit without paying the same tuition. The highest-signal findings are:

1. **PQSigner's current GTZC1_TZSC=0 "everything NS" regression has a direct, verified Trezor fix** — adopt their per-peripheral S-allowlist.
2. **Counter-gated SE authorization**, **OTP-derived PBS**, **MCU pre-commit PIN counter**, and **domain-separated secret_keys via HKDF-Expand** are all Trezor patterns PQSigner already tracks or has landed. These findings validate existing `work-todo.md` items #4/#24 and `hw/secret_keys.rs`.
3. **Genuine gaps not yet tracked:** prodtest factory firmware, screenshot-hash UI regression, libFuzzer corpus for APDU+NSC, vendor-header-hash OTP lock, multi-source TAMP enable list, glitch-sentinel `wait_random`, richer OTP layout (batch/SN/vendor-lock/manufacturing-lock).
4. **Morale/validation:** `MODEL_BOARDLOADER_PQ_KEYS` at `core/embed/models/T3W1/model_T3W1.h:48-51` shows Trezor is wiring PQ signature verification into their boardloader — PQSigner's PQ-only stance is not niche.

Trezor is **classical-crypto-first with a PQ overlay coming**; PQSigner is PQ-only. Most value is in *patterns* (boot chain, storage shape, fault-injection countermeasures, test harnesses) and *concrete register/metadata values* — not primitives.

---

## Section 1 — Must fix before shipping

### 1.1 TZSC peripheral allowlist (fixes CRIT-4 regression)

**Gap:** `secure/src/sau.rs` currently clears `GTZC1_TZSC_SECCFGR{1,2,3} = 0` — all AHB1/AHB2/APB peripherals non-secure. `CLAUDE.md` Development Posture already flags this.

**Trezor's fix (`core/embed/sys/trustzone/stm32u5/trustzone.c:510-544`):** default-NS baseline, then explicitly mark crypto/security peripherals SEC+PRIV:
```
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_ALL, NSEC | PRIV);  // baseline
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_RNG,     SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_SAES,    SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_IWDG,    SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_HASH,    SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_RAMCFG,  SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_WWDG,    SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_ICACHE_REG,  SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_DCACHE1_REG, SEC | PRIV);
HAL_GTZC_TZSC_ConfigPeriphAttributes(GTZC_PERIPH_DCACHE2_REG, SEC | PRIV);
for (int i = 0; i < 512; i++) NVIC_SetTargetState(i);  // all IRQs NS by default
```

**Action for PQSigner:** Rewrite `sau.rs` → SBAR/TZSC sequence to mirror this allowlist. Keep USB OTG FS, I2C3 (OLED), UART, user-button GPIO as NS. Add `NVIC_SetTargetState` loop so only explicitly-re-targeted IRQs are secure. Verify SE I2C bus (Optiga + SE050) is SEC — Trezor treats I2C as user-space because they trust the shielded channel to protect the wire; PQSigner should make the same call explicitly rather than by omission.

### 1.2 Vendor-header OTP lock before first firmware install

**Gap:** PQSigner's FSBL reads `vendor_pubkey.rs` compiled-in. There is no OTP-anchored binding preventing a re-flashed FSBL from substituting a different vendor key.

**Trezor (`core/embed/models/T3W1/otp_layout.h:6` + `sec/image/image.c`):** `FLASH_OTP_BLOCK_VENDOR_HEADER_LOCK` holds a 32-byte hash pin. The bootloader refuses firmware whose vendor header hash diverges. Because OTP is one-way, this is durable across RDP regression and board-level reflash attacks.

**Action:** Add a `FLASH_OTP_BLOCK_VENDOR_PK_HASH` block. FSBL computes `SHA-256(vendor_pubkey_bytes)`, compares against the OTP block on every boot; reject on mismatch; refuse to boot. On factory line, `fwsign` seals the OTP block irrevocably before `RDP-2`. This closes the "substitute vendor key + reflash FSBL" path.

---

## Section 2 — High-value gaps PQSigner does not track yet

### 2.1 `prodtest` factory firmware (`core/embed/projects/prodtest/`)

Trezor's prodtest is a separate, signed, UART-CRC-framed command shell with ~300 commands (`prodtest_optiga_pair`, `prodtest_otp_batch_write`, LED/touch/BLE/SD self-tests, one-shot OTP burns). It is the *only* image that can write the MANUFACTURING_LOCK OTP block.

**Why PQSigner needs an equivalent:**
- The current bench-chip brick (`docs/optiga-brick-postmortem.md`) happened because **provisioning ran mixed with normal boot**. A prodtest separation would have failed-closed on "pair with Optiga before locking the E140 LcsO".
- PQSigner has no clean path to write SN / batch / vendor-pk-hash / manufacturing-lock OTP blocks.
- The `--execute` gate pattern (`core/embed/projects/prodtest/cmd/*.c`) is the right shape: dry-run-by-default for destructive ops.

**Action:** Add a `prodtest/` project that shares the NSC infrastructure but links a different `main.rs` with an explicit factory command set. Gate behind `prodtest` feature flag; CI must enforce it never ships on release firmware.

### 2.2 Optiga brick-prevention invariant: handshake-before-lock

**Finding:** Trezor's prodtest pairs Optiga via `prodtest_optiga_pair()` (`core/embed/projects/prodtest/cmd/prodtest_optiga.c:107-158`) and only *after a successful handshake* calls `prodtest_optiga_lock()` (line 169-246) to set LcsO=Operational on E140. If the handshake fails, lock is never executed and the chip stays provisionable.

**Relevance:** PQSigner's bench-chip brick (`project_optiga_brick.md`) is the exact scenario Trezor prevents by construction. The fix tracked in work-todo #24 (Trezor-style OTP-derived PBS) is correct — add the **"verify Shielded Connection round-trip succeeds before E140 lock"** gate as an explicit prodtest step.

### 2.3 Screenshot-hash UI regression tests

**Gap:** PQSigner has no UI regression coverage. Any OLED render change can silently break confirmation screens.

**Trezor (`tests/ui_tests/common.py:131-132` + `fixtures.json`):** each test emits framebuffer bytes → `SHA-256(Image.tobytes())`; fixture stores hash per `[model][group][test_name]`. `client.debug.reseed(0)` locks RNG so screens are deterministic.

**Action:** Add a Rust-side harness that dumps the SSD1306 GDDRAM bytes to a file per "step" in `make e2e` runs, SHA-256s them, compares to `tests/ui_fixtures.json`. First run regenerates; subsequent runs fail on diff with an `update_fixtures.py`-style knob. ~200 LOC effort for a production-critical safety net.

### 2.4 libFuzzer corpus for APDU parser + NSC validation

**Gap:** PQSigner's NSC pointer validation (`nsc/ptr_validate.rs`) and APDU v2 parser (`nonsecure/src/usb/commands.rs`) are the primary attack surfaces from NS world. Neither has any fuzz coverage.

**Trezor (`crypto/fuzzer/`):** libFuzzer harnesses for BIP32, base58, ECDSA, SHA256. Build: `FUZZER=1 make fuzzer`. No APDU/USB protocol fuzzer on their side either, but the C harness shape is the template.

**Action:** Build a cargo-fuzz target against a feature-gated `parse_cmd_sign_userop_input(&[u8])` entrypoint. Seed corpus from `tests/` existing fixtures. Continuous fuzz on every PR. This is the cheapest delta-to-security on the whole list.

### 2.5 Multi-source TAMP enable list (verified on U5)

**Gap:** PQSigner's tamper handling is placeholder per CLAUDE.md invariant 4 + `docs/HARDENING.md`.

**Trezor (`core/embed/sec/tamper/stm32u5/tamper.c:140-166`):** concrete `TAMP->CR1` bitmask enables ITAMP1 (backup-domain voltage), ITAMP2 (temperature), ITAMP3 (LSE clock CSS), ITAMP5 (RTC overflow), ITAMP6 (JTAG/SWD when RDP>0), ITAMP7/12/13 (ADC watchdogs), ITAMP8 (monotonic counter overflow), ITAMP9 (**crypto peripheral fault — SAES/AES/PKA/TRNG**), ITAMP11 (IWDG reset + tamper flag). `TAMP->CR3 = 0` puts all tampers in "confirmed" mode → secrets erased on any trigger. `TAMP_FLTCR` filter: 8-cycle pre-charge + 4-sample debounce + RTCCLK/256 (128 Hz) sampling for external inputs.

**Action:** Port this register initialization verbatim to a `secure/src/hw/tamp.rs` module. Wire `TAMP_IRQHandler` to `trigger_lockout_wipe()`. ITAMP9 alone closes an entire fault-injection class (SAES/PKA glitches).

### 2.6 `wait_random()` glitch sentinel (fault-injection hardening)

**Gap:** PQSigner's HARDENING TODO lists "random delays" as unimplemented.

**Trezor (`core/embed/sec/random_delays/stm32/random_delays.c:186-202`) — verified:**
```c
void wait_random(void) {
  int wait = drbg_random8();
  volatile int i = 0, j = wait;
  while (i < wait) {
    if (i + j != wait) error_shutdown("(glitch)");
    ++i; --j;
  }
  if (i != wait || j != 0) error_shutdown("(glitch)");
}
```
The double-invariant `i + j == wait` under a `volatile` pair catches single-bit glitches mid-loop, not just at entry/exit. Pair with `systimer`-driven periodic RDI reseeded from RNG every 1000 calls (line 140-179).

**Action:** Port to a `no_std` Rust helper with `core::ptr::{read_volatile, write_volatile}`. Inject into every critical-decision site: PIN compare, C10 verify-before-release, master-key zeroize completion, OTP write path.

### 2.7 Richer OTP layout

**Gap:** PQSigner OTP currently holds only rollback fuses (`hw/otp.rs`).

**Trezor (`core/embed/models/T3W1/otp_layout.h`):**
```c
FLASH_OTP_BLOCK_BATCH                = 0  // manufacturing batch
FLASH_OTP_BLOCK_BOOTLOADER_VERSION   = 1  // monoctr for bootloader
FLASH_OTP_BLOCK_VENDOR_HEADER_LOCK   = 2  // see 1.2
FLASH_OTP_BLOCK_RANDOMNESS           = 3  // per-device salt for PBKDF2
FLASH_OTP_BLOCK_DEVICE_VARIANT       = 4
FLASH_OTP_BLOCK_FIRMWARE_VERSION     = 5  // monoctr for firmware
FLASH_OTP_BLOCK_DEVICE_SN            = 6
FLASH_OTP_BLOCK_DEVICE_VARIANT_REWORK= 7
FLASH_OTP_BLOCK_MANUFACTURING_LOCK   = 8  // irreversible "provisioning done"
```

**Action:** Extend `hw/otp.rs` with explicit blocks for: DEVICE_SN (for host-visible serial), RANDOMNESS (mix into `hw/secret_keys.rs` HKDF as an additional domain separator so cross-device flash dumps can't be cross-decrypted), VENDOR_HEADER_LOCK (see 1.2), MANUFACTURING_LOCK (one-way gate that rejects any further OTP writes post-factory, defeats bench re-provisioning).

### 2.8 Monotonic-counter on SECRET area (alternative to fuse budget)

**Finding:** Trezor's `monoctr` (`core/embed/sec/monoctr/stm32u5/monoctr.c:59-92`) uses a *unary* counter in a SECRET flash region: `monoctr_write(value)` writes `value` zeroed 16-byte chunks at `OFFSET + i*16`. Read counts non-`0xFF` chunks. Idempotent: `value == current` is a no-op; `value < current` is rejected.

**PQSigner current:** 1024-bit OTP budget (32×32 fuses) — one-way hardware burn.

**Trade-off:** Trezor's approach is revocable with a flash erase of the SECRET region (not exposed to firmware) and survives power-loss mid-write because each chunk is atomic. PQSigner's OTP budget is simpler and harder to override, at the cost of a finite ceiling.

**Verdict: KEEP CURRENT — note the alternative.** OTP fuses are the stronger invariant for a rollback counter; Trezor's scheme is a workaround for boards that don't have an OTP budget. Don't switch; document the trade-off.

---

## Section 3 — Hardening patterns worth porting

### 3.1 consumption_mask PWM (power side-channel)

`core/embed/sec/consumption_mask/` drives TIM2 with DMA-fed random values onto a GPIO (typically a no-connect pin), creating a power-draw mask during crypto operations. Cheap: one timer + DMA + RNG. Recommended for signature operations (C10 keygen is 7 s — a long side-channel window).

### 3.2 MPU region banking (APP vs PRIV modes)

`core/embed/sys/mpu/stm32u5/mpu.c:43-134, 554-557` — 5 fixed regions + 3 banked. `MPU_MODE_APP_SAES` grants unprivileged SAES + TAMPER access during narrow crypto windows, then snaps back. Enforces W^X on every data region. PQSigner currently uses only SAU; MPU is unused. Adding MPU is the standard DEP defense and costs ~150 LOC.

### 3.3 Pre-commit PIN counter (MCU-authoritative)

`storage/storage.c:1171-1311` increments the MCU-side PIN counter **before** calling the SE verify. A mid-attempt power-loss or glitch still charges the attempt. **PQSigner already has this** — `nsc/mod.rs:265 gated_unlock` + `hw/flash.rs:522 pin_attempts_bump`, cited in `work-todo.md #4 Phase 1` as landed and modelled on Trezor. *Validates existing plan.*

### 3.4 Wipe-code side-channel defense

`storage/storage.c:390-475` — wipe code is stored as `wipe || salt(8) || HMAC-tag(8)` under a separate flash key; both PIN and wipe-code attempts run the *full* PBKDF2 + DEK-decrypt; the wipe-code check is a constant-time HMAC compare with `wait_random()` delays. **Crucially: no branch on "is this a wipe code" before the decrypt succeeds**, which would leak via timing.

PQSigner has no wipe code. If one is added (not currently planned), this is the pattern. Until then: aware-of, not-adopting.

---

## Section 4 — Patterns that validate existing PQSigner plan

These Trezor findings confirm directions PQSigner has already committed to — the recommendation is *"stay the course; the convergent evolution is a good sign"*.

| Trezor pattern | PQSigner equivalent | Status |
|---|---|---|
| `secret_keys/stm32u5/secret_keys.c:41-175` domain-labelled HKDF-Expand from OTP master | `secure/src/hw/secret_keys.rs` header comment literally says "PQSigner parallel to Trezor's" | ✅ Landed |
| `monoctr`-in-OTP for bootloader/firmware rollback | `hw/otp.rs` 1024-bit budget across 32 fuses | ✅ Landed (different primitive, same invariant) |
| Counter-gated SE auth (Optiga E120/E121/E122 LUC) | `work-todo #4 Phase 2` + `#24` to migrate Optiga counter to 0xE120 | 🟡 Tracked |
| OTP-randomness-derived PBS (`secret_key_master_key_get` at `sec/secret_keys/stm32u5/secret_keys.c:178-195`): TRNG seed written once to OTP, then read every boot, HKDF-Expand to produce PBS | `work-todo #24` | 🟡 Tracked — adopts exact Trezor pattern |
| MCU pre-commit PIN counter, bump-before-SE-verify, glitch-guard readback | `nsc::gated_unlock` + `hw::flash::pin_attempts_bump` | ✅ Landed (cites Trezor `storage.c:1171-1311`) |
| BIP-39 → PBKDF2-HMAC-SHA512 → seed | `secure/src/crypto.rs` | ✅ Same primitive |
| SHA-256 hardware peripheral for hot inner loop | `secure/src/hw/hash.rs` + KAT-on-boot ("abc" known-answer test, halt on fail) | ✅ Landed; Trezor has no equivalent self-test on `sec/hash_processor/` — **PQSigner's KAT is actually better** |

---

## Section 5 — Explicit skips (and why)

| Trezor feature | Why skip |
|---|---|
| MicroPython on-device (`core/src/*.py`) | Adds ~500k LOC attack surface; PQSigner `no_std`/no-alloc; no scripting layer is a feature |
| ED25519 attestation via Optiga `sign_device` (`core/src/apps/management/authenticate_device.py`) | Classical crypto; violates invariant #5. Future PQ attestation via SPHINCS+ key in OTP is a separate design |
| secp256k1 / ECDSA everywhere | Classical; not porting |
| Protobuf wire protocol on device | No mature `no_std` codec; APDU v2 is fine. Reconsider if host-lib version churn becomes support burden |
| On-device i18n (`core/translations/*.json`, ~100 KB/language) | Requires heap + asset store; PQSigner is English-only intentionally |
| SLIP-39 Shamir backup | SHA-256-based so PQ-compatible, BUT: PQSigner uses XOR split across two SEs for the same threat (one chip compromise must not reveal seed). Shamir is host-visible; dual-SE is host-invisible. Current split is stronger against host-side compromise |
| Passphrase / hidden wallet (25th word) | PBKDF2-based so PQ-compatible. Compatible with PQSigner at the seed layer if added later; currently no product need (account_index 0..255 gives 256 wallets per seed already) |
| PIN keypad shuffle on touchscreen | PQSigner uses isolated hardware buttons, not touchscreen. Shuffle defeats smudge/replay on touch; irrelevant to two-button entry. If UI ever moves to touch, adopt |
| Custom Trezor anti-glitch "handle_fault" paired-counter (`ctr` + `ctr_ck`) | Listed in `work-todo #4 Phase 2` as a stretch goal; current post-bump readback catches most fault classes |
| Trezor's classical boardloader + bootloader Ed25519 signatures | PQSigner uses SPHINCS+C10 for firmware signing end-to-end. Trezor is *adding* PQ keys (see 6.1); PQSigner got there first |

---

## Section 6 — Structural observations

### 6.1 Trezor is converging on PQ

`core/embed/models/T3W1/model_T3W1.h:48-51` defines `MODEL_BOARDLOADER_PQ_KEYS` — three 32-byte public-key fingerprints alongside the existing `MODEL_BOARDLOADER_KEYS` (ED25519 CoSi) and `MODEL_BOARDLOADER_EC_KEYS`. The keys are defined but the current boardloader verify path does not yet consume them (`grep sphincs core/embed/projects/boardloader/` returns nothing). This is Trezor's groundwork for PQ firmware verification — PQSigner's all-PQ posture is the correct end-state that Trezor is migrating toward.

Direct implication: PQSigner's `fsbl` + `fwsign` + SPHINCS+C10 stack *is* the endgame architecture. The "should we hedge with a classical fallback?" discussion is settled by Trezor's own direction of travel — they are *removing* the hedge, not *adding* one.

### 6.2 Boot chain layer count

Trezor T3W1 is 5 layers: boardloader → bootloader → kernel → secmon (TrustZone S-world) → firmware (NS-world, MicroPython). PQSigner is 2 layers: FSBL → single firmware (with S-world + NS-world inside one build). The missing "secmon as separate signed artifact" is not urgent *if* PQSigner's secure-world image is itself signed and the NS-world is rebuilt per firmware update. Trezor's split lets them ship kernel patches without rotating firmware vendor keys; PQSigner doesn't need that yet. *Consider revisiting if firmware update cadence accelerates past quarterly.*

### 6.3 Dual-SE architecture convergence

T3W1 uses both Optiga Trust M *and* Tropic01 (`core/embed/sec/tropic/`) — same two SE chips PQSigner evaluated. Trezor ships them in parallel for attestation diversity, not entropy-split. PQSigner's XOR-split across Optiga + SE050 is a *different* use of dual-SE (neither chip alone reveals the seed). SE050 vs Tropic01 is a product-level decision; the dual-SE pattern is validated by Trezor.

### 6.4 IMAGE_CHUNK_SIZE = 256 KB (T3W1)

`core/embed/models/T3W1/model_T3W1.h:63`. Trezor streams firmware in 256 KB chunks with a 16-entry pre-computed hash table in the firmware header, verifying each chunk on the fly and writing immediately. PQSigner uses smaller BEGIN/CHUNK/COMMIT with RAM buffering. For large firmware, Trezor's approach is faster. For safer power-loss semantics, PQSigner's is cleaner. *Not a switch worth doing; note the trade-off.*

---

## Section 7 — Concrete action list

Per `CLAUDE.md` Development Posture: PQSigner is pre-production bring-up. Items below are prioritised for the eventual **hardening pass / production branch**, not the current bring-up branch where known regressions (e.g. TZSC=0) are acceptable while end-to-end wiring is being proven out. The ordering is "when hardening begins, do these first," not "interrupt bring-up now."

**Before shipping production (restore the invariants):**
1. Rewrite `secure/src/sau.rs` to implement Trezor's per-peripheral S-allowlist (§1.1). Closes the CRIT-4 `docs/work-todo.md` regression flagged in `CLAUDE.md`.
2. Port `wait_random()` + glitch sentinel into a `secure/src/fi.rs` helper and call it at PIN compare, C10 verify-before-release, and master-key zeroize (§2.6).

**Hardening pass (high value, pick up during the dedicated branch):**
3. `prodtest/` project — own entry point, own signing key slot, feature-gated (§2.1). Unblocks clean factory provisioning + prevents another bench-chip brick.
4. `FLASH_OTP_BLOCK_VENDOR_HEADER_LOCK` + FSBL check (§1.2).
5. `secure/src/hw/tamp.rs` with Trezor's U5 TAMP register map (§2.5).
6. cargo-fuzz harness for `parse_cmd_sign_userop_input` + NSC pointer validation (§2.4) — *this one is safe to pick up opportunistically during bring-up, because fuzzing doesn't block hardware work.*
7. Screenshot-hash UI fixtures in `make e2e` (§2.3) — *also bring-up-safe; regression coverage for UI iteration.*

**Defer until UI/touchscreen/product decisions land:**
8. Passphrase / hidden wallet (not until product request).
9. Touch-keypad shuffle (only if touch replaces buttons).
10. On-device i18n (only if product-market-fit demands non-English).

**Keep current plan:**
11. OTP-derived PBS (`work-todo #24`) — matches Trezor exactly.
12. Optiga 0xE120 counter migration (`work-todo #4 Phase 2`) — matches Trezor E120/E121/E122 pattern.
13. XOR dual-SE split — stronger than Trezor's attestation-only dual-SE for seed-recovery threat model.
14. SPHINCS+C10-only signing — Trezor is moving toward PQ; PQSigner's head-start is a moat, not a risk.

---

## Appendix A — Trezor file index by subsystem

| Subsystem | Entry point |
|---|---|
| TrustZone config (STM32U5) | `core/embed/sys/trustzone/stm32u5/trustzone.c` |
| MPU + region banking | `core/embed/sys/mpu/stm32u5/mpu.c` |
| SMCall (syscall gateway) | `core/embed/sys/smcall/stm32/` |
| Tamper (U5 TAMP) | `core/embed/sec/tamper/stm32u5/tamper.c` |
| Random delays / RDI / DRBG | `core/embed/sec/random_delays/stm32/random_delays.c` |
| Consumption mask (PWM) | `core/embed/sec/consumption_mask/` |
| Secure AES / HASH driver | `core/embed/sec/{secure_aes,hash_processor}/stm32u5/` |
| Optiga driver | `core/embed/sec/optiga/` |
| Tropic01 driver | `core/embed/sec/tropic/` |
| Per-device secret derivation | `core/embed/sec/secret_keys/stm32u5/secret_keys.c` |
| Monotonic counter (SECRET area) | `core/embed/sec/monoctr/stm32u5/monoctr.c` |
| NORCOW + storage + PIN | `storage/{storage,norcow,pinlogs_blockwise}.{c,h}` |
| Image verify + header parse | `core/embed/sec/image/`, `sec/fwutils/` |
| Boardloader | `core/embed/projects/boardloader/` |
| Bootloader | `core/embed/projects/bootloader/` |
| Kernel | `core/embed/projects/kernel/` |
| Secmon | `core/embed/projects/secmon/` + `core/embed/models/T3W1/secmon/` |
| Firmware (MicroPython) | `core/embed/projects/firmware/` + `core/src/` |
| Prodtest | `core/embed/projects/prodtest/` |
| UI (Rust) | `core/embed/rust/src/ui/` |
| Wire protocol (protobuf) | `common/protob/`, `core/src/trezor/wire/` |
| Model config (T3W1 = Safe 7) | `core/embed/models/T3W1/` |
| OTP layout | `core/embed/models/T3W1/otp_layout.h` |
| UI screenshot-hash tests | `tests/ui_tests/common.py` + `fixtures.json` |
| Upgrade tests | `tests/upgrade_tests/` |
| Click tests | `tests/click_tests/` + `tests/input_flows.py` |
| Crypto fuzzer | `crypto/fuzzer/` |
| CI workflows | `.github/workflows/core.yml`, `common.yml` |

## Appendix B — Verified vs asserted

During the research pass, four load-bearing claims from the deep-dive agents were spot-verified against Trezor source before inclusion in this doc:

- ✅ `wait_random()` glitch sentinel — `random_delays.c:186-202`, exact text matches.
- ✅ TZSC config is default-NS + explicit S-allowlist (original agent framing was reversed — corrected here).
- ✅ `monoctr_write` is unary-counter with idempotent rewrites — `monoctr.c:59-92`, behavior matches.
- ✅ TAMP multi-source enable list with `TAMP->CR3 = 0` confirmed mode — `tamper.c:100-166`.
- ✅ `secret_keys/stm32u5/secret_keys.c:178-195` — OTP-randomness → HKDF-derived PBS, matches work-todo #24 plan.
- ✅ `MODEL_BOARDLOADER_PQ_KEYS` exists and is wired into the model header at `model_T3W1.h:48-51`.
- ✅ T3W1 OTP layout 9 blocks — `otp_layout.h:4-12`.
- ✅ PQSigner's existing `hw/secret_keys.rs`, `gated_unlock`, `pin_attempts_bump` all confirm the "validates existing plan" category is not speculative.

The one OID-map conflict noted: Trezor's `F1D4` is `STRETCHED_PIN` (AUTOREF); PQSigner's `F1D4` is `OID_BOOTSTRAP_VK` per `secure/src/optiga/apdu.rs:151`. The two firmware families use disjoint Optiga object maps — symmetry is coincidental in the D4 digit, not meaningful. Do not treat per-OID analogies as portable without re-checking the `change/read/execute` metadata each side writes.
