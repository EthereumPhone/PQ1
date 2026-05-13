# Feature flags & key-derivation roots

The single page that disambiguates the ~50 Cargo features in `secure/Cargo.toml`. If you're trying to figure out **what root a given build uses for the OPTIGA PBS / SE050 admin PIN / SE050 SCP03**, or **which features are safe in a shipping image**, this is the doc.

> See also: `secure/Cargo.toml` (feature definitions), `secure/src/nsc/mod.rs` (`compile_error!` production-build fence), `docs/HARDENING.md` §3-5 (invariants), `docs/production-todo.md` (irreversible factory gates), `docs/work-todo.md` (in-progress feature work), `docs/trezor-comparison.md` (the comparison this all came from).

---

## 1. The five axes

Every build picks at most one option from each axis (except *Accelerators*, which compose). The axis aliases (`platform-*`, `secure-element-*`, `ui-mode-*`, `mode-*`, `accel-*`) wrap legacy feature names for the Makefile recipes (handoff: phase-8 PR 2 will flip every recipe and delete the legacy aliases — for now both work).

| Axis | Options | Notes |
|---|---|---|
| **Platform** | `platform-qemu` · `platform-stm32u585` (`= ["stm32u585"]`) | Pick one. `stm32u585` is real hardware; `platform-qemu` is `mps2-an505`. |
| **Secure element** | `secure-element-mock` · `-optiga` · `-se050` · `-tropic01` · `-dual` (`= ["dual-se"]` ⇒ OPTIGA + SE050) | Pick one at the top level. `dual` is what ships. |
| **UI** | `ui-mode-semihosting` · `-oled` · `-noop` · `-mirror` · `-capture` | Mutually exclusive backends. `-mirror`/`-capture` compose on top of `-oled`/`-noop`. |
| **Mode** | `mode-production` · `-bringup` (=`debug-log`) · `-e2e` (=`debug-log,e2e-test`) · `-bench` | Development profile. |
| **Accelerators** | `accel-pka` · `-tamp` · `-consumption-mask` · `-saes-dhuk` | Compose freely. |

---

## 2. Key-derivation roots, **by build**

There are three different things a SE secret can be rooted in, picked at compile time:

| Build features | OPTIGA PBS root (`optiga_pairing_secret`) | SE050 admin PIN root (`se050_admin_pin`) | SE050 SCP03 keys (today / after #20) | Ships? |
|---|---|---|---|---|
| **Production:** `saes-dhuk` + `bhk` (no hardcoded keys) | silicon **DHUK** — `SAES-CMAC(DHUK, "pqsigner/optiga-pbs-v1")` | silicon **BHK** — `SAES-CMAC(BHK, "pqsigner/se050-admin-pin-v1")` | published factory keys *today*; **BHK** after `make flash-hw-se050-rotate-scp03` at provisioning | ✅ this is the shipping config |
| `make dual-se-bhk-e2e` (`saes-dhuk,bhk,e2e-test`) | silicon DHUK | silicon BHK | factory (probe-derived if `se050-derived-scp03` also added) | ❌ test image (`e2e-test`) |
| `make dual-se-admin-wipe-e2e`, `make e2e-hw` (`otp-hardcoded-master-key`, no `bhk`) | **compile-time OTP constant** (HKDF) | `derive_into_bhk` *falls through* → **compile-time OTP constant** (HKDF) | published factory keys | ❌ dev-only (fence) |
| `bhk-hardcoded-master-key` (dev) | (per the DHUK/OTP arm) | **compile-time BHK constant** (HKDF) | published factory keys | ❌ dev-only (fence) |
| Neither `saes-dhuk` nor `otp-hardcoded-master-key` (legacy) | per-board **TRNG OTP-master** (HKDF; burned by `ensure_device_master`) | falls through → per-board TRNG OTP-master | published factory keys | not used; legacy fallback only |

**The thing that's easy to get wrong:** `secret_keys::derive_into_bhk` is the *call site* for SE050 secrets (the Phase-2C call-site flip, `aa23f05`), but whether it actually uses the silicon BHK depends on the `bhk` feature. With `bhk` off it falls through to `derive_into` → DHUK / OTP-const / OTP-master per the table. The "BHK axis" describes the code path; the root is build-dependent.

**Provisioning-order constraint (production):** because the BHK is stored DHUK-ECB-wrapped on flash page 126, and the DHUK changes at `RDP0 → RDP1` (ST-substituted constant → real per-die), the BHK first-write — and anything derived from it, including the admin UserID and the SCP03 PUT KEY ceremony — must happen *at RDP ≥ 1*. Factory sequence: `step RDP → 1` → provision (BHK first-write) → OPTIGA provision → SE050 provision → SCP03 PUT KEY → … → `burn RDP=2`.

---

## 3. What "OTP" means in this codebase

Two distinct things both called "OTP":

- **STM32U585 OTP fuse region** — used in production for the **firmware rollback counter** (`hw/otp.rs` `ROLLBACK_WORDS = 32`, 1024 bits, one cleared per accepted firmware update; never reset; exhausted parts are update-EOL). Always used. *Not* a key.
- **OTP "master key" region** (32 bytes in OTP, burned once by `hw::otp::ensure_device_master()`) — the **legacy** derivation root. On a `saes-dhuk` shipping build `ensure_device_master()` is **never called** (verified in the Phase-2C pre-flight) → this region **stays blank for the device's life**. The roots are the silicon DHUK + BHK, not an OTP-burned master. The old "burn an OTP master in production" plan is superseded.
- **`otp-hardcoded-master-key` Cargo feature** — a *dev-only compile-time constant* standing in for that OTP master so re-flashed bench boards keep stable derivations. **Never ships** (in the `compile_error!` fence in `nsc/mod.rs`).

---

## 4. The production-build fence (`secure/src/nsc/mod.rs`)

A `compile_error!` rejects any `feature = "stm32u585" + !debug_assertions + !e2e-test + !dev-testkey` build that also enables any of:

```
debug-log · ui-semihosting · ui-mirror · ui-capture ·
mock-se ·
otp-hardcoded-master-key · bhk-hardcoded-master-key ·
saes-self-test · uart-console · boot-pulse ·
se050-rotate-scp03
```

Hardware test images opt in via `e2e-test` (or `dev-testkey`) — both are unambiguous "not-shippable" markers. CI must still gate shipped firmware on `e2e-test` being OFF.

There's also a dedicated dual-feature `compile_error!` for `otp-hardcoded-master-key + optiga-lock-operational` (publishes the Shielded-Connection secret across every dev board), and one in `secret_keys.rs` for `bhk + otp-hardcoded-master-key` (the BHK boot wiring is `not(otp-hardcoded-master-key)`-gated, so this combo would compile and fail at runtime with `KeyInvalid`).

---

## 5. Common Makefile recipes → feature sets

| Recipe | Features | Purpose / brick-risk |
|---|---|---|
| `make e2e-hw` | `e2e-test,stm32u585,otp-hardcoded-master-key,dual-se,…` | The full unified-sign e2e on real silicon. **Brick-proof** (all-constants config). Default for routine dev. |
| `make dual-se-admin-wipe-e2e` | `dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,otp-hardcoded-master-key` | Admin-wipe roundtrip with the OTP-const root. **Brick-proof.** Self-heals the OPTIGA back to OTP-const PBS. |
| `make dual-se-bhk-e2e` | `dual-se-admin-wipe-e2e,stm32u585,ui-oled,debug-log,e2e-test,saes-dhuk,bhk` | The production-shape validation — admin PIN on silicon BHK + OPTIGA PBS on silicon DHUK. Provisions+wipes in one boot, so no persistent brick — but **don't run on a board you're about to RDP-regress** if you've left a BHK-derived provisioning persistent. |
| `make flash-hw-se050-rotate-scp03` | `se050-rotate-scp03,bhk,stm32u585,ui-oled,debug-log,e2e-test` | **IRREVERSIBLE.** One-shot GP PUT KEY ceremony, replaces SCP03 keyset 0x0B in place. Production-provisioning only. |
| `make saes-self-test-hw[-rdp1]` | `saes-self-test,debug-log,ui-noop,e2e-test,mock-se[,uart-console]` | DHUK fingerprint check. **Brick-proof** (`mock-se` — no real SE I/O). Used for the per-die DHUK experiments. |
| `make test-key-speed` | (bench profile) | DWT-timed signing bench, no semihosting reads → works on real silicon without the probe-rs `SYS_READC` hang (CLAUDE.md HW gotcha). |

**RDP-cycling dev playbook:** use `make e2e-hw` / `make dual-se-admin-wipe-e2e` (all-constants) for routine iteration that hits the real SEs; only run `make dual-se-bhk-e2e` when you've stopped RDP-cycling for a bit; `make saes-self-test-hw-rdp1` is SE-safe (mock-se) so it can RDP-cycle freely.

---

## 6. The full "what each feature does, one line each" table

Live source: `secure/Cargo.toml` (each feature has an inline `#`-comment). The high-level groupings:

- **Backend mutex (pick one at the top level):** `mock-se` · `optiga-trust-m` · `se050` · `tropic01-se` · `dual-se` (= `optiga-trust-m + se050`).
- **Platform:** `stm32u585` (real HW, implies `hw-sha256`) vs. nothing (QEMU `mps2-an505`).
- **UI:** `ui-semihosting` · `ui-oled` · `ui-noop` (silent for headless USB) · `ui-mirror` (RTT framebuffer stream) · `ui-capture` (per-frame SHA-256).
- **Hardening / accelerators (compose):** `saes-dhuk` (Tier-1 DHUK-SAES KDF) · `saes-self-test` · `tamp` (currently log-only) · `consumption-mask` (TIM2 PWM PA5) · `pka-accel` · `bhk` (Tier-2 BHK lifecycle on flash page 126).
- **OPTIGA-specific:** `optiga-hw-counter` (E120 LUC bound to F1D0) · `optiga-lock-operational` (irreversible LcsO bump — production only) · `optiga-no-shield` (dev only).
- **SE050-specific:** `se050-derived-scp03` (Stage A of #20 — derived SCP03 keys with probe-on-boot fallback) · `se050-rotate-scp03` (Stage B — the irreversible PUT KEY ceremony build, fenced) · `se050-factory-reset` · `se050-reset-e2e` · `se050-admin-wipe-e2e` · `se050-admin-extract-attempt-e2e` · `se050-crash-safety-e2e`.
- **TROPIC01-specific:** `tropic01-se`.
- **Test scaffolding:** `e2e-test` (fixed mnemonic + PIN, short-circuits `confirm()`/`enter_pin()`) · `e2e-skip-*` (sub-tests skipped under e2e) · `dev-testkey` (interactive UI, OTP substituted) · various `*-e2e` one-shot dispatchers.
- **Dev-only (NEVER ship):** `debug-log` · `ui-semihosting` · `ui-mirror` · `ui-capture` · `mock-se` · `otp-hardcoded-master-key` · `bhk-hardcoded-master-key` · `saes-self-test` · `uart-console` · `boot-pulse` · `se050-rotate-scp03` (irreversible ceremony build).

For the exact list of each feature's implications (the `feature = [...]` tuples), read `secure/Cargo.toml` — it has one-line comments on every flag explaining what it does and what it gates.

---

## 7. Cross-references

- `docs/work-todo.md #7 Tier 1/2` — the DHUK/BHK silicon-root migration (Phase 2C call-site flip + activation).
- `docs/work-todo.md #20 / "11. SCP03 Key Rotation"` — Stage A (derived keys + probe-on-boot, landed) + Stage B (PUT KEY code landed, ceremony deferred).
- `docs/production-todo.md` — "Irreversible gates" + the factory-sequence checklist + the BHK-page first-write item.
- `docs/HARDENING.md §3.5` — the SE050 SCP03 rotation requirement (BHK root, RDP≥1 ordering, brick class).
- `docs/trezor-comparison.md §6.5` — why the OPTIGA stays on DHUK and only the SE050 goes on BHK; the inverse trade-off Trezor takes with its BHK (storage-KEK stretching, regenerate-on-wipe).
- `docs/optiga-brick-postmortem.md` — the brick class the on-demand HUK-derivation closes (the old flash-seal-tied PBS).
