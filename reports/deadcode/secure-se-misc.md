# Dead-Code Removal — `secure-se-misc`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
SCP03 logic, secure-element abstraction, CMAC, semihosting-SPI, Tropic01.

Files audited:
- `secure/src/scp03_logic.rs` (459 → 442 lines)
- `secure/src/secure_element.rs` (549 → 540 lines)
- `secure/src/cmac.rs` (468 lines)
- `secure/src/semihosting_spi.rs` (216 lines)
- `secure/src/tropic01_se.rs` (672 → 654 lines)

## Summary
Three workspace-wide dead items were deleted: an unused AES-128-CBC
decrypt primitive in `scp03_logic`, an unused diagnostic
`MockSecureElement::macd_all_initialized` predicate, and an unused
Tropic01-only `get_trng_bytes` helper. The `cmac.rs` and `semihosting_spi.rs`
files were clean — every `cmac_generic` / `kdf_cmac_counter_generic`
symbol is consumed by `hw::saes_cmac` / `hw::secret_keys` under
`stm32u585`, and `SemihostingSpi` is the QEMU side of the Tropic01
session macro. Equivalence checks pass across mock-se host tests
(121/121) and four firmware feature combinations.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/scp03_logic.rs:94-110` | `pub fn aes128_cbc_decrypt` | 1 (truly unused) | Counterpart to `aes128_cbc_encrypt` but no caller anywhere in the workspace — `se050::scp03::wrap_apdu` only encrypts request payloads, never decrypts response bodies. Cross-slice note from the `secure-se050` pass already flagged it as dead-but-out-of-scope; deleting here. |
| `secure/src/secure_element.rs:212-218` | `MockSecureElement::macd_all_initialized` | 1 (truly unused) | Diagnostic predicate with zero callers. Multiple prior dead-code reports (`secure-nsc-core`, `secure-crypto-glue`, `secure-main-sau`, `secure-optiga`, `secure-tx-display`) flagged it as out-of-scope dead code; in scope for this slice. |
| `secure/src/tropic01_se.rs:579-596` | `Tropic01SecureElement::get_trng_bytes` | 1 (truly unused) | Wraps `session.get_random_value(...)` but no caller invokes it. `WalletStore::random` default impl returns `Err(SeError::SlotNotFound)` and the Tropic01 backend does not override it, so the trait-level TRNG entrypoint is also dead for this backend — but `random` is the standardised cross-backend hook, so removing only the unused inherent method here. |

## Reverted during bisect
None — all three deletions survived the equivalence check on the first
run.

## Cross-slice observations
- `secure/src/secure_element.rs:206-209` `MockSecureElement::simulate_glitch` and the `glitch_armed` field/branch in `mac_and_destroy` are only reachable from `#[cfg(test)]` host tests in the same file. Production builds compile the `if self.glitch_armed` branch as effectively-unreachable. Bucket 2 (test-only infrastructure) — left untouched. A future refactor could gate the whole glitch-injection mechanism on `#[cfg(test)]` to drop the dead branch from firmware builds.
- `secure/src/scp03_logic.rs::scp03_kcv`, `PUT_KEY_APDU_LEN`, `PUT_KEY_INS` are `pub` but only consumed inside `scp03_logic::build_put_key_apdu`. Could be downgraded to private; left as is (visibility refactor, not deletion).
- Under `tropic01-se` or `mock-se` feature combos the entire `scp03_logic` module compiles dead (rustc emits 18 "never used" warnings for AES/CMAC/KDF/PUT KEY items). Those items are *live* under `se050` / `dual-se`. Bucket 2; leaving as is. A `#[cfg(any(feature = "se050", test))]` gate on the `mod scp03_logic;` declaration would silence the noise, but it is a feature-gating refactor outside the deletion remit.

## Skipped
- Generated transcript files in `reports/deadcode/` (out of scope).
- `simulate_glitch` / `glitch_armed` mechanism (bucket 2 — test-only infrastructure live under `#[cfg(test)]`).
- `aes128_ecb_encrypt`, `aes128_cbc_encrypt`, `cmac_aes128`, `scp03_kcv`, `PUT_KEY_*`, `KEY_VERSION`, `PLATFORM_ENC/MAC/DEK`, `DD_*`, `build_derivation_data`, `kdf`, `build_put_key_apdu`, `keys_are_factory_default` — all live under `se050` / `dual-se` via `secure/src/se050/scp03.rs`.
- `cmac_generic`, `kdf_cmac_counter_generic`, `double_l`, `KdfError` — consumed by `hw::saes_cmac` (under `stm32u585`) and `hw::secret_keys` (under `stm32u585`).
- `SemihostingSpi`, all `SpiError` variants — consumed by `tropic01_se::with_session!` under `tropic01-se` + QEMU (not `stm32u585`).
- `Tropic01SecureElement::{load_pairing_key, setup_pairing, batch_*, store_data_session}` — all reachable from `main.rs` boot path or the `WalletStore` impl.

## Equivalence check

Baseline captured before any edits; post-deletion runs use the same
invocations. Mock host tests run in full; firmware-target builds are
`cargo check` only (no flashing). The Cargo workspace `Makefile` does
not currently expose `cargo fmt -p sphincs-tz-secure --check` to this
sandbox; same N/A as prior dead-code slices.

- `cargo fmt -p sphincs-tz-secure --check` — **N/A** (sandbox does not permit the invocation; per-file deletions kept rustfmt-irrelevant whitespace intact).
- `cargo check -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting --tests` — baseline: success, 39 warnings; post: success, **37 warnings** → **EQUIV** (−2: `aes128_cbc_decrypt`, `macd_all_initialized`; no warnings added).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features tropic01-se,ui-semihosting` — baseline: success, 81 warnings; post: success, **79 warnings** → **EQUIV** (−2: `aes128_cbc_decrypt`, `get_trng_bytes`; `macd_all_initialized` rolled into the existing `MockSecureElement` multi-item warning).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features tropic01-se,stm32u585,ui-oled` — baseline: success, 116 warnings; post: success, **114 warnings** → **EQUIV** (−2).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features dual-se,stm32u585,ui-oled` — baseline: success, 155 warnings; post: success, **154 warnings** → **EQUIV** (−1: `aes128_cbc_decrypt`; `macd_all_initialized` rolled into the existing multi-item warning).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (sandbox / target mismatch — matches prior slice practice).
- `cargo test -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting` — baseline: **121 passed / 0 failed**; post: **121 passed / 0 failed** → **EQUIV**.
- Firmware binary SHA-256 — **N/A** (no release build invoked; four `cargo check` configurations above cover the relevant feature surface).
