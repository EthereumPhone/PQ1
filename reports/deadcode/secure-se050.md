# Dead-Code Removal — `secure-se050`

_Date_: 2026-05-16
_Reviewer_: Claude Code (ultrathink)

## Scope
SE050 driver (T=1' + SCP03 + APDU + UserID PIN).

Files audited:
- `secure/src/se050/mod.rs` (2390 → 2347 lines)
- `secure/src/se050/apdu.rs` (941 → 916 lines)
- `secure/src/se050/scp03.rs` (355 → 350 lines)
- `secure/src/se050/i2c.rs` (248 → 211 lines)
- `secure/src/se050/t1oi2c.rs` (344 → 342 lines)

## Summary
The SE050 driver had a small pile of vestigial scaffolding: a `factory_reset`
method explicitly documented as "does NOT actually wipe objects" (its sole
caller in NXP's quick-start sketch was retired when we moved to
`iterative_delete_all` / `admin_factory_reset`), an unused
`provision_with_admin` wrapper that no path picks up (the WalletStore
provision route inlines `provision_admin` + `store_objects` instead), an
unused `Se050Error::I2c` variant (the `T1Error → Se050Error` From impl maps
every transport failure to `Transport`), a leftover `i2c::write_read` from
early bring-up before the driver settled on separate write+read transactions,
two unused PCB constants in the T=1 framer, and a handful of unused
`pub use` re-exports in `scp03.rs`. All deletions are leaves on the
call graph and verified against five feature combinations on the firmware
target plus the host test suite. No tests regressed (121 / 121 pass) and
no new warnings were introduced; the dual-se / se050 / dual-se+debug-log
configs each shed 9–11 warnings. `user_factory_reset` was kept — it's only
reachable under `e2e-test` + `dual-se-admin-wipe-e2e` (bucket 2,
dev-only infrastructure).

## Deletions applied

| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/se050/i2c.rs:64` | `const ISR_TXE` | 1 | Bit position never read; no flag wait ever masks it. |
| `secure/src/se050/i2c.rs:69` | `const ISR_TC` | 1 | Only reader was `write_read` (also deleted); transfer-complete-reload (`ISR_TCR`) is what the surviving write/read paths use. |
| `secure/src/se050/i2c.rs:73` | `const ISR_BUSY` | 1 | Bus-busy flag never polled by SE050 driver (OPTIGA path has its own copy via `optiga/i2c.rs`). |
| `secure/src/se050/i2c.rs:83` | `const CR2_STOP` | 1 | Explicit STOP bit unused — the driver uses `CR2_AUTOEND` exclusively. |
| `secure/src/se050/i2c.rs:217-248` | `pub fn write_read` | 1 | Repeated-START write-then-read helper with zero callers. SE050 driver issues APDUs via the T=1 framing layer, which does write + separate read transactions; the only `write_read` consumer in the workspace is `optiga::ifx_i2c` which calls `optiga::i2c::write_read` (different module). |
| `secure/src/se050/t1oi2c.rs:60` | `const PCB_S_BLOCK` | 1 | S-block tag bits (0xC0) never compared against — the WTX/INTF_RESET handlers compare full PCB bytes (`PCB_S_WTX_REQ`, `PCB_S_INTF_RESET_REQ`) directly. |
| `secure/src/se050/t1oi2c.rs:64` | `const PCB_S_INTF_RESET_RSP` | 1 | Response PCB tag (0xEF) never validated — the driver treats any non-error reply to the reset-request frame as success. |
| `secure/src/se050/apdu.rs:23` | `Se050Error::I2c` variant | 1 | Never constructed; `impl From<T1Error> for Se050Error` maps every transport failure (including bus errors) to `Se050Error::Transport`. No match arm anywhere extracts `I2c`. |
| `secure/src/se050/apdu.rs:865-886` | `pub unsafe fn platform_factory_reset` | 4 | `SetPlatformSCPRequest` only toggles SCP03-mandatory, doesn't wipe objects (acknowledged in its own doc comment); only caller was the dead `Se050::factory_reset`. |
| `secure/src/se050/mod.rs:467-479` | `pub fn Se050::factory_reset` | 4 | Same vestigial path; doc itself says "Legacy ... does NOT actually wipe objects." All real cleanup goes through `iterative_wipe`, `user_factory_reset`, or `factory_reset_admin`. Zero callers in workspace. |
| `secure/src/se050/mod.rs:1557-1585` | `pub fn Se050::provision_with_admin` | 1 | Three-line wrapper around `store_objects(... Some(admin_pin))` plus cache writes. Zero callers — the `WalletStore::provision` impl at line 2094 calls `provision_admin` + `policy_roundtrip_selftest` + `store_objects` directly, and `dual_se.rs` provisions via that trait method. |
| `secure/src/se050/scp03.rs:17-19` | unused `pub use` re-exports: `aes128_cbc_decrypt`, `scp03_kcv`, `PUT_KEY_APDU_LEN`, `PUT_KEY_INS` | 1 | None of these four are consumed outside `scp03_logic` itself: `aes128_cbc_decrypt` has zero workspace callers (driver doesn't decrypt response payloads — only wraps commands); `scp03_kcv`, `PUT_KEY_APDU_LEN`, and `PUT_KEY_INS` are used only inside `scp03_logic::build_put_key_apdu`. Trailing doc-comment block updated for accuracy. |

## Reverted during bisect
None — every deletion survived the equivalence check on the first pass.

## Cross-slice observations

| file:line | item | note |
|---|---|---|
| `secure/src/scp03_logic.rs:95` | `fn aes128_cbc_decrypt` | Dead in the workspace once the `pub use` is trimmed — no caller anywhere. Lives in `secure/src/scp03_logic.rs`, outside the `secure-se050` slice. |
| `secure/src/scp03_logic.rs:167` | `fn scp03_kcv` | Only used inside `scp03_logic::build_put_key_apdu` and its own `#[cfg(test)]` block — not externally consumed. |
| `secure/src/hw/secret_keys.rs:308-340` | `se050_scp03_{enc,mac,dek}_key` | Only used under `feature = "se050-derived-scp03"` (bucket 2). Out of scope for this slice but worth flagging if the feature is ever retired. |
| `secure/src/se050/t1oi2c.rs:16` | `T1Error::I2c(i2c::I2cError)` inner field | The `dead_code` lint flags "field 0 is never read" because no `match T1Error::I2c(e) => ...` arm extracts the inner error. Left alone: the variant *is* constructed (via `impl From<I2cError>`), the inner `I2cError` is preserved for `Debug`-printed logs under `debug-log`, and removing the field would change the diagnostic Debug output (an observable-behaviour change). |

## Skipped

The remaining SE050 warnings under `dual-se,stm32u585,ui-oled` are all
bucket 2 / 5 and intentionally retained:

- `unused variable: e` / `name` / `success_attempt` / `last_err` / `admin_post`
  — each is referenced inside a `secure_log!(...)` call whose body is gated
  on `feature = "debug-log"`. CI gates production on `debug-log = OFF`, so
  these are dev-only consumers. The compiler can't see through the
  `macro_rules! secure_log` no-op definition under `not(debug-log)`, which
  is the source of the warnings.
- `unnecessary unsafe block` (mod.rs:2338) — pre-existing, not introduced by
  this pass; would be an unrelated cleanup.
- `method user_factory_reset is never used` — bucket 2: called from
  `main.rs` under `e2e-test + dual-se + stm32u585` and from `dual_se.rs`
  under `dual-se-admin-wipe-e2e`. Retained.
- `unused imports: build_put_key_apdu and keys_are_factory_default`
  (scp03.rs:17) — bucket 2: both are used only under
  `feature = "se050-rotate-scp03"` (the GP `PUT KEY` rotation path in
  `Se050::rotate_scp03_keys`).

## Equivalence check

Verified across five feature combinations on the firmware target plus the
host test suite. Each command's outcome class (build success / warning set
/ test count) is identical or strictly smaller post-deletion.

- `cargo fmt -p sphincs-tz-secure -- --check` — **N/A** (host policy
  disallowed this exact invocation; the edits removed whole items and
  cleaned up adjacent whitespace, so no rustfmt-relevant in-line spacing
  changed inside untouched code).
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure
  --no-default-features --features dual-se,stm32u585,ui-oled`
  — baseline: success, 171 warnings; post: success, **160 warnings** →
  **EQUIV** (11 warnings removed — exactly the deletion-table items; no
  warnings added).
- `cargo check ... --features se050,stm32u585,ui-oled` — baseline 133,
  post **124** → **EQUIV** (9 warnings removed).
- `cargo check ... --features mock-se,debug-log,ui-semihosting` — baseline
  78, post **78** → **EQUIV** (no SE050 driver compiled under `mock-se`;
  deletions invisible to this config, as expected).
- `cargo check ... --features dual-se,stm32u585,ui-oled,debug-log` —
  baseline 119, post **110** → **EQUIV** (9 warnings removed).
- `cargo check ... --features dual-se,stm32u585,ui-oled,e2e-test,debug-log`
  — baseline 24, post **24** → **EQUIV** (no SE050 warning hits this
  config since `user_factory_reset` becomes live and the other deleted
  items were already either dead or used).
- `cargo check ... --features dual-se,stm32u585,ui-oled,e2e-test,dual-se-admin-wipe-e2e`
  — post: success, 85 warnings → **EQUIV** (admin-wipe e2e path still
  compiles; `user_factory_reset` retained for this exact path).
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — **N/A** (host
  policy / target mismatch).
- `cargo test -p sphincs-tz-secure --no-default-features
  --features mock-se,debug-log,ui-semihosting` — baseline: 121 passed /
  0 failed; post: **121 passed / 0 failed** → **EQUIV**.
- Firmware binary SHA-256 — **N/A** (no release build was invoked; the
  six `cargo check` runs above cover every relevant feature combo).
