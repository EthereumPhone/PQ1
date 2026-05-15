# Dead-Code Removal — `secure-hw-io`

_Date_: 2026-05-15
_Reviewer_: Claude Code (ultrathink)

## Scope
Bus / IO peripherals: I2C, SPI, USB, UART, buttons + hw/mod.rs.

Files audited:
- `secure/src/hw/mod.rs` (128 lines)
- `secure/src/hw/i2c.rs` (250 lines)
- `secure/src/hw/i2c_hw.rs` (144 lines)
- `secure/src/hw/i2c2_probe.rs` (407 lines)
- `secure/src/hw/spi.rs` (260 lines)
- `secure/src/hw/spi_hw.rs` (224 lines)
- `secure/src/hw/usb_hw.rs` (258 lines)
- `secure/src/hw/uart.rs` (187 lines)
- `secure/src/hw/buttons.rs` (389 lines)

## Summary
This slice is largely clean — almost every symbol is either reachable from
`secure/src/main.rs` under one of the documented feature gates
(`stm32u585`, `usb`, `se050`/`optiga-trust-m`, `tropic01-se`, `ui-oled`,
`uart-console`, `gpio-buttons`) or via the test-mode targets
(`stsafe-probe`, `button-test`). Three small removals applied:
an unused `SR_TXTF` status-bit constant in the SPI driver, two
unnecessary `unsafe { }` wrappers around safe `cs_assert()`/`cs_deassert()`
calls (which were producing `unnecessary unsafe block` warnings under
`tropic01-se`), and a stale doc-comment reference (PI2/PA15 → PC1/PA8) in
the buttons driver plus a stale comment about `t1oi2c` "reaching in" to
`i2c_hw` typed handles (callers actually only consume the `I2C1` base-address
const). Equivalence verified by `cargo check` under the default
QEMU/`mock-se` config plus the two hardware configs that compile our
files (`stm32u585,se050,gpio-buttons,usb` and `stm32u585,tropic01-se`):
warning sets are equivalent or strictly smaller post-deletion. Slice is
healthy.

## Deletions applied
| file:lines (pre-edit) | item | bucket | rationale |
|---|---|---|---|
| `secure/src/hw/spi.rs:57` | `const SR_TXTF: u32 = 1 << 4` | 1 (truly unused) | Status-register bit constant with zero callers; pre-existing `never used` warning under `tropic01-se`. The flag-clear path uses `IFCR_TXTFC` (a different bit, in IFCR), which remains. |
| `secure/src/hw/spi.rs:207-211` | `unsafe { cs_assert(); }` block | 3 (dead unsafe) | `cs_assert` is a safe `pub fn`; the wrapping `unsafe` block was producing `unnecessary unsafe block` warnings. SAFETY comment removed with it. |
| `secure/src/hw/spi.rs:252-255` | `unsafe { cs_deassert(); }` block | 3 (dead unsafe) | Same as above for `cs_deassert`. |
| `secure/src/hw/buttons.rs:135` | doc-comment "PI2 / PA15" | 5 (stale comment) | Stale references to pins from a much earlier wiring; actual code wires PC1 (LEFT) and PA8 (RIGHT). Fixed to match the body of `init()` and the rest of the module. |
| `secure/src/hw/i2c_hw.rs:32-33` | comment "The se050::t1oi2c driver reaches in for the raw register addresses; keep the typed handles below as the source of truth." | 5 (stale comment) | Misleading — `se050/i2c.rs` and `optiga/i2c.rs` consume the `I2C1` base-address const and build their own typed handles; they do not touch `I2cHwRegs`/`REG`. |

## Reverted during bisect
None.

## Cross-slice observations
- `secure/src/hw/i2c_hw.rs`: `pub struct I2c1Regs`, `pub struct I2cHwRegs`,
  `pub const REG` and their `pub` fields have no external callers
  (verified by `grep` across the workspace — only the `I2C1` base-address
  const escapes the module). Pre-existing dead-field warnings
  (`fields cr2, isr, icr, rxdr, txdr are never read` on `I2c1Regs`)
  already flag this. A focused refactor could either drop the unused
  reg-handle fields or remove the typed-handles entirely and inline the
  remaining few register accesses in `init()`. Left as a recommendation
  because it touches more lines than this pass aims for and changes
  visibility surface, not behaviour.
- `secure/src/hw/usb_hw.rs::init()` step-numbering comments jump from
  "---- 4. Reset USB OTG FS ----" to "---- 6. Mark USB pins as non-secure ----"
  (step 5 was inlined into rcc::init as a comment notes). Cosmetic, left
  as-is.
- `secure/src/hw/uart.rs::write_byte` and `write_bytes` are `pub` but only
  used internally by `write_str` / `write_hex_8`. They are a sensible
  low-level driver surface — left as-is.
- `secure/src/hw/spi_hw.rs::CS_PIN` is `pub const` but only used inside
  the module. Same reasoning — sensible driver surface, no harm.
- Out-of-scope: many `// SAFETY:` / `unsafe { ... }` blocks in
  `secure/src/hw/usb_hw.rs` (debug-log register dumps) and
  `secure/src/hw/i2c2_probe.rs` could be migrated to the `hw::mmio`
  typed-handle pattern per `docs/handoff-unsafe-reduction.md`. Not dead
  code — listed only for visibility.

## Skipped
- All `#[cfg(feature = "...")]`-gated dev/test modules (`button-test::run_test`,
  `stsafe-probe::run_probe`, `uart-console::*`, `debug-log` register dumps)
  are bucket 2 (intentional dev/test infrastructure with live Makefile
  targets — `make button-test`, `make stsafe-probe`, `make saes-self-test-hw`).
  Not dead.

## Equivalence check
Commands run against the three configurations that compile the in-scope
files. `cargo fmt` and `cargo clippy -- -D warnings` are blocked by this
session's permission profile; verified instead via direct `cargo check`
warning-diff per config.

- `cargo fmt -p sphincs-tz-secure --check` — N/A (permission)
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features mock-se,debug-log,ui-semihosting`
  — baseline: 82 warnings, none in scope → post: 82 warnings, none in scope → **EQUIV**
  (none of the in-scope files compile in this config beyond `mod.rs`)
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features se050,gpio-buttons,debug-log,ui-semihosting,stm32u585,usb`
  — baseline: 1 in-scope warning (`I2c1Regs` dead fields) → post: same 1 in-scope warning at adjusted line → **EQUIV**
- `cargo check --target thumbv8m.main-none-eabi -p sphincs-tz-secure --no-default-features --features tropic01-se,debug-log,ui-semihosting,stm32u585`
  — baseline: 3 in-scope warnings (`SR_TXTF` unused + 2× `unnecessary unsafe block`) → post: **0** in-scope warnings → **EQUIV (strictly fewer warnings, all explained by the targeted deletions)**
- `cargo clippy -p sphincs-tz-secure -- -D warnings` — N/A (permission)
- `cargo test -p sphincs-tz-secure` — N/A (firmware crate, `no_std`, `thumbv8m` target — no host-runnable tests; `make e2e`/`make e2e-hw` excluded per the task brief)
- binary SHA-256: not captured (release builds need `make secure` with full feature set; no in-scope behavior change, only dead constant + dead `unsafe` block + comment text)
