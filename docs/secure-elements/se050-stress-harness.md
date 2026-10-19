# SE050 on-silicon stress-test harness

**TL;DR — `make se050-stress`** runs every Safe-tier test in
`secure/src/se050_stress/tests/` against the real SE050 on the
attached STM32U585 board, prints a PASS/FAIL summary over
semihosting, and exits 0 if every test passed. Adding a new test is
**one function + one macro line + one slice entry** — no
Cargo.toml, no main.rs, no Makefile edits per test.

This doc tells you how to (a) run it, (b) read the output, (c) add a
test, (d) understand the safety model.

---

## 1. Why this exists

No public SE050 emulator/simulator exists. Every assumption about
how the chip behaves under unusual or adversarial sequencing has to
be checked on real silicon. Pre-existing tests in this repo follow
a strict **one-feature-per-test** pattern
(`se050-reset-e2e`, `se050-admin-wipe-e2e`, …), which is fine for a
handful of curated tests but creates 4-file friction per added test
— hostile to stress testing.

This harness is a single catalog-driven runner. It was built (2026-
05-28) primarily to verify the just-landed **S-5** (SCP03 elevated
to `P1=0x33` with `unwrap_response` wired) and **S-6** (user UserID's
admin-delete policy entry removed) ship-blocker fixes on real silicon.

---

## 2. Hardware prerequisites

- **Board:** B-U585I-IOT02A with the standard wiring used by
  `make flash-hw-dual-se-oled-standalone`. SE050 reachable on I²C1
  (PB8 SCL / PB9 SDA).
- **TrustZone option bytes set:** Run `make flash-hw-dual-se-oled-
  standalone` once before the first stress run. The stress recipes
  flash the secure ELF only — they do NOT reconfigure TZ option bytes.
  Re-flashing the standalone target is also the easiest "go back to
  normal wallet" path after stress tests.
- **probe-rs attached** for the catalog runs (semihosting is the
  output channel). `probe-rs` cannot send semihosting `SYS_READC`,
  but the stress runner never reads input — it just emits PASS/FAIL
  lines, so this is fine.

---

## 3. Running tests

> **`probe-rs run` never exits on its own.** Even after the runner
> prints `=== SUMMARY:` + `=== DONE ===` and the firmware halts in
> `wfi`, the semihosting stream stays open. The Makefile recipes
> wrap `probe-rs run` in `timeout 1200` for this reason
> (`Makefile:1085`). If you invoke `probe-rs run` directly, **always
> prepend `timeout <N>`** — otherwise the terminal hangs forever
> after the tests finish.
>
> Related: the USB probe handle is held exclusively. If a prior run
> was force-killed mid-stream you'll see `interface is busy (errno
> 16)` on the next launch — `pkill -f 'probe-rs run'` clears it.

| Command | What it does |
|---|---|
| `make se050-stress` | Run every Tier::Safe test |
| `make se050-stress-destructive` | Run Safe + Destructive |
| `make se050-stress-only-<name>` | Run a single test by name |
| `make se050-stress-list` | Print the catalog (no flash, no board) |

**Examples:**

```bash
# Quick smoke run on the bench.
make se050-stress

# Run just the S-5 silicon verifier.
make se050-stress-only-scp03_response_encryption_verify

# Run everything, including the UserID-lockout test.
make se050-stress-destructive

# What's in the catalog?
make se050-stress-list
```

The catalog list is grep-driven from the source, so it works
without building the firmware.

---

## 4. Reading the output

Every run emits a stream like this over probe-rs stdout:

```text
[S][stress] === SE050 STRESS RUNNER ===
[S][stress] catalog: 8 tests, tier=safe, filter=ALL, repeat=1
[S][stress] top-of-run admin sweep: 0 cleared, 0 failed
[S][stress] BEGIN 001/008 scp03_handshake_repeat
[S][stress] PASS  001/008 scp03_handshake_repeat (143 ms)
[S][stress] BEGIN 002/008 scp03_apdu_burst
[S][stress] PASS  002/008 scp03_apdu_burst (5212 ms)
[S][stress] BEGIN 003/008 scp03_response_encryption_verify
[S][stress] PASS  003/008 scp03_response_encryption_verify (94 ms)
...
[S][stress] === SUMMARY: 6 PASS / 0 FAIL / 0 SKIP ===
[S][stress] === DONE ===
```

The make recipe scrapes the `=== SUMMARY:` line and exits 0 iff
`FAIL` count is 0. On the OLED you also see per-test status (`name
… PASS` / `… FAIL`) and a final `SUMMARY P/F` frame.

**Failure shape:**

```text
[S][stress] FAIL 003/008 scp03_response_encryption_verify err=Mismatch{what:"S-5 SCP03 payload round-trip",expected:0xde,got:0x00} (94 ms)
```

The `err=` field is a structured `StressError` (one of
`Sw(u16) / Assertion{what,iter} / Mismatch{what,expected,got} /
Driver(Se050Error) / Timeout(&'static str)` — see
`secure/src/se050_stress/mod.rs`). Tests that loop should also
`set_iter(n)` so the `iter` field tells you which iteration failed.

---

## 5. Adding a new test

Three things, in one file under `secure/src/se050_stress/tests/`:

```rust
// 1. Write the function.
fn my_test(ctx: &mut StressCtx) -> StressResult {
    let oid = ctx.oid(0x01);                     // 0x7B5E_<id>01
    ctx.write_scratch(oid, b"hello")?;
    let mut buf = [0u8; 5];
    let n = ctx.read_scratch(oid, &mut buf)?;
    ctx.assert_eq("payload", &buf[..n], b"hello")?;
    Ok(())
}

// 2. Register it.
stress_test!(MY_TEST, "my_test_name", Tier::Safe, my_test);
```

```rust
// 3. Add one row to secure/src/se050_stress/tests/mod.rs::ALL_TESTS.
pub static ALL_TESTS: &[&StressTest] = &[
    ...
    &my_category::MY_TEST,
    ...
];
```

That's it. `make se050-stress-list` will pick it up by grep without
even building.

### Test categories (= source files)

| File | Topic |
|---|---|
| `tests/scp03.rs` | SCP03 channel: handshake freshness, MCV chain, WTX |
| `tests/userid.rs` | UserID PIN counter behaviour: lockout (always-on), reset-on-success, NVM persistence across reinit, attribute-read non-burn |
| `tests/trng.rs` | TRNG quality |
| `tests/object.rs` | Object IO: extended-Lc boundaries, churn |
| `tests/audit.rs` | Ship-blocker silicon verification + adversarial confidentiality/substitution probes (S-5, S-6, admin-passive-read, unauth-read, in-place PIN UPDATE, data-substitution residual exposure) |

To add a new category: drop a new file, add `pub mod <name>;` to
`tests/mod.rs`, append your test entries to `ALL_TESTS`.

### Things you can do in a test

`StressCtx` (in `ctx.rs`) is the API. Highlights:

- `ctx.oid(slot: u8) -> u32` — get an OID in this test's sub-range.
- `ctx.write_scratch / read_scratch / delete_scratch` — admin-gated
  scratch object IO (the runner cleans these up between tests).
- `ctx.provision_test_userid(oid, pin, max_attempts, policy)` —
  create a UserID; `AdminPolicy::{WithAdminDelete, WithoutAdminEntry}`.
- `ctx.open_user_session / open_admin_session / close_session` —
  authed sessions.
- `ctx.check_exists / delete_authed` — typed APDU wrappers.
- `ctx.assert_true / assert_eq / assert_ne / assert_sw_eq` —
  structured assertions.
- `ctx.set_iter(n)` — diagnostic tagging for loops.
- `ctx.scp03_snapshot()` — read-only copy of session keys / MCV /
  counter / active flag.
- `ctx.t1_scp03()` — split-borrow `(&mut T1State, &mut Scp03Session)`
  escape hatch for tests that need to call `apdu::*` directly with
  parameters the typed wrappers don't cover. Pass both refs to a
  single APDU call, then drop them.
- `ctx.raw_apdu(bytes, resp_buf)` — send an arbitrary SCP03-wrapped
  APDU (lowest-level escape hatch).
- `ctx.se()` — `&mut Se050` for calling driver methods like
  `random()`, `reinit()`, `pin_attempt_count_raw()`.

Need a new helper? Add a method on `StressCtx`. It's a forward-
compatible change — existing tests ignore methods they don't call.

---

## 6. Tiers

| Tier | When it runs | Use for |
|---|---|---|
| `Tier::Safe` | always | idempotent tests that leave no persistent state |
| `Tier::Destructive` | only `make se050-stress-destructive` (or `-only-`) | drives UserID counters, mutates persistent state |

The runner sweeps the test's sub-range under admin auth after every
test (PASS or FAIL), so a Destructive test that strands objects
still cleans up. But the OPT-IN classification gives you the choice:
a default `make se050-stress` skips them, both for speed and to
avoid chip-state churn during routine smoke runs.

Future tiers (e.g. `Tier::Soak`, `Tier::Adversarial`) just add a
variant to `Tier` and a matching Makefile recipe; existing tests
keep their declared tier unchanged.

---

## 7. Safety model — why stress tests can't break the wallet

- **Carve-out OID range `0x7B5E_*`.** All stress test objects live
  here. Production OIDs (`0x7B10_*`) are never touched. Other test
  ranges (`0x7B07_*`, `0x7B09_*`, `0x7B0A_*`, `0x7B0B_*`) are also
  steered clear of.
- **Stress-admin UserID at `0x7B5E_00A0`** has unlimited attempts
  and a HW-root-derived PIN
  (`hw::secret_keys::se050_admin_pin()` — the same admin key the
  production code uses; deterministic per device, stable across
  reboots/reflashes). It holds admin-delete authority over the
  whole `0x7B5E_*` range, so the runner can always clean up.
- **Top-of-run admin sweep** clears every OID in `0x7B5E_*` before
  the first test runs. A prior crashed run never poisons the next.
- **Per-test sub-range sweep** (`0x7B5E_NN00..NNFF` for test N)
  after every test. Strands from one test can't bleed into the next.
- **Inter-test `Se050::reinit()`** — full T=1' reset + fresh SCP03
  handshake between tests. SCP03 counter perturbations don't bleed.
- **Compile-time gate** — `compile_error!` rejects
  `se050-stress + mock-se` so a "stress run" can't silently turn
  into a tour of the in-RAM mock.

If you re-flash `make flash-hw-dual-se-oled-standalone` after a
stress session, the device boots straight back into the normal
wizard / unlock flow. The production `0x7B10_*` objects are
untouched.

---

## 8. Seed catalog (what's already covered)

### Original 8 tests (SCP03 mechanics + S-5/S-6 closure)

| ID | Name | Tier | What it probes |
|---|---|---|---|
| 1 | `scp03_handshake_repeat` | Safe | 8× `reinit() + establish()`; assert `s_enc` differs across handshakes |
| 2 | `scp03_apdu_burst` | Safe | 256× wrapped GET_RANDOM in one session; MCV chain integrity |
| 3 | **`scp03_response_encryption_verify`** | Safe | **S-5 silicon verifier.** Write `[0xDE; 32]`, read back through `unwrap_response` |
| 4 | `object_extended_lc_boundary` | Safe | Write+read at 1 / 8 / 32 / 254 / 255 / 256 / 257 / 512 / 1024 B — exercises extended-Lc branch in `wrap_apdu` |
| 5 | `scp03_wtx_endurance` | Safe | 100× GET_RANDOM 256 B; no T=1' WTX timeout near the 500-retry budget |
| 6 | `trng_quality_basic` | Safe | 4096 B; no all-zero / all-one 64-B block, byte-histogram χ²≤330 |
| 7 | **`userid_no_admin_delete`** | Destructive | **S-6 silicon verifier.** UserID with `admin_entry=None`; admin delete must FAIL, user self-delete OK |
| 8 | `userid_silicon_lockout` | Destructive | UserID(max=3); 3× wrong PIN; 4th attempt returns lockout SW (logs actual SW for `apdu.rs:42-54` confirmation) |

### Adversarial additions (2026-05-28, batch 2) — "challenge every assumption"

Four audit-tier tests for confidentiality / substitution claims under
the desolder-bench threat model, plus four PIN-counter persistence
tests for the NVM-durability claims the firmware relies on. Each
asserts a single silicon-level invariant; a FAIL is a hard signal that
the firmware's assumption is wrong on this chip.

| ID | Name | Tier | What it asserts |
|---|---|---|---|
| 9 | **`audit_unauth_read_refused`** | Safe | **Default-deny.** Pure-SCP03 (no UserID session) ReadBinary on a user-gated object MUST return non-9000. A FAIL means transport SCP03 silently bypasses the policy gate — every gated object leaks. |
| 10 | **`audit_admin_passive_read_refused`** | Destructive | **Confidentiality.** Admin session + read of user-PIN-gated object MUST be refused. A FAIL means anyone who recovers `se050_admin_pin()` (BHK leak) extracts `half_E` directly. Stress-harness counterpart to the feature-gated `run_admin_extract_attempt`. |
| 11 | **`audit_admin_cannot_rotate_user_pin`** | Destructive | **Substitution closure (UPDATE path).** Transport-level AND admin-session-context `WriteUserID` UPDATE on an existing user OID MUST fail (no `ALLOW_WRITE` granted to those auth contexts). A FAIL means admin can rotate user PIN in place — same outcome as the pre-S-6 DELETE+CREATE attack, via a different APDU. |
| 12 | **`audit_data_substitution_chip_level`** | Destructive | **SE050 chip-layer assertion (scoped narrowly).** Strict three-step chain: admin DELETE on a user-gated data object → transport-SCP03 WriteBinary at the freed OID with `(attacker payload, user→ALLOW_READ policy)` → user-PIN-auth READ. PASS = all three steps succeed (silicon has no CREATE-ACL on freed OIDs — the chip cannot tell who originally created an OID after it's been deleted). FAIL = silicon is *more* defensive than the chip-layer model claims; the firmware can drop a defense layer if this happens. **This test does NOT show the seed is extractable.** The systemic protection lives in firmware: the unlock path in `dual_se.rs` (`[DUAL] CRITICAL: reconstructed entropy…`) re-derives `kdf("sphincs-master", full_entropy, 0)` and compares against OPTIGA's independently-stored `master_o`. A single-SE substitution (the chain this test exercises) fails that check; a two-SE coordinated substitution defeats the check but only *installs* a chosen seed rather than recovering the original. Pre-funding tamper detection vector is the 8-word OLED measurement fingerprint. |
| P1 | **`pin_counter_resets_on_correct_pin`** | Destructive | **Counter reset on success.** 3-burn + correct-PIN success + 4-burn on `max_attempts=5`; the 2nd burn cannot complete without lockout unless the success step reset the counter. Inference-only (no attribute reads — see A1 in `docs/secure-elements/se050-silicon-findings.md` §2). Load-bearing for `Se050::remaining`'s "resets on every successful unlock" claim. |
| P2 | **`pin_counter_persists_across_reinit`** | Destructive | **NVM durability across power-cycle emulation.** 4-burn + `Se050::reinit()` + 2 individual probes; the 2nd post-reinit wrong PIN must be `AuthMethodBlocked` (counter persisted across reinit). FAIL = the 2nd post-reinit wrong is `PinIncorrect`, meaning a desolder attacker can brute-force a 4-digit PIN by power-cycling between tries. Inference-only (post-A1). |
| P3 | **`pin_lockout_persists_across_reinit`** | Destructive | **Lockout permanence.** Lock UserID(max=3) by burning 4 wrong PINs, `reinit()`, then verify wrong PIN AND correct PIN both still return blocked. A FAIL means the 10-wrong-PIN brick is recoverable by power-cycling — invariant #2 violated. |
| P4 | **`pin_attribute_read_refused_on_user_userid`** | Safe | **A1 silicon regression check (renamed 2026-05-28).** Provision a user-PIN-gated UserID with the standard two-entry policy, then call `ReadObjectAttributes` and assert it is REFUSED (driver helper returns `None`). Codifies Finding A1: B-U585I-IOT02A treats attribute reads as policy-gated, so the boot-time MCU↔SE050 attempt-counter reconcile via `pin_attempt_count_raw` is correctly skipped. FAIL = chip honoured the read → re-enable the SE050 leg of the reconcile in `Se050::pin_attempt_count_raw`. Originally `pin_attribute_read_does_not_burn`, repurposed because A1 made the original probe untestable. |
| P5 | **`pin_unlimited_no_lockout`** | Destructive | **S-7a silicon closure.** Provision a UserID via `write_userid_unlimited` (TAG_MAX_ATTEMPTS omitted per AN12413 §4.7.1.5), then burn 100 consecutive wrong PINs in a loop. EVERY attempt MUST return PinIncorrect; a post-loop correct PIN MUST still open a session (sanity that the chip didn't soft-lock). PASS = production unlimited-UserID code paths (`ADMIN_WIPE_OBJ`, `DURESS_USERID_OBJ`, E2E test admins per `mod.rs:482-510`) are silicon-validated. FAIL = a single `AuthMethodBlocked` anywhere in the loop, or post-loop correct PIN refused → silicon enforces an implicit cap and the omitted-TLV form is unsafe on this chip. (Behavioural inference only — `(max=0)` marker reads dropped per A1.) |

### Platform-SCP additions (2026-10-19, #989) — `tests/policy.rs`

Appended at the end of `ALL_TESTS` (not slotted in by tier): a test's scratch
OIDs follow its catalog index, so inserting would move every later test's
carve-out. Run 6B.23 while the die is still `SCP_NOT_REQUIRED` — under
`SCP_REQUIRED` every plain command is refused and its plain leg proves nothing
about the policy, so the test then FAILS as `6B.23 INCONCLUSIVE` rather than
passing. The two negatives send `SCP_NOT_REQUIRED` (a no-op on a factory die
even if wrongly accepted) and pass only on a policy refusal SW
(`0x6982`/`0x6985`/`0x6986`), not on a framing error.

| Name | Tier | What it asserts |
|---|---|---|
| **`policy_halfe_plain_refused`** (DVT 6B.23) | Safe | The exact production `half_E` policy (`write_binary_write_once`: user `READ\|DELETE\|REQUIRE_SM`, admin `DELETE\|REQUIRE_SM`) on a **present** carve-out object. After an SE rail power cycle, plain (no-SCP03) read / write / delete are refused and the object survives; a session-less SCP03 read is refused; an admin session cannot read; a user session reads the untouched value and cannot overwrite it; the admin path deletes it. Closes the gap the 2026-10-19 probe left (its plain `Read(ENTROPY_OBJ)` hit an absent object). |
| **`platform_scp_set_refused_without_session`** (6B.5) | Safe | `SetPlatformSCPRequest` with only platform SCP03 (no session) is refused. |
| **`platform_scp_set_refused_from_carveout_session`** (6B.5) | Safe | The same command from an ordinary UserID session is refused: only a `RESERVED_ID_PLATFORM_SCP` (`0x7FFF0207`) session may change the requirement. |

Setting and clearing the requirement itself is NOT a stress test (it is
persistent, device-level state outside the carve-out): use the UID-bound bench
tool, `make se050-platform-scp-hw ACTION=status|require|release|cycle
SE050_UID=<6B.2 hex>`.

**Highest-priority first run after the S-5/S-6 commits:** tests #3
and #7. Run individually:

```bash
make se050-stress-only-scp03_response_encryption_verify
make se050-stress-only-userid_no_admin_delete
```

If either fails, the corresponding fix has a silicon-side problem —
investigate before shipping. CLAUDE.md notes that logic-analyzer
verification of S-5 is still pending; running test #3 while
capturing SDA/SCL with a Saleae confirms the response phase is
ciphertext + 8-byte R-MAC and not the 32-byte cleartext `0xDE` run.

---

## 9. File layout

```
secure/src/se050_stress/
├── mod.rs        types, runner (run_catalog), env-filter, summary printer
├── ctx.rs        StressCtx + helper API (the surface tests are written against)
├── oid.rs        carve-out layout + admin sweep machinery
├── registry.rs   stress_test! macro definition
└── tests/
    ├── mod.rs    declares categories + ALL_TESTS (one row per test)
    ├── scp03.rs  SCP03-focused tests
    ├── userid.rs UserID/PIN tests
    ├── trng.rs   TRNG quality
    ├── object.rs object IO
    └── audit.rs  ship-blocker silicon verifiers
```

Plus tiny touches elsewhere:

| File | Change |
|---|---|
| `secure/Cargo.toml` | `se050-stress = ["se050"]` feature |
| `secure/src/main.rs` | `mod se050_stress;` + dispatch block + `compile_error!` gate |
| `secure/src/se050/mod.rs` | `Se050::reinit()` + `pub(crate) fn t1_scp03_mut()` |
| `Makefile` | 4 recipes (run, destructive, single, list) + `SE050_STRESS_RUN` shell helper |

---

## 10. Internals worth knowing for future LLMs / debuggers

### Why `t1_scp03_mut()` is one method, not two

`Se050.t1: T1State` and `Se050.scp03: Scp03Session` are two distinct
fields. The borrow checker permits a "split borrow" when you write
`(&mut self.t1, &mut self.scp03)` inside the impl — it sees the
fields as disjoint. But if you expose two separate accessor methods
(`t1_mut()` and `scp03_mut()`), each takes `&mut self`, and the
borrow checker cannot see the disjoint structure across method
boundaries → E0499. So we expose a single accessor that returns
both refs at once. Callers do `let (t1, scp03) = ctx.t1_scp03();`
and use both within the same lifetime.

This pattern is repeated throughout `ctx.rs` and `oid.rs` — anywhere
that calls an `apdu::*` function (which takes both refs in its
signature). If you add a new typed wrapper or helper, follow the
same shape: grab the split borrow inside the unsafe block, call the
APDU, drop the borrow before re-acquiring for the next call.

### Why `option_env!` needs a cache-bust

`option_env!("SE050_STRESS_ONLY")` reads its env var at compile time
of the secure crate. Cargo fingerprints builds on RUSTFLAGS, source
file mtimes, features, and `cargo:rerun-if-env-changed=...` from
build scripts — but **not** env vars read by `option_env!` in regular
source. So changing `SE050_STRESS_ONLY` alone would silently reuse a
stale binary. Fix: the Makefile injects
`--cfg=stress_build="$(date +%s)"` into RUSTFLAGS for the recipes
that change selection state. RUSTFLAGS IS fingerprinted → cargo
rebuilds. The cfg itself is never queried in source; it's just a
cache-bust marker.

### Why the build needs `usb`

`secure/src/nsc/cmd_fw_begin.rs:87` and `cmd_fw_commit.rs:185`
reference `crate::hw::usb_hw::*` inside a `#[cfg(feature =
"stm32u585")]` block — but the `usb_hw` module itself is gated
behind `feature = "usb"`. So any `stm32u585` build without `usb`
fails to resolve those paths. The stress recipes include `usb` in
the feature list for this reason. (Existing `se050-*-e2e` recipes
that don't include `usb` likely also fail in the current tree;
that's a separate latent issue.)

### `probe-rs` semihosting capture

The runner emits everything via the `secure_log!` macro
(`secure/src/main.rs:22-45`), which compiles to `cortex_m_semi-
hosting::hprintln!` when `debug-log` is enabled. On real STM32U585
the macro checks `DHCSR.C_DEBUGEN` first so the BKPT is skipped when
no debugger is attached (safe to power-cycle standalone). `probe-rs
run --chip STM32U585AIIx <elf>` captures the semihosting stream on
stdout. Recipes `tee` it to a tempfile, grep `=== SUMMARY:`, and
extract the `N FAIL` count for the exit code.

---

## 11. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `make se050-stress` halts before `=== SUMMARY:` line | timeout (recipes use `timeout 600`); test is slower than 10 min, or a test deadlocked. Run single-test to localise. |
| `FATAL: Se050::init() failed` | SE050 not responding — chip wiring, power, prior init left T=1' in a weird state. Power-cycle the board (USB unplug+replug). |
| `sweep: se050_admin_pin unavailable` | `hw::secret_keys::se050_admin_pin()` failed — OTP not provisioned, or `otp-hardcoded-master-key` feature missing. The recipes include this feature. |
| `compile_error: 'se050-stress' requires real SE050 silicon` | you tried to build with `mock-se`. Drop it. |
| `usb_hw` not found | drop `usb` from your custom feature set was missed. The stock recipes include it. |
| Same binary keeps loading even after env var change | cache-bust cfg got dropped from RUSTFLAGS. Use the stock recipes; don't override RUSTFLAGS. |
| `make se050-stress-list` shows raw `stress_test!(...)` lines | regex didn't match — name contained chars outside `[A-Z0-9_]+`, or multi-line invocation. Use single-line. |
| All tests fail with `Se050Error::Scp03` | SCP03 keys mismatch — the firmware can't open a session with the chip's keyset. Likely the SE050 was paired to a different firmware version. Re-flash `make flash-hw-dual-se-oled-standalone` and re-pair. |
| `scp03_response_encryption_verify` fails | S-5 fix has a silicon-side issue — investigate `secure/src/se050/apdu.rs:296-310` and `secure/src/se050/scp03.rs:459` (`unwrap_response`). **Before shipping.** |
| `userid_no_admin_delete` fails | S-6 fix is not enforced on this silicon — admin successfully deleted a UserID with no admin policy entry. Audit `secure/src/se050/apdu.rs:465-492` (`write_userid`) for the admin-entry handling. **Before shipping.** |
| `userid_silicon_lockout` reports unexpected SW | the lockout SW inferred at `apdu.rs:42-54` doesn't match silicon. Check the logged SW and update the `AuthMethodBlocked` mapping. |

---

## 12. Future extensions

The structure is deliberately not coupled to anything SE050-specific
in the runner — the chip handle is just a type parameter.

- **OPTIGA stress harness:** copy `se050_stress/` to `optiga_stress/`,
  swap `Se050` for `OptigaTrustM`, swap the apdu/shield helpers.
- **Dual-SE stress harness:** same approach with `DualSecureElement`.
- **Long-soak mode:** `SE050_STRESS_REPEAT=N` outer-loops the catalog.
  Already plumbed; just set the env var.
- **Power-cycle between tests:** SE050 has no STM32-driven VCC line on
  this board. `T1State::interface_reset()` + `Se050::reinit()` is the
  closest approximation. If a future board revision adds a power-gate,
  plumb it through a new `StressCtx::power_cycle()`.
- **CI integration:** the recipes already exit 0/1 cleanly. A
  board-attached self-hosted runner could call `make se050-stress`
  per commit. Provisioning the runner is out of scope here.

---

## 13. Quick-start cheat-sheet

```bash
# One-time setup (sets TZ option bytes).
make flash-hw-dual-se-oled-standalone

# Then, any time:
make se050-stress                                              # safe smoke run
make se050-stress-list                                         # see catalog
make se050-stress-only-scp03_response_encryption_verify        # single test
make se050-stress-destructive                                  # full coverage

# Add a test:
$EDITOR secure/src/se050_stress/tests/scp03.rs   # write fn + stress_test!
$EDITOR secure/src/se050_stress/tests/mod.rs     # one row in ALL_TESTS
make se050-stress                                # done

# Go back to normal wallet:
make flash-hw-dual-se-oled-standalone
```

---

## 14. First on-silicon results (2026-05-28)

First end-to-end real-hardware run: 6 PASS / 11 FAIL. The 6 PASS
silicon-verify the load-bearing confidentiality claims (admin-passive-
read refused, unauth-read refused, chip-layer substitution chain
behaves as documented, S-5 round-trip works). The 11 FAIL split into
(a) three real silicon behaviors the codebase had wrong assumptions
about — none breach confidentiality, the worst is an accepted DoS
vector — and (b) test-wrapper bugs that need fixing to make future
runs report cleanly. Full analysis + action items: **[docs/se050-
silicon-findings.md](se050-silicon-findings.md)**.
