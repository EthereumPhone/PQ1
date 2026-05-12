# `tools/sca/` — side-channel & fault-injection self-tests

Emulation-based pre-audit testing of PQSigner's security-critical code paths,
driven by the **Ledger Donjon** toolchain (`rainbow` for emulation + fault
simulation, `lascar` for side-channel analysis) through the **`donjon-sca`** CLI.

No hardware, oscilloscope, or glitcher needed — `rainbow` runs the code under
Unicorn, records execution traces, and injects faults at chosen instruction
indices. This catches the bugs that are *our* fault (a non-constant-time
compare, a secret-indexed lookup, a guard that a single instruction-skip
defeats) before the professional audit and before any lab time. It does **not**
replace a real bench — it tests *algorithmic* properties of our code, not the
STM32U585's analog leakage or its silicon countermeasures.

## Prerequisites

The `donjon-sca` CLI on your `PATH`. Install it (and the rainbow/lascar
toolchain it manages) once:

```bash
git clone https://github.com/Nicola-Ceornea/my-claude-skills.git ~/repos/my-claude-skills
~/repos/my-claude-skills/setup.sh
donjon-sca doctor          # should be all-green
```

`donjon-sca` also ships the `rainbow` and `lascar` Claude Code skills, so Claude
can drive this directory too.

## Quick start

```bash
make -C tools/sca fi        # build the fault-injection target ELF, then run the FI-guard sweep
# or step by step:
make -C tools/sca build     # cargo build --release --target thumbv8m.main-none-eabi (the sca-fi-target ELF)
make -C tools/sca doctor    # donjon-sca doctor
donjon-sca run tools/sca/fault_sweep_fi.py    # run a harness directly
```

## What's wired up now

### FI-guard fault sweep — `fault_sweep_fi.py` + `fi_target/`

Sweeps a single **instruction-skip** fault over every instruction of PQSigner's
fault-injection countermeasures in [`secure/src/fi.rs`](../../secure/src/fi.rs)
— `fi::check_true` (the double-evaluate-then-sentinel-then-recheck verdict
guard used at every verify-before-release site) and `fi::wait_random` (the
Trezor-port `i + j == wait` glitch-sentinel delay loop) — and classifies each
skip as **exploitable** (made `check_true(false)` return a non-zero / "true"
value to its caller), **crash** (invalid instruction), **hang** (caught — landed
in `halt_on_glitch`'s endless `wfe` loop, or broke a loop's termination), or
**no-effect** (returned the correct `false`).

`fi_target/` is a tiny standalone `thumbv8m.main-none-eabi` crate that
**`#[path]`-includes `secure/src/fi.rs` verbatim** (so the test always runs
against the exact production source — if `fi.rs` grows a new dependency, this
build breaks loudly) and re-exports its functions under stable `#[no_mangle]`
C symbols. Its one hardware dependency, the `crate::rng::byte()` call inside
`wait_random`, is satisfied by a small fixed-value stub (keeps the random-delay
loop short so sweeps are fast; the loop's *invariant checks* — what we're
probing — are unchanged). `#[used]` statics keep the exported symbols from being
garbage-collected by cortex-m-rt's `--gc-sections` link.

**Current result:** *passes* — no single instruction-skip inside `fi.rs` code
flips a clean `false` verdict into a `true` return. (The lone "exploitable"
index the sweep reports is at instruction ~5, inside this harness's own
`sca_fi_check_true` wrapper / the synthetic boolean source — i.e. you can glitch
the boolean *fed into* `check_true`, which `check_true` does not claim to
prevent; its job is hardening the check/commit/recheck/return path, not the
computation that produces the boolean. In production that boolean comes from
`sphincs_c10::verify(...)`, which is itself a separate glitch surface.)
Disassembling the built `fi::check_true` confirms the optimizer keeps the
defense shape `fi.rs`'s doc promises: two distinct `bl sca_fi_cond` (the
re-evaluation), two separate `v1`/`v2` registers, and three decision points
guarding the `true` return (`cbz` on v1, `cmp #0` on v2, `cmp #OK_SENTINEL` on
the re-read sentinel) — so the "passes" is the defense holding, not the test
under-probing.

Caveats on the breakdown numbers: most of the swept positions report **crash**
(`fault_skip` produced an invalid Thumb encoding) — that's weakly informative
for *security*: it means a naive skip can't get useful state there, not that the
*defense* held. The defensive evidence is the **no-effect** positions (skip
landed somewhere harmless, correct `false` still returned) plus the few **hang**
positions (the glitch was caught by `halt_on_glitch`'s endless `wfe`). Also: the
"passes" result depends on the *toolchain* (`rustc`, `cortex-m-rt`, opt-level),
not just crate versions — `Cargo.lock` pins the latter; if you ever promote this
to a CI gate, add a `rust-toolchain.toml` in `fi_target/` to pin the compiler.

> **Methodology note worth keeping in mind.** `check_true`'s defense ("a glitch
> must skip ALL FOUR decision points to turn false→true") only holds if the
> closure passed to it is *opaque to the optimizer*. An earlier version of this
> harness used `check_true(|| want != 0)`; LLVM common-subexpression-eliminated
> the two `cond()` evaluations into one load and collapsed the `&& v1 && v2`
> chain, leaving a single skippable `cbz` — a false positive. The fix (see
> `fi_target/src/main.rs`): the boolean source is an `#[inline(never)]` fn
> wrapped in `core::hint::black_box`, so the double-eval and the `&&` re-checks
> survive — matching the production codegen where `cond` is a real `bl verify`.
> If you add new fault targets, give them realistic, un-foldable inputs.

This is **single-fault, instruction-skip only**. For stuck-at faults
(`rainbow.fault_models.fault_stuck_at`) or multi-fault sweeps (nested loops),
extend `fault_sweep_fi.py` — its structure makes that a small change. For each
"exploitable" index the harness prints the faulted PC and a copy-paste
`donjon-sca python -c "..."` repro using a verbose emulator (`Print.Code |
Print.Faults`).

## Layout

```
tools/sca/
  README.md              — this file
  Makefile               — `make fi` / `make build` / `make doctor` / `make clean`
  fault_sweep_fi.py      — the FI-guard fault sweep (a rainbow harness)
  fi_target/             — standalone thumbv8m crate: re-exports secure/src/fi.rs under C symbols
    Cargo.toml           —   (its own [workspace] — detached from the PQSigner workspace)
    build.rs             —   places memory.x for cortex-m-rt's link.x
    memory.x             —   arbitrary conventional STM32-ish layout
    src/main.rs          —   #[path]-includes ../../../../secure/src/fi.rs + #[no_mangle] wrappers + rng stub
```

## Roadmap — targets not yet wired

Each needs a `thumbv8m` (or host-x64) ELF of the code under test, plus stubs for
whatever hardware it touches. Pattern: a `<name>_target/` crate that
`#[path]`-includes or path-depends on the relevant **standalone workspace
crate** (`sphincs-c10`, `pqsigner-domain`, …) and re-exports the function under
stable C symbols, then a `rainbow`/`lascar` harness.

- **C10 verify-before-release fault sweep** — sweep skips over
  `crypto::c10_sign_verified*`'s FI-gated guard (the `OK_SENTINEL` /
  `FAIL_SENTINEL` double-checked verify result around `sphincs_c10::verify`).
  Build the `sphincs-c10` crate (software SHA-256 path) into a thumb ELF; the
  verify of one C10 signature is a few thousand SHA-256 blocks — slow but
  tractable to emulate. Win condition: no single skip makes a *bad* signature
  verify, and no single skip makes `c10_sign_verified` emit an *unverified*
  signature.
- **Tier-1 KDF leakage CPA** — emulate `hw::saes_cmac::cmac_dhuk` /
  `pqsigner-domain`'s KDF over many label/counter inputs with
  `TraceConfig(register=HammingWeight(), mem_address=HammingWeight())`, stub the
  SAES (or test the software AES reference), and run `lascar` CPA over the
  DHUK-derived subkey bytes. Tells you whether the *software* KDF wiring leaks;
  the silicon SAES's own leakage still needs a scope. (At RDP0 the DHUK is the
  ST-substituted constant anyway — see `docs/work-todo.md §7` / the per-die DHUK
  notes — so this is a code-leakage test, not a key-recovery one.)
- **PIN pre-commit skip sweep** — sweep skips over `nsc::gated_unlock`'s
  page-124 attempt-counter pre-commit and `hw::flash::pin_attempts_bump`'s
  post-bump delay + double-readback (`fi::check_true`-gated). Win condition: no
  single skip lets a wrong-PIN attempt proceed without the counter advancing.
- **`fault_sweep_fi.py` extensions** — stuck-at faults, two-fault sweeps, and a
  *leakage* pass over the FI guards themselves (does `wait_random`'s loop count
  leak via timing? — emulated traces are jitter-free, so this would be a
  structural check, not a timing one).

Separately, for *on-silicon* work later (ChipWhisperer / Scaffold / a crowbar
rig — not this emulation path): a `sca-trigger` firmware feature flag that
toggles a GPIO around `c10_sign_verified*` / `cmac_dhuk` / `gated_unlock`, gated
OFF in production CI alongside `debug-log`. Tracked separately; not needed for
anything in this directory.

## See also

- The `rainbow` and `lascar` Claude Code skills (installed by `donjon-sca`) —
  full API, recipes, gotchas.
- `~/.local/share/donjon-sca/rainbow/examples/` — upstream worked examples
  (`CortexM_AES/`, `HW_analysis/pin_compare.py`, `pin_fault.py` — the last is
  the model `fault_sweep_fi.py` is built on).
- `README.md` (repo root) "Security self-testing" angle; the threat model and
  shipping checklist there.
