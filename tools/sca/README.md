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

Three **single-fault models** are swept: instruction-skip, dest-register-stuck-at-`0`,
dest-register-stuck-at-`0xFFFFFFFF`. The `[skip]` sweep is the contract test —
`fi::check_true`'s doc claims *skip*-resistance — so a `[skip]` hit inside `fi.rs`
exits the script non-zero (a regression). `[stuck-at-FF]` hits inside `fi.rs` are
printed as **INFO, not a regression**: a stuck-at on a result register defeats *any*
bool-returning function (the final `mov r0, r4` / a `movs r0, #0`), which `check_true`
can't claim to prevent — the mitigation for that class is a sentinel-encoded return
(see F-2 below). Current result: `make fi` exits 0 (zero `[skip]` hits in `fi.rs`;
the lone `[skip]` "exploitable" is at instr ~5 in the harness wrapper; `[stuck-at-FF]`
flags 3 `fi.rs` result-register positions as INFO). For multi-fault / two-fault,
extend the nested loops. Each hit prints its faulted PC + a verbose-emulator repro.

### C10 verify-before-release gate fault sweep — `fault_sweep_c10_verify.py`

Sweeps the three single-fault models over `sca_c10_verify_release` in the target
ELF — a **structural mirror** of
[`secure/src/crypto.rs::c10_sign_verified_with_progress`](../../secure/src/crypto.rs)
(it is *not* a `#[path]` include — `crypto.rs` pulls in `pqsigner-domain`,
`secure_element`, the BIP-39 bridge, … too much for a leaf test crate; the mirror
carries a `KEEP IN SYNC` comment and tracks the `crypto.rs` body line-for-line,
including the F-1 fix — it now passes `|| core::hint::black_box(v)`):

```
sig = sk.sign_with_progress(...)                       # stubbed: sca_c10_sign_stub()
fi::wait_random()
v   = sphincs_c10::verify(...)                          # stubbed: sca_c10_verify_stub(want_pass)
if !fi::check_true(|| core::hint::black_box(v)) { Err } # ← the gate (F-1 fix applied)
Ok(sig)
```

`sign` and `verify` are stubbed because this target probes the *release gate*,
not the SPHINCS+ math (which gets its own target — see Roadmap). The harness
calls the gate with `want_pass = 0` (the signature did **not** verify) and any
run that returns non-zero ("would release the signature") is a bypass: a glitch
made the firmware emit an *unverified* C10 signature. Faults in the sign/verify
stubs are reported separately (out of scope here). `make c10` exits 0: the F-1
fix is in (verified by disasm — `check_true` keeps its full four-decision-point
shape here), and the remaining handful of gate bypasses are the **F-2** residual
(the `if !guard() { err }` call-site glue), documented below; the harness shouts
loudly if a bypass ever lands at a *decision point* inside `check_true` (which
would mean the F-1 collapse came back).

## Layout

```
tools/sca/
  README.md                  — this file
  Makefile                   — `make fi`/`c10`/`pin` (fast fault sweeps), `make kdf` (lascar leakage),
                             —   `make sweeps`, `make build`/`build-kdf`/`doctor`/`clean`
  fault_sweep_fi.py          — FI-guard fault sweep (fi.rs: check_true / wait_random)
  fault_sweep_c10_verify.py  — C10 verify-before-release gate fault sweep
  fault_sweep_pin.py         — PIN-attempt pre-commit gate fault sweep (gated_unlock + pin_attempts_bump)
  leakage_kdf.py             — lascar leakage analysis: AES-256 / AES-GCM entropy wrap + a leaky-S-box positive control
  fi_target/                 — standalone thumbv8m crate: the fault-sweep targets, in one ELF (sca-fi-target)
    src/main.rs              —   #[path]-includes ../../../../secure/src/fi.rs verbatim (sca_fi_*),
                             —   + structural mirrors of crypto.rs's verify-before-release gate (sca_c10_*)
                             —     and gated_unlock + pin_attempts_bump (sca_pin_*, with a fake page-124 counter),
                             —   + #[no_mangle] wrappers, an rng stub, and #[used] keep-statics
    Cargo.toml / build.rs / memory.x  — own [workspace] (detached); places memory.x for cortex-m-rt's link.x
  kdf_target/                — standalone thumbv8m crate (own [workspace]): the leakage targets, in ELF sca-kdf-target —
    src/main.rs              —   sca_leaky_sbox (out[i]=SBOX[in[i]^KEY[i]], the positive control),
                             —   sca_aes256_encrypt_block (the `aes` crate's AES-256, fixed key), and
                             —   sca_aesgcm_wrap (a structural mirror of pqsigner_domain::encrypt_entropy_blob's
                             —     AES-256-GCM wrap; uses the same crates.io deps — aes-gcm 0.10 / aes 0.8 / sha2 0.10)
```

## Roadmap — targets not yet wired

Each needs a `thumbv8m` (or host-x64) ELF of the code under test, plus stubs for
whatever hardware it touches. Pattern: a `<name>_target/` crate that
`#[path]`-includes or path-depends on the relevant **standalone workspace
crate** (`sphincs-c10`, `pqsigner-domain`, …) and re-exports the function under
stable C symbols, then a `rainbow`/`lascar` harness.

- **C10 verify-before-release — full version.** The *gate* is wired
  (`fault_sweep_c10_verify.py`, with `sign`/`verify` stubbed). The remaining
  work is the *real* one: build the `sphincs-c10` crate (software SHA-256 path)
  into a thumb ELF and sweep faults over an actual `sk.sign(...)` →
  `sphincs_c10::verify(...)` round-trip — verify of one C10 sig is a few
  thousand SHA-256 blocks, slow but emulable if you restrict the sweep window to
  the post-`verify` gate region rather than the whole call. Win condition
  beyond the gate: no single skip makes a *bad* signature `verify()` as good.
- ~~**Tier-1 KDF leakage CPA**~~ — **DONE-ish** (`leakage_kdf.py` — see "### Leakage
  analysis" below). It's a TVLA + CPA on the `mem_address` channel of the AES the
  entropy-blob wrap uses (`pqsigner-domain`'s `encrypt_entropy_blob`, mirrored)
  plus a leaky-S-box positive control: the toy leaks (TVLA spike, CPA recovers
  16/16 key bytes — pipeline verified), the real AES / AES-GCM-wrap are *flat* on
  `mem_address` (bitsliced "soft" AES → no T-table / cache mem-address channel).
  *Not yet done*: a `lascar` CPA against the actual **Tier-1 KDF** primitive
  (`hw::saes_cmac::cmac_dhuk`) — that's the *hardware* SAES (not emulated) on
  device; a software-CMAC-AES reference could be emulated, but at RDP0 the DHUK is
  the ST-substituted constant anyway (`docs/work-todo.md §7`), so it'd be a
  code-leakage test, not a key recovery. Also not done: SPA/template/single-trace
  analysis of the wrap key/keystream during the one-shot boot-time wrap (needs a
  profiling setup, not fixed-vs-random TVLA), and register-HW-channel DPA of the
  AES round keys (needs a scope on the running device — the emulated `register`
  channel is unusable here: rainbow's per-instruction `reg_read` of every
  capstone-named dest reg hits an invalid id inside the bitsliced AES on unicorn
  2.1.x; `mem_address` works universally and is the meaningful "is it
  constant-time" channel anyway).
- ~~**PIN pre-commit skip sweep**~~ — **DONE** (`fault_sweep_pin.py` — a structural
  mirror of `nsc::gated_unlock`'s `stm32u585` branch + `hw::flash::pin_attempts_bump`,
  with the fake page-124 counter + `se.unlock` stubbed and the real `fi::*`
  `#[path]`-included; 3 fault models). Surfaced **F-3** (the `se.unlock` Ok/Err
  discrimination is a plain `match`, single-fault-defeatable — but the SE does the
  PIN compare in silicon, so it's a robustness gap not a seed extraction) and **F-4**
  (the page-124 attempt isn't always charged under a single fault — F-2-class
  call-glue residual; impact ≤10 free guesses = a 1-in-10^6 lottery). Both
  documented in §Findings; `make pin` exits 0 (they're residuals, not regressions).
  *(historical, pre-implementation note follows:)* — sweep skips over `nsc::gated_unlock`'s
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

## Findings

### F-1 — `crypto.rs` verify-before-release gate: `check_true(|| v)` collapsed under CSE — **FIXED** (single instruction-skip released an unverified C10 signature, in emulation)

`secure/src/crypto.rs::c10_sign_verified_with_progress` did:

```rust
let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig);
if !crate::fi::check_true(|| v) { return Err(()); }   // ← the bug
Ok(sig)
```

`fi::check_true`'s contract (per its own doc) is that a glitch must skip **all
four** decision points (first `cond()`, second `cond()`, sentinel commit,
sentinel re-check) to flip a `false` verdict into a `true` return. But `cond`
here was the trivial closure `|| v` over a pre-computed `bool` local, so LLVM
common-subexpression-eliminated the two `cond()` calls into one `ldrb`, proved
`v1 == v2`, and collapsed the `&& v1 && v2` re-check — the compiled
`check_true::<|| v>` had **one** branch (`cbz` on the single loaded byte), not
four. `fault_sweep_c10_verify.py` showed **5 distinct single instruction-skips**
making the gate "release the signature" with `verify` forced to fail: skip the
`ldrb`/`cbz` inside the collapsed `check_true`, skip the `bl check_true` call,
skip the `cbz r0` post-check, or skip the `movs r0, #0` so the non-zero
`FAIL_SENTINEL` lingered in the return register.

**Fix applied** (`crypto.rs` + the harness mirror): `if !crate::fi::check_true(|| core::hint::black_box(v))`.
The `black_box` forces `v` to be re-materialised opaquely on each evaluation, so
LLVM can't CSE the two `cond()` calls — `check_true` regains its full
four-decision-point shape at this call site (verified by disassembling the built
ELF: two distinct loads of `v`, `cbz` on v1 + `cmp #0` on v2 + `cmp #OK_SENTINEL`
on the re-read sentinel). Cost: one extra `ldrb` per check. The
even-stronger option — re-running `sphincs_c10::verify(...)` inside the closure,
per `fi::check_true`'s doc example — also defends a data fault on `v`'s storage,
at the cost of a second multi-second verify; not adopted (keeps the single-verify
design). `fault_sweep_c10_verify.py` now reports the F-1 collapse gone (and is
the regression test if it ever comes back). **Audit note:** the same
`check_true(|| <trivial local>)` smell should be checked at every other
`check_true` call site in the tree — pass `|| core::hint::black_box(x)` or a
closure that's genuinely opaque (a real `bl`).

**Scope caveat (still applies):** emulated single-fault against a *structural
mirror* of `crypto.rs` (it can't be cheaply `#[path]`-included), with
`sign`/`verify` stubbed. The mirror tracks `crypto.rs` line-for-line — confirm
against the real binary before treating it as exhaustive.

### F-2 — verify-before-release *call-site glue* is single-fault-defeatable (residual; needs a design decision)

Even with the F-1 fix, ~3 single instruction-skips (and a few more under
stuck-at-`0xFFFFFFFF`) still make `sca_c10_verify_release` "release the
signature": skip the `bl check_true` call (→ a stale stack pointer in `r0` looks
truthy to the caller), skip the `cbz r0` post-check that branches to `Err`, skip
the prologue load of `v` into `check_true`'s frame, or stuck-at-FF a result
register. These aren't a `check_true` failure — they're the inherent weakness of
the `if !guard() { return err }` idiom: `check_true` hardens *its own* internal
check, but can't stop the caller from skipping the call to it, the branch on its
result, or replacing its boolean return with a glitched register value. The
textbook mitigation is a **sentinel-encoded return**: `c10_sign_verified` returns
`OK_SENTINEL`/`FAIL_SENTINEL` (not a 0/1 `Result`) and the caller compares
against `OK_SENTINEL` — then "skip the `bl`" yields garbage `≠ OK_SENTINEL`
(error path), and stuck-at-FF likewise. Even that isn't single-fault-proof
(it raises the cost, doesn't eliminate); the realistic decision is "add a
sentinel-encoded return + caller re-check" vs "accept this as residual,
mitigated by the silicon's own FI countermeasures + the `wait_random` jitter".
**Maintainer's call.** `make c10` exits 0 with this printed as a known residual;
it only fails (loudly) if a bypass moves into `check_true`'s decision-point region
(= an F-1 regression).

### F-3 — `gated_unlock`'s SE-unlock Ok/Err discrimination is single-fault-defeatable (residual)

`secure/src/nsc/mod.rs::gated_unlock` does `match se.unlock(pin) { Ok(master) => …, Err(e) => Err(e) }`
— a plain `match`, not wrapped in `fi::check_true` / a sentinel. `fault_sweep_pin.py`
shows a single instruction-skip (or stuck-at-FF) on that discriminant makes the
gate return `Ok` on a wrong PIN — the wallet *thinks* it unlocked. **But** the real
`se.unlock` does the PIN compare in *SE silicon* (CLAUDE.md invariant #2), so a
wrong PIN genuinely returns `Err`; the "master" the wallet would then read is the
`Err`-variant's union payload reinterpreted as the 32-byte `Ok` value — garbage,
not the seed. So it's a **robustness gap** (the wallet proceeds as if unlocked,
likely failing downstream with the garbage), not a seed extraction. Mitigation:
wrap the SE-result discrimination in `fi::check_true` / have `se.unlock` return a
sentinel the caller positively compares; or accept (the SE-silicon PIN gate + the
10-attempt cap are the real defenses). `make pin` exits 0 (this is a residual).

### F-4 — the page-124 attempt isn't always charged under a single fault (residual)

`gated_unlock`'s pre-commit (`if pin_attempts_bump().is_err() { return InternalError }`,
then `se.unlock`) is meant to make every wrong-PIN attempt cost a charged counter
slot. `fault_sweep_pin.py` shows a single fault that skips the `bl pin_attempts_bump`
call (from `gated_unlock`), or skips `pin_attempts_bump`'s `write_quadword_verified`
call (its `post != pre+1` re-check then makes it return `Err`, so `gated_unlock`
correctly *refuses* with `InternalError` — but the counter didn't advance), leaves
the wrong attempt uncharged → a "free guess". This is the same `if !guard() { err }`
/ call-glue residual as **F-2**: `pin_attempts_bump`'s internal re-checks
(`post != pre+1`, `check_true(|| pin_attempts_read() == pre+1)`) harden the bump's
*innards* — and that internal invariant (`Ok` ⇒ counter advanced) holds against
single instruction-skips in the sweep — but can't stop the caller skipping the whole
`bl bump`, or a glitched flash-write being correctly-refused-but-uncharged. Impact:
≤10 free guesses = a 1-in-10⁶-per-try lottery, still capped at 10 (vs the intended
10 *charged* attempts). Mitigation: a sentinel-encoded bump result the caller
positively compares (and/or charge-on-refuse where flash permits); or accept. The
`make pin` "pin_attempts_bump invariant check" only fails on a `[skip]`-model
violation of the bump's internal invariant (none currently); stuck-at-FF on the
bump's Ok/Err return slot produces an "Ok"-looking value, the same
result-register-corruption class as the `fi::check_true` stuck-at-FF INFO above —
reported, not a regression.

## Leakage analysis — `leakage_kdf.py` (first lascar target)

`make -C tools/sca kdf` builds the `sca-kdf-target` ELF and runs a `lascar` TVLA
(Welch fixed-vs-random t-test) + CPA on the `mem_address` channel of three
subjects. (The `register` channel is unusable here — rainbow's per-instruction
`reg_read` of every capstone-named dest reg hits an invalid id inside the
bitsliced AES on unicorn 2.1.x — and `mem_address` is the channel that matters
for "is it constant-time?" anyway: a *data-dependent memory address* is a
T-table / cache side channel; a data-dependent *value* in a register is
unavoidable in any AES/GCM and needs a scope on the device, not an emulated
fixed-vs-random test, to characterise.)

| Subject | What | Result |
|---|---|---|
| `sca_leaky_sbox` | positive control: `out[i] = AES_SBOX[in[i] ^ KEY[i]]` (a deliberate table leak) | TVLA `max\|t\| ≈ 24` at the `SBOX[]` load address → **leakage detected**; CPA over `HW(&SBOX + (in[i] ^ guess))` recovers **16/16** key bytes (the FIPS-197 vector key) → **lascar pipeline verified, both ways** |
| `sca_aes256_encrypt_block` | `AES-256-ENC(fixed_key, plaintext)` via the `aes` crate (the AES `pqsigner-domain`'s entropy wrap uses) | TVLA `max\|t\| = 0.00` over 600 traces → **flat**: the bitsliced "soft" backend on thumbv8m is constant-time w.r.t. its plaintext — no data-dependent memory accesses → no T-table / cache mem-address side channel |
| `sca_aesgcm_wrap` | structural mirror of `pqsigner_domain::encrypt_entropy_blob`'s AES-256-GCM wrap of the 32-B entropy under a fixed key+nonce | TVLA `max\|t\| = 0.00` over 600 traces → **flat**: no entropy-dependent memory access (constant-time AES + constant-time GHASH) |

No findings — the production AES / AES-GCM-wrap path is clean on the `mem_address`
channel in emulation; `make kdf` exits 0. **Caveats:** (1) emulation only — the
analog power/EM leakage of the running silicon, and register-HW DPA of the AES
round keys, still need a scope (ChipWhisperer / PicoScope / Scaffold — see the
`rainbow`/`lascar` skills and the earlier discussion); (2) the *deployed* entropy
wrap is a *single* encryption with a *fixed* nonce, so there's no
attacker-chosen-input DPA surface against it anyway — the residual is the
single-trace leakage of the wrap key / keystream during that one boot-time
operation (an SPA/template attack), which a profiling setup on the device would
probe, not this fixed-vs-random TVLA; (3) `sca_aesgcm_wrap` is a *mirror* of
`encrypt_entropy_blob` (not a `#[path]` include — `pqsigner-domain` uses
`{ workspace = true }` deps and can't be path-dep'd from a detached workspace) —
it uses the *same* crates.io deps (`aes-gcm` 0.10 / `aes` 0.8 / `sha2` 0.10), so
the AES's leakage behaviour matches; KEEP IN SYNC if `encrypt_entropy_blob`'s
shape changes (e.g. a different AEAD); (4) 600 traces is a first-pass "flat"
claim — a real assurance argument would want more.
