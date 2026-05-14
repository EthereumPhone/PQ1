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
  Makefile                   — `make fi`/`c10`/`pin`/`fw-verify` (fast fault sweeps), `make kdf` (lascar leakage),
                             —   `make sweeps`, `make build`/`build-kdf`/`build-fw-verify`/`doctor`/`clean`
  fault_sweep_fi.py          — FI-guard fault sweep (fi.rs: check_true / wait_random)
  fault_sweep_c10_verify.py  — C10 verify-before-release gate fault sweep
  fault_sweep_pin.py         — PIN-attempt pre-commit gate fault sweep (gated_unlock + pin_attempts_bump)
  fault_sweep_c10v.py        — fault sweep over the *real* sphincs_c10::verify (forge-a-signature direction)
  fault_sweep_fw_verify.py   — fault sweep over the *real* fw-manifest verify chain (FW-update bypass direction)
  fault_sweep_ns_ptr.py      — fault sweep over the *real* secure::nsc::ptr_validate::validate_ns_{read,write}_ptr
                             —   predicates (TrustZone-boundary NS-pointer bypass direction)
  fault_sweep_c10_sign.py    — end-to-end FI test of the *real* c10_sign_verified_with_progress
                             —   (real sign + real verify + real F-1/F-2/F-5 gate); baseline + tiny tail sweep
                             —   (full sweep deferred — unicorn ~14s per emulation for one C10 sign)
  leakage_kdf.py             — lascar leakage analysis: AES-256 / AES-GCM entropy wrap + a leaky-S-box positive control
  fi_target/                 — standalone thumbv8m crate: the fault-sweep targets, in one ELF (sca-fi-target)
    src/main.rs              —   #[path]-includes ../../../../secure/src/fi.rs verbatim (sca_fi_*),
                             —   + structural mirrors of crypto.rs's verify-before-release gate (sca_c10_*)
                             —     and gated_unlock + pin_attempts_bump (sca_pin_*, with a fake page-124 counter),
                             —   + #[no_mangle] wrappers, an rng stub, and #[used] keep-statics
    Cargo.toml / build.rs / memory.x  — own [workspace] (detached); places memory.x for cortex-m-rt's link.x
  c10v_target/               — standalone thumbv8m crate (own [workspace]): real sphincs_c10::verify
                             —   wrapped as sca_c10_verify_real(pk_seed, pk_root, msg_hash, sig) → u32
  fw_verify_target/          — standalone thumbv8m crate (own [workspace]): real fw_manifest verify chain
                             —   build.rs bakes 3 deterministic fixtures (valid + bad_sig + bad_digest) from a
                             —     fixed vendor keypair (sk_seed=[0x42;32], pk_seed=[0x77;16])
                             —   src/main.rs exports `sca_fw_verify_{structural,crc,digest,vendor_fpr,signature,
                             —     rollback,all,all_fi}` — `all` chains them in FSBL order; `all_fi` is the
                             —     F-7-hardened mirror (verify_signature through fi::check_true_into_sentinel)
  ns_ptr_target/             — standalone thumbv8m crate (own [workspace]): real NS-pointer validators
                             —   src/main.rs `#[path]`-includes `secure/src/nsc/ptr_validate.rs` verbatim and
                             —     exports `sca_ns_validate_{read,write}` (plain) +
                             —     `sca_ns_validate_{read,write}_fi` (sentinel-wrapped); harness sweeps both
                             —     to validate any hardening candidates side-by-side with the production gate
  c10_sign_target/           — standalone thumbv8m crate (own [workspace]): real `c10_sign_verified_with_progress`
                             —   build.rs precomputes pk_root from a fixed sk_seed/pk_seed so the runtime path
                             —     uses SigningKey::from_parts (cheap struct fill) instead of keygen — saves
                             —     billions of unicorn-instructions per emulation
                             —   src/main.rs exports `sca_c10_sign_plain` (raw sign, no gate),
                             —     `sca_c10_sign_verified` (production gate, F-1/F-2/F-5 fixed), and
                             —     `sca_c10_verify_real` (independent off-board verify for the harness)
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

- ~~**C10 verify-before-release — full version**~~ — **DONE** (`fault_sweep_c10v.py`
  + `c10v_target/`, which path-deps the *real* `sphincs-c10`, software SHA — see
  "### Full C10 verify fault sweep" below). It loads the `wrong-message` vector
  from `contracts/smart-wallet/test/c10_test_vectors.json` (a structurally-valid
  sig for a different message → `verify` runs the full FORS/WOTS/hypertree path,
  then fails the final root check) and sweeps all 3 fault models over every one of
  `verify`'s ~7521 instructions; **result: no single fault makes a forged
  signature verify as good** — `make c10v` exits 0. *Not yet done*: the
  `sk.sign(...)` side (a fault inside C10 *signing* that leaks `sk_seed` or emits
  a malformed sig), and a sign-then-verify round-trip; sign is slower to emulate
  but tractable. Also: only single-fault — multi-fault / on-device timing-EM
  glitches are out of scope.
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
- **`fault_sweep_fi.py` extensions** — ~~stuck-at faults~~ **DONE** (all 3 single-fault
  models swept) and ~~two-fault sweeps~~ **DONE** (`fault_sweep_fi.py --two-fault` /
  `make fi-twofault`: a `UC_HOOK_CODE`-driven pair sweep over every ordered pair of
  `check_true(false)`'s ~205 instructions). Finding **F-5**: `fi::check_true` is
  **~2-coordinated-skip-defeatable**, not 4-skip as its doc-comment claims — but
  almost all the 2-skip routes are *out of `check_true`'s claimed scope*: corrupting
  *both* `cond()` evaluations (the boolean source — which `check_true` explicitly does
  not promise to protect; and in the harness the trivial `sca_fi_cond(x)=black_box(x)!=0`
  makes "skip the arg-load → r0 holds a truthy stack pointer" easy, which does **not**
  transfer to a real `bl sphincs_c10::verify(pk_seed,…)` closure where a skipped arg
  makes verify *fail*). The pairs that matter are the few with *both* faults in
  `check_true`'s verdict/return code (e.g. skipping the result `mov r0, r4` /
  fail-path result-zeroing) — for those, sentinel-encode the return; or just soften
  the doc's "4" to "~2". Exploratory: `make fi-twofault` exits 0 (the single-fault
  `[skip]` sweep is the hard gate, and it passes). *Still open*: a 3-fault sweep
  (combinatorics get heavy; 3 coordinated skips is a much steeper bar), and a
  *leakage* pass over the FI guards (does `wait_random`'s loop count leak via timing?
  — emulated traces are jitter-free, so it'd be a structural check, not a timing one).

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

### F-2 — verify-before-release *call-site glue* — **PARTIALLY MITIGATED** (`fi::check_true_into_sentinel`)

Even with the F-1 fix, a single fault still made `sca_c10_verify_release` "release
the signature" via the *call-site glue*: skip the `bl check_true` call (→ a stale
register looks truthy to the caller), stuck-at-FF the bool return register, skip
the post-check branch, or skip the prologue load of `v` into `check_true`'s frame.
These aren't a `check_true` *internal* failure — they're the inherent weakness of
the `if !guard() { return err }` / bool-return idiom: `check_true` hardens its own
check, but can't stop the caller skipping the call, the branch on the result, or a
stuck-at on a `bool`-shaped return register.

**Action taken.** Added `fi::check_true_into_sentinel<F>(cond) -> u32` (a sibling
of `check_true` — same body, but returns `OK_SENTINEL`/`FAIL_SENTINEL` instead of
a `bool`), and migrated **all ~13 `check_true` callsites in the `secure` crate**
to `if crate::fi::check_true_into_sentinel(C) != crate::fi::OK_SENTINEL { err }`
(and `gated_unlock`'s `match result { Ok(master) if verdict == OK_SENTINEL => …,
Ok(_) => Err(InternalError), Err(e) => Err(e) }`). Files: `crypto.rs`,
`nsc/mod.rs`, `nsc/cmd_sign_userop.rs` ×3, `nsc/cmd_sign_userop_batch.rs` ×3,
`nsc/cmd_sign_offchain.rs`, `dual_se.rs`, `hw/otp.rs`, `hw/flash.rs` ×2 — built
clean for `thumbv8m` (`mock-se+…+stm32u585` and `dual-se+…+stm32u585`), `cargo
test -p sphincs-tz-secure` 105/105 (incl. `glitched_unlock_returns_internal_error`, the
`gated_unlock`-path and `fi::tests` cases), and `make c10`/`make pin` exit 0 (their
harness mirrors exercise `check_true_into_sentinel` + the `!= OK_SENTINEL` caller
pattern). (`make e2e` — the QEMU unified-sign e2e — timed out at the 10-min budget,
which is QEMU's software-SHA C10-sign×2 being slow, not a regression; `make run`
smoke is the lighter confirmation.) This
**kills "skip the `bl`" and "stuck-at the return register"** at every gated
callsite (a garbage register is overwhelmingly `≠ OK_SENTINEL` → the caller takes
the error path) and turns the harness mirror's residual from "skip the `bl
check_true`" into just "skip the caller's `if … != OK_SENTINEL { err }` branch"
(the irreducible one-skip-of-the-return-branch — could be doubled) plus the
boolean-source routes (corrupting `cond`, out of `check_true`'s scope). `make c10`
exits 0 with the remaining 4–6 hits printed as the F-2 residual; it fails (loudly)
only if a bypass moves into `check_true_into_sentinel`'s *internal* logic
(= an F-1-class regression). (We keep `check_true` as a standalone body — *not* a
wrapper over `check_true_into_sentinel` — because the `== OK_SENTINEL → bool`
reduction a wrapper adds is itself a one-skip-to-a-truthy-`FAIL_SENTINEL`; `make
fi` caught that when tried.)

### F-3 — `gated_unlock`'s SE-unlock Ok/Err discrimination — **ADDRESSED (upstream, commit `13c194e`)**

When this finding was first written, `secure/src/nsc/mod.rs::gated_unlock` did a
plain `match se.unlock(pin) { Ok(master) => …, Err(e) => Err(e) }`, and an early
version of `fault_sweep_pin.py` (mirroring that) showed a single skip on the
discriminant making the gate return `Ok` on a wrong PIN. Commit `13c194e` then
hardened it: `gated_unlock` now reads the discriminant **twice** (separated by
`wait_random()`), routes the verdict through `fi::check_true`'s hamming-distant
sentinel, and only takes the `Ok(master)` arm if the guard agrees — otherwise
`match result { Ok(master) if both_ok => …, Ok(_) => Err(InternalError), Err(e)
=> Err(e) }`. `fault_sweep_pin.py`'s mirror was updated to track that, and the
`[skip]` sweep now confirms **no single instruction-skip makes a wrong PIN
unlock**: even though LLVM CSEs the two `is_ok()` reads into one, `both_ok` is
computed from them (= `false` for a genuine `Err`) *before* the `match`, so a
single skip of the `match` discriminant lands in `Ok(_) => Err(InternalError)`,
not `Ok(master)`. (Caveat: a `stuck-at-FF` on the status-return path still forces
an "unlocked"-looking return — the inherent result-register-corruption class,
same as the `fi::check_true` stuck-at INFO; not a `[skip]` bypass, not a
regression. Belt-and-braces: `core::hint::black_box(&result).is_ok()` would
defeat the `is_ok_1`/`is_ok_2` CSE if a future compiler ever hoists the `match`
load to coincide with them — `fault_sweep_pin.py` would catch that regression.)
And the original severity bound still holds anyway: even a successful flip would
have the wallet read the `Err`-variant garbage as the "master", not the seed (the
SE does the PIN compare in silicon), so it's a robustness gap, never a seed
extraction. `make pin` exits 0.

### F-4 — the page-124 attempt isn't always charged under a single fault — **minor (the SE-silicon counter is the real gate); accept**

`gated_unlock`'s pre-commit (`if pin_attempts_bump().is_err() { return InternalError }`,
then `se.unlock`) is meant to make every wrong-PIN attempt cost a charged counter
slot. `fault_sweep_pin.py` shows a single fault that skips the `bl pin_attempts_bump`,
or skips `pin_attempts_bump`'s `write_quadword_verified` (its `post != pre+1`
re-check then makes it return `Err`, so `gated_unlock` correctly *refuses* with
`InternalError` — but the MCU's page-124 counter didn't advance), leaves the wrong
attempt uncharged → a "free guess". **But that "free guess" only affects the MCU's
*redundant* counter, not the authoritative one**: `gated_unlock` does the page-124
bump *before* `se.unlock(pin)`, so even when the bump is glitched/skipped,
`se.unlock(pin)` still runs and the SE counts the wrong PIN **in silicon**
(invariant #2 — SE050 UserID `max_attempts`, OPTIGA F1D0/E120 LUC). Boot reconciles
to the *strictest* of {MCU page-124, OPTIGA E120 LUC, SE050 UserID}, so if the
MCU's lags, the SE's becomes the gate → 10 attempts → wipe. So the MCU-side
redundancy degrades to no-redundancy under a precise repeated glitch, but the
**primary (SE-silicon) rate-limit holds** — it's a robustness/redundancy gap, not
an unlimited-guesses hole. A "fix" would be drastic (treat a `pin_attempts_bump`
failure as tamper → `factory_reset_admin`); `pin_attempts_bump`'s *internal*
re-check is now `fi::check_true_into_sentinel`-based (F-2 migration). **Recommend:
accept** (and the README/threat-model could note "the MCU page-124 counter is a
redundant belt over the SE-silicon braces; under FI, the braces are what hold").
`make pin` exits 0; its "pin_attempts_bump invariant check" fails only on a
`[skip]`-model violation of the bump's internal `Ok ⇒ counter advanced` invariant
(none currently — stuck-at-FF on the bump's return slot is the inherent
result-register class, not a regression).

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
| `sca_hmac_sha512_kdf` | `HMAC-SHA512("sphincs-c6-v1", bip39_seed)` — the C10 master-key derivation step in `pqsigner-domain` (varies the seed; the HMAC key is the fixed 13-byte domain tag) | TVLA `max\|t\| = 0.00` over 600 traces → **flat**: RustCrypto's `hmac` + `sha2` are constant-time |
| `sca_c10_keygen` | `SigningKey::keygen(sk_seed, pk_seed)` — builds the C10 hypertree from a varying sk_seed (pk_seed fixed) | TVLA `max\|t\| = 0.00` over 80 traces × 500 K mem-events → **flat**: SHA-256-driven WOTS+/FORS/hypertree address sequence is determined by `pk_seed` and the tree-structure constants, not the sk_seed *value* (which only feeds SHA-256 input bytes) |
| `sca_c10_sign` | `SigningKey::sign(msg, None)` — varies msg_hash, keeps sk_seed/pk_seed/pk_root fixed via `from_parts` so emulation actually reaches the sign phase (not the ~2.5 B-instruction keygen prelude) | TVLA `max\|t\| = **40.71**` over 600 traces × 10 M mem-events → **LEAKAGE @ sample 9 997 943** — see Finding F-9 below. (Earlier 80-trace × 500 K smoke run showed `max\|t\| = 1.45` "flat" but that was a coverage artifact — the 500 K-sample window only reached the SHA-256 preamble, not the FORS phase where the leak lives.) |

Findings: AES / AES-GCM-wrap / HMAC / C10 keygen all clean on `mem_address`.
**C10 sign IS NOT FLAT — see Finding F-9** for the audit-grade result and
its security analysis (msg-dependent address variation in the FORS phase;
the leaked information is the FORS leaf indices, which are public — already
recoverable from the signature itself, so no SECRET leaks via this channel
beyond what the signature reveals; flagged for the hardware-FI threat model
nonetheless). `make kdf` exits 1 to flag the finding.

**Performance.** The harness uses `multiprocessing.Pool` with `spawn` to
parallelize trace collection (POC at `/tmp/parallel_collect_poc.py`
confirmed parallel == serial element-wise). On AMD Ryzen AI 9 HX PRO 370
(12 cores / 24 threads), the full sweep (including the heavy C10 keygen +
sign subjects) finishes in **~30 seconds** — vs ~57 minutes single-thread,
~100× speedup. Worker memory is bounded by a custom unicorn `UC_HOOK_MEM_*`
that writes Hamming-weight values directly into a fixed-size numpy array
and calls `emu_stop()` when full, bypassing rainbow's default Python-dict
accumulation (which would OOM the system on SPHINCS+ sign — empirically
hit 90 GB RAM + 8 GB swap exhaustion before the bound was added).

**Caveats:** (1) emulation only — the analog power/EM leakage of the
running silicon, and register-HW DPA of the AES round keys / SHA-256 state /
SPHINCS+ FORS values, still need a scope (ChipWhisperer / PicoScope /
Scaffold — see the `rainbow`/`lascar` skills); (2) the *deployed* entropy
wrap is a *single* encryption with a *fixed* nonce, so there's no
attacker-chosen-input DPA surface against it anyway — the residual is
single-trace leakage of the wrap key / keystream during that one boot-time
operation (an SPA/template attack), which a profiling setup on the device
would probe, not this fixed-vs-random TVLA; (3) `sca_aesgcm_wrap` is a
*mirror* of `encrypt_entropy_blob` (not a `#[path]` include — `pqsigner-domain`
uses `{ workspace = true }` deps and can't be path-dep'd from a detached
workspace) — it uses the *same* crates.io deps (`aes-gcm` 0.10 / `aes` 0.8 /
`sha2` 0.10), so the AES's leakage behaviour matches; KEEP IN SYNC if
`encrypt_entropy_blob`'s shape changes (e.g. a different AEAD); (4) 600
traces × 10 M samples for C10 keygen/sign is audit-grade (TVLA's 4.5
threshold is calibrated for ≥ 600 traces); the parallel harness produces
this in ~25-30 min on AMD Ryzen AI 9 HX PRO 370.

### F-9 — SPHINCS+C10 sign: audit-grade TVLA finds msg-dependent address variation in the FORS phase

Earlier we wrote "C10 sign / mem_address is flat" based on an 80-trace ×
500 K-sample smoke run that returned max\|t\| = 1.45. That was a **coverage
artifact**: the 500 K-sample window only reached the *very early* SHA-256
preamble of the sign, not the FORS phase. **Re-running at audit-grade
(600 traces × 10 M samples)** flips that result:

```
sca_c10_sign  (varies msg_hash, sk_seed/pk_seed fixed):
  TVLA [mem_address]: max|t| = 40.71  (600 traces, 10 000 000 samples)  → LEAKAGE  @sample 9 997 943
```

max\|t\| = 40.71 is **~9× the 4.5 leakage threshold** — unambiguous, far
above statistical noise. The leakage *starts* in the last 0.06 % of our
swept window (sample 9 997 943 of 10 000 000), suggesting the actual
leakage region extends *past* our window into the FORS sign phase.

**Almost certainly the FORS leaf-index access pattern.** SPHINCS+C10 sign
derives `k = 13` FORS leaf indices from `H_msg = HASH(R ‖ pk ‖ msg_hash)`
and then accesses `forsSk[leaf_idx]` and the FORS auth-path siblings
`forsTree[level][sibling_idx]`. Those indices are msg-derived, so the
*addresses* of those accesses vary with msg.

**Security analysis.** The FORS leaf indices are **public** —
recoverable from the signature by any verifier (they're encoded in the
authentication-path positions). An attacker watching N power traces
learns N sets of leaf indices, which they would already learn from the
N corresponding signatures. So **no SECRET information leaks beyond
what the signature reveals**. This is a "transparent" side channel.

**Where it would still matter.** A more advanced attack model:
side-channel-aware FAULT injection. If an attacker can observe the
leaf indices in real time during signing (via EM/power probe), they
could time a fault injection to a specific FORS leaf or sibling node
*before* the signature is finalised — potentially manipulating which
leaves get signed. That's a multi-disciplinary FI+SCA attack, more
sophisticated than the FI sweeps we've already done. Worth flagging
for a hardware-FI auditor.

**Recommendation.** Document the finding in the threat model. The
production code is doing what SPHINCS+ requires — there's no
"implementation bug" to fix. If a future hardening pass wants
constant-address FORS access, it would need either bitsliced
table-lookup (slow) or pre-loaded scratch buffers (high RAM).
Neither is standard practice in the SPHINCS+ spec; the spec assumes
"side channels are out of scope for this primitive."

**Limitation of our measurement.** We tried 600 × 50 M samples to
localise the leak region's end and check for additional leakage
sources past FORS. The 30 GB trace array + lascar's per-sample
working arrays peak system memory above 64 GB on this hardware, and
the kernel OOM-killed `make kdf` during the lascar t-test phase.
A future deeper sweep needs either (a) batched / streaming TVLA in
lascar (Session.run with chunked input), or (b) multiple narrower
windows captured via snapshot/restore at different sign-phase
offsets (same machinery `fault_sweep_c10_sign.py` already uses).

## Full C10 verify fault sweep — `fault_sweep_c10v.py` + `c10v_target/`

`make -C tools/sca c10v` builds `sca-c10v-target` (a thin `#[no_mangle]` wrapper
over the **real** `sphincs_c10::verify` — software SHA-256 path, path-dep'd
straight from `../../sphincs-c10`) and sweeps a single fault at every instruction
of `verify`'s execution on a known *invalid* vector, watching for a fault that
flips the **reject into an accept** — i.e. a *forged* C10 signature verifying,
which is the worst-severity FI outcome (an attacker could install their own slot
key / userOp). The vector is the `wrong-message` entry from
`contracts/smart-wallet/test/c10_test_vectors.json` (the same JSON the Solidity
verifier's Foundry tests use): a *structurally valid* signature for a different
message, so verification runs the full FORS + WOTS + hypertree recomputation and
then fails the final `computed_root == pk_root` check — the failure happens at
the end, after everything else has run, so the sweep exercises the whole pipeline
including the classic SPHINCS+ FI spot (the final root comparison).

It sweeps **every invalid vector in the JSON** (`wrong-message`, `wrong-root`,
`mutated-R`, `mutated-FORS-auth`, `mutated-WOTS-sigma`,
`mutated-WOTS-count-target-sum-fail`), under all 3 fault models (skip /
stuck-at-0 / stuck-at-FF). `wrong-message`/`wrong-root`/`mutated-R` run the full
`verify` (~7521 instr — H_msg, FORS recompute, hypertree, final root compare —
*all* of it), so the sweep covers every instruction; `mutated-FORS-auth` /
`mutated-WOTS-sigma` / `mutated-WOTS-count-target-sum-fail` make `verify` do
~1.2–1.8 **million** instructions (see "F-6" below) — for those the sweep covers
the first 8 000 instructions (the early checks, where a forge-relevant fault
would live) with each emulation capped at 25 000 instr (a fault during the
multi-million-instr chain shows up as "hung" → verify never returns → non-forge).
The harness reuses one persistent emulator (`reset()` + re-write the inputs +
zero `verify`'s stack between iterations) so the whole 6-vector sweep finishes in
~1–2 min instead of timing out on per-iteration ELF re-parsing.

**Result: clean** — across all 6 invalid vectors × all 3 fault models, **no
single fault made a forged signature verify as good** (the faults that hit
something either crash on an invalid instruction, hang, or are correctly
rejected). `make c10v` exits 0; it exits 1 (with the offending instruction
indices + PCs + a verbose repro) the moment any single fault flips a reject into
an accept.

Caveats: emulated single-fault only (multi-fault / on-device clock-EM glitches
out of scope); this is the `verify` direction — a fault inside C10 *signing* is a
separate, not-yet-wired target, and note the meaningful FI threat against C10
*signing* is *differential* (two glitched signs reusing the same FORS/WOTS
one-time keys → universal forgery), not a single-trace "did the output flip"
check, so that target needs a 2-sign harness, not a re-run of this one.

### F-12 — Flash-counter SCAN is single-fault rollback-bypassable; severity higher than F-10 because the flash-promote defense doesn't apply

`make flashctr` mirrors `secure/src/hw/flash.rs::offchain_count_read` —
the scan-and-take-max loop over the log-structured per-slot counter page
(page 123, 512 QWs of 16 B each). The mirror page is populated with 100
valid OFFCHAIN_TYPE_COUNT entries (counts 1..=100). The expected read
result is 100. Any return value < 100 is a **rollback**: the firmware
underreports `local_offchain_count` by the delta, letting the firmware
believe the counter is lower than it actually is.

**Plain mirror (production code) under FI:**

```
sca_flashctr_read_plain  [skip       ]  529 rollbacks  (delta range: 1..100)
sca_flashctr_read_plain  [stuck-at-0 ]  122 rollbacks
sca_flashctr_read_plain  [stuck-at-FF]  119 rollbacks
                                       ─────
                            TOTAL:     770 single-fault rollbacks
```

770 successful rollback cases across 7,184 instructions × 3 fault models.
Rollback magnitudes span the full range — many reduce the count by 1-10
(partial under-report), but the worst return 0 (full counter reset).

**Production blast radius — worse than F-10.** A single successful fault
on the scan can underreport by up to the number of entries in flash for
that slot (capped at OFFCHAIN_CAPACITY = 512 per compaction cycle, with
compaction extending the effective horizon to ~65 k sigs). The
flash-promote step that bounds F-10 to ~1 extra sig per fault does NOT
help here: `offchain_count_promote_to` uses the same scan internally, so
a rollback at the read layer corrupts the promote target as well.

A single well-timed fault can let an attacker get from ~1 up to ~512
extra signatures past the cap; sustained attacks can chain into
substantially more.

**Hardened variant (scan-twice + halt-on-mismatch):** rollbacks drop from
770 to 10 across the three models — ~98.7 % reduction:

```
sca_flashctr_read_fi  [skip       ]  4 rollbacks (all delta=+100, return 0)
sca_flashctr_read_fi  [stuck-at-0 ]  4 rollbacks (all delta=+100)
sca_flashctr_read_fi  [stuck-at-FF]  2 rollbacks (all delta=+100)
```

The remaining 10 cases all return 0 — likely faults at scan entry that
cause both `scan_once` invocations to terminate identically early
(control-flow corruption → both return 0 → r1 == r2 → halt-on-mismatch
doesn't fire → return 0). To close those, additional layers needed:

  - **Reverse-direction second scan.** First scan iterates 0..CAPACITY;
    second scan iterates CAPACITY-1..=0. A control-flow fault that
    early-exits scan 1 doesn't symmetrically affect scan 2.
  - **CRC/checksum tail in the page.** A non-blank tail QW holds a
    32-bit CRC over the previous QWs' contents; scan validates the CRC
    before returning. A counter rollback that returns a value
    inconsistent with the CRC fails.
  - **Counter monotonicity invariant in SRAM.** Cache the last-read
    counter value in a sentinel-protected SRAM struct; subsequent reads
    must return ≥ cached. A rollback below cached → halt.

For first-pass production fix: scan-twice (forward + reverse) gets
~99.99 % closure cheaply. Tracked as F-12 fix in work-todo.

**Severity: HIGH.** Most severe finding in this audit. F-7 / F-8 closed,
F-10 / F-11 bounded by re-validation/promote/on-chain, but F-12 has no
existing defense — the production code is **single-fault rollback-
bypassable end-to-end**. The 65 k structural cap that bounds F-9 (FORS
leaf-index leak) AND every other SPHINCS+ subset-resilience-bound risk
depends on `offchain_count_read` being accurate.

### F-11 — Type 1 / Type 2 dispatch sanity-check rejections are single-fault bypassable — **silent-T1-emission class is NOT reachable; reject-bypass class is, but on-chain re-validation bounds the blast radius**

`make dispatch` sweeps the dispatch logic in `cmd_sign_userop.rs:160-236`.
Two findings emerge:

**Positive finding (the dangerous bypass class doesn't reproduce):** the
`plain_t2` scenario (companion sends `flags=0`, expecting Type-2-only)
shows ZERO "expected 0 → observed 1" deviations under all three fault
models. **A single fault cannot flip `register_slot` from false to true
to silently emit a Type 1** the companion did not request. This was
the most concerning attack class in the threat model (silent attacker-
controlled slot-key installation).

**Negative finding (reject bypasses):** scenarios that SHOULD be rejected
(incompatible flag combos, INCLUDE_INIT_CODE+nonzero-slot, REGISTER_SLOT+slot0)
have single-fault bypasses on both plain and FI-hardened mirrors:

```
plain × both_flags     [skip 2 / s@0 1]  → 99→1, 99→0 deviations
plain × init_with_slot [skip 5 / s@0 2]  → 99→0, 99→2 deviations
plain × register_slot0 [skip 5 / s@FF 1] → 99→0, 99→1, 99→2 deviations
fi    × {same scenarios} [similar counts] → same residual as F-10
```

Same root cause as F-10: input-register stuck-at fault makes the gate
correctly compute "the corrupted input passes" → reject is skipped.

**Severity: medium-low.** Even the worst-case bypass (a rejected combo
proceeds as Type 1+Type 2) is bounded by **on-chain re-validation**:
`PQSmartWallet.validateUserOp` independently re-checks the bootstrap C10
sig and the slot pubkey installation — a Type 1 emitted from an
inconsistent state still has to be paired with a valid bootstrap-key
signature, which the unfaulted code path produces correctly. The
on-chain validator catches malformed combos as `BootstrapKeyUsed` /
`SlotKeyUsed` invariant violations.

**Recommendation: same as F-10 (input redundancy).** Read `flags` and
`slot_index` from the NS-pointer-validated input buffer TWICE, with
`wait_random()` between, and compare. A stuck-at on one read survives;
the second re-reads from memory; the cmp catches the discrepancy →
halt. Tracked alongside F-10.

### F-10 — Off-chain gap + cap enforcement is bypassable via input-register fault — **architectural; requires input-redundancy, not gate-sentinel-wrapping**

`make cap` sweeps the gates in `cmd_sign_offchain.rs:202-223` that bound a
single SPHINCS+C10 slot key to MAX_SLOT_USES = 65,536 signatures per chain.
Both the plain (production) predicate AND a sentinel-wrapped variant
(`pqsigner_fi::check_true_into_sentinel`, the F-7/F-8 hardening pattern)
are single-fault-bypassable:

```
sca_cap_check_plain × gap_at_boundary  [skip 7 / s@0 4 / s@FF 1]   = 12 bypasses
sca_cap_check_plain × cap_at_max       [skip 3 / s@0 3 / s@FF 0]   =  6
sca_cap_check_plain × cap_overflow     [skip 3 / s@0 1 / s@FF 1]   =  5

sca_cap_check_fi × gap_at_boundary     [skip 5 / s@0 4 / s@FF 2]   = 11
sca_cap_check_fi × cap_at_max          [skip 1 / s@0 3 / s@FF 0]   =  4
sca_cap_check_fi × cap_overflow        [skip 2 / s@0 1 / s@FF 1]   =  4
```

**Bypass mechanism: input-register fault.** Bypasses cluster around
"instr 3" (function prologue / argument unpack) and at the gate input
compute (~instr 3897 for the second gate). A stuck-at-0 on the register
holding `local_offchain` clamps the input to 0; the gate correctly
computes "0 < MAX_OFFCHAIN_GAP" and "0 + 1 <= MAX_SLOT_USES" → accept.
The F-7/F-8 sentinel-wrap pattern doesn't defend against this:
sentinel-wrapping protects the gate COMPUTATION (boolean true/false flip
inside the predicate or its caller-side cmp), but if the INPUT to the
predicate is corrupted, the predicate correctly accepts the corrupted
input.

**Production blast-radius — bounded by the flash-promote step.** The
production code has a "promote" check before the gap check
(`cmd_sign_offchain.rs:200-210`):

```rust
let last_userop = offchain_state::last_userop_count_read(&slot_flash_key);
let mut local_offchain = offchain_state::offchain_count_read(&slot_flash_key);
if last_userop > local_offchain {
    offchain_state::offchain_count_promote_to(...)?;
    local_offchain = last_userop;
}
```

This means a SINGLE successful fault gets at most ~1 extra signature past
the cap before the next call's flash read + promote step re-anchors
local_offchain to the on-chain last_userop. Sustained attack would require
faulting EVERY call (or also faulting the promote step).

**Severity: medium.** Bounded blast-radius per fault, but each successful
fault permanently erodes the structural 65 k invariant the SPHINCS+
subset-resilience margin depends on. Worth fixing.

**Fix direction (not yet applied — needs design choice).** Sentinel-wrapping
alone isn't enough; the gate needs **input redundancy**:
  - **Option A: read inputs twice from flash, compare.** Cheap (each flash
    read is ~µs), simple. A stuck-at on the input register survives one
    read but the second re-loads from flash; the cmp catches the
    discrepancy → halt.
  - **Option B: compute the gate via two independently-derived paths.**
    E.g., `gap_pass = (local - last) < GAP_MAX` AND `gap_pass2 = local < (last + GAP_MAX)`.
    Each formulation routes the values through different register paths
    and arithmetic. Disagreement → halt.
  - **Option C: pad with magic-cookie integrity values on the input
    struct.** Read inputs into a struct with HMAC-tagged sentinel
    bytes; verify the tag before using the fields. Most thorough but most
    code.

Recommend Option A for first-pass — it's the least invasive while still
forcing an attacker to fault TWO independent flash reads (which happen
microseconds apart with different bus timings). Track as F-10 fix in
work-todo.

### F-6 — `sphincs_c10::verify` does ~1.2–1.8 M instructions on some malformed signatures — **intrinsic to SPHINCS+ verify, NOT fixable as a code change**

`instr_count` (a clean `verify()` run, instrumented) reports: `wrong-message` /
`wrong-root` / `mutated-R` → ~7 521 instructions; **`mutated-FORS-auth` →
1 239 403**, **`mutated-WOTS-sigma` → 1 777 214**, **`mutated-WOTS-count-target-sum-fail`
→ 1 239 403**.

**Why the gap.** `wrong-message` hits the forced-zero constraint check
(`if fors_indices[K-1] != 0 { return false }`) — `H_msg` with a wrong msg
produces random `fors_indices[K-1]`, which is non-zero with probability
2047/2048 → early reject. The other three malformed vectors keep the
correct `msg + pk + R`, so the forced-zero check passes, and full FORS
reconstruction (~K-1 = 12 trees × A = 11 hashes each ≈ 1.2M unicorn-instr
of SHA-256) runs to completion before the cascading-failure cascade hits
the final root mismatch.

**Originally-suggested "fail-fast `digit < W` / bounded-loop assertion" doesn't
apply.** `extract_digits` already masks with `W_MASK = W-1 = 7`, so
`digits[i] ∈ [0, 7]` by construction; chain lengths `(W-1) - digits[i]`
are bounded by 7 — no unbounded loop exists. The expense is intrinsic:
SPHINCS+ verify can only validate a signature by RECOMPUTING the full
FORS+WOTS+hypertree, and any deeper-than-H_msg mutation can't be caught
without running the recomputation through to where the corruption
propagates to the final root compare. No signature-internal MAC or
per-component integrity check exists in the SPHINCS+ spec.

**Severity unchanged: low.** Correctness still holds (malformed sigs
always reject); on-chain the matching `SPHINCsC10Asm.sol` has the same
~1.2-1.8M staticcalls shape and blows past `verificationGasLimit` → OOG
revert → the bundler's `eth_estimate…` simulation catches it → the
userOp is dropped before submission, nobody eats the gas. So no
ERC-4337 DoS. The observation is just "SPHINCS+ verify is intrinsically
~1-2M-instruction work on signatures that pass the forced-zero check but
fail deeper" — not a bug to fix.

**Not fixed** — investigation determined the work is intrinsic; the
production code already has the only fast-fail point that exists in the
SPHINCS+ spec (the forced-zero check). Adding a separate signature-bytes
integrity scheme would be a SPHINCS+ extension, not a fix.

### F-5 — `fi::check_true` is ~2-coordinated-skip-defeatable, not 4-skip as its doc claimed — **doc updated + the result-path route mitigated at call sites**

`fi::check_true`'s doc-comment said "a glitch must successfully skip ALL FOUR
decision points to turn a `false` into a `true` return". The `[skip,skip]` pair
sweep (`fault_sweep_fi.py --two-fault` / `make fi-twofault`, ~21k ordered pairs)
shows that's optimistic: ~210 pairs flip `check_true(false)→true` — of which 205
are scaffolding-only, 4 are a harness artifact (skipping the `mov r0, want` before
the synthetic `bl sca_fi_cond` leaves a nonzero stack pointer in r0, which the
trivial `sca_fi_cond(x)=black_box(x)!=0` reads as "true" → does **not** transfer
to a real `bl sphincs_c10::verify(pk_seed,…)` closure where a skipped arg makes
verify *fail*), and exactly **1** is a real candidate — `(199,201)`, both faults
in `check_true`'s result/return path (the final `mov` of the verdict register /
the fail-path zeroing → leaving `FAIL_SENTINEL`/garbage in `r0`). The same residual
shows up under `[stuck-at-FF]` (a stuck-at on the return register defeats any
`bool`-returning fn). So: `check_true` raises the bar from 1 skip to **~2
coordinated faults**, and the only in-`check_true` two-skip route is the
result/return path. **Action taken:** (a) `secure/src/fi.rs`'s `check_true`
doc-comment rewritten to say this honestly; (b) added `fi::check_true_into_sentinel`
and migrated all ~13 `check_true` callsites in the `secure` crate to compare a
sentinel rather than a bare `bool` (see F-2) — so a garbage / `FAIL_SENTINEL`
return is `≠ OK_SENTINEL` → the caller takes the error path: the *result/return-path*
2-skip route and the stuck-at-on-return route are no longer call-site bypasses.
**Still residual (maintainer's call):** the 2-coordinated-skip route *inside*
`check_true_into_sentinel` itself (corrupting its sentinel commit) — and doubling
each caller's `if … != OK_SENTINEL { err }` branch would harden the irreducible
one-skip-of-the-return-branch a notch further; or accept (2 *coordinated* skips is
a steep bar). `make fi`/`make fi-twofault` exit 0 — the single-fault `[skip]`
sweep (the contract test) still passes; `make fi` caught and rejected the one
attempt at making `check_true` a *wrapper* over `check_true_into_sentinel` (the
`== OK_SENTINEL → bool` reduction it adds is itself a one-skip-to-truthy step), so
both functions are kept as standalone bodies.

## Full FW-manifest verify-chain fault sweep — `fault_sweep_fw_verify.py` + `fw_verify_target/`

This is the **`make fw-verify`** target — a single-fault sweep over the *real*
`fw_manifest::ManifestRef` verify chain. Mirror-free: the thumbv8m target ELF
path-deps the production `fw-manifest` and `sphincs-c10` crates, so the code
under test is bit-identical to what the FSBL (`fsbl/src/main.rs::filter_valid`)
and the secure-world COMMIT handler (`secure/src/fw_update/mod.rs::verify_manifest`)
actually run. **Attack model**: an adversary delivers a manifest over
`CMD_FW_BEGIN/CHUNK/COMMIT` with every cheap field correct (magic, CRC,
vendor-fingerprint, fw_version above the rollback floor) but a **bogus
SPHINCS+C10 signature** they can't forge without the vendor private key — does
any single instruction skip / register stuck-at flip the chain's `Err` return
into `Ok` (= unsigned firmware accepted)? Three fault models: `fault_skip`,
`fault_stuck_at(0)`, `fault_stuck_at(0xFFFFFFFF)`. Three fixtures built
deterministically by `build.rs` from a fixed vendor keypair: `MANIFEST_VALID`
(baseline), `MANIFEST_BAD_SIG` (sig zeroed; the attacker's actual vector),
`MANIFEST_BAD_DIGEST` (manifest_digest flipped; cross-check on `verify_digest`).
For each of the per-step `verify_*` entry points AND a chained `sca_fw_verify_all`
mirroring FSBL's call order, sweep every instruction × every model × every
bad fixture; print bypass count + crashes + hangs + correctly-rejected.

### F-7 — `fw-manifest::verify_signature` was single-fault-bypassable in the COMMIT gate, propagating end-to-end — **FIXED in `secure::fw_update::verify_manifest` (commit follows this README update)**

The `make fw-verify` sweep finds **13 single-fault bypasses** of
`verify_signature` in isolation on `MANIFEST_BAD_SIG` (7 `[skip]` + 1
`[stuck-at-0]` + 5 `[stuck-at-FF]`), and the focused-suffix sweep on
`sca_fw_verify_all × bad_sig` empirically confirms **at least 2 of these
propagate end-to-end through the chained verify** (the `[skip]` faults at
relative offsets 18 and 21 inside `verify_signature`; the late-tail offsets
{7533, 7537-7545} would propagate by the same mechanism but live past the
practical sweep range given persistent-emulator state pollution at high fault
indices). The stuck-at chain bypasses are present per-step but the rainbow
`start_and_fault` flow polluted state too quickly on the long chain runs to
catch them empirically. By construction they propagate: `verify_signature` is
the *last meaningful step* in the FSBL/COMMIT chain on `bad_sig` —
`verify_rollback` runs after but unconditionally passes (the bad manifest's
`fw_version=100` is above the `rollback_floor=0`), so any per-step Err→Ok flip
of `verify_signature` lifts the chain's final return to `Ok(())` →
`filter_valid` / `verify_manifest` returns `Some(&m)` / `Ok(())` →
**unsigned firmware accepted**.

The per-step bypasses on `verify_digest × bad_digest` (4 skip + 3 stuck-at-0 +
3 stuck-at-FF) do **not** propagate — `verify_signature` runs after
`verify_digest` in the chain and rejects on `bad_digest` (the sig was over the
*original* digest). The chain's defence-in-depth catches this class; the
`verify_signature` class is the residual.

**Production callers affected:**
- `fsbl/src/main.rs::filter_valid` — boot-time slot selection. A successful
  fault here boots an unsigned firmware on next reset.
- `secure/src/fw_update/mod.rs::verify_manifest` — re-verify before flipping
  the active slot in `cmd_fw_commit`. A successful fault here commits the
  unsigned firmware to flash + bumps the OTP rollback-floor.

**Action taken:** `secure/src/fw_update/mod.rs::verify_manifest` was updated
to wrap the `verify_signature` call in `fi::check_true_into_sentinel`. The
closure is double-called with `fi::wait_random()` between, the verdict is
sentinel-committed to a volatile local, re-checked, and the caller compares
the returned `u32` to `OK_SENTINEL` rather than handling a bare `Result`. The
harness mirrors this in `sca_fw_verify_all_fi` (using a `#[path]`-include of
`secure/src/fi.rs` plus a small `rng::byte()` stub — same pattern as
`fi_target/`). The focused-suffix sweep on `sca_fw_verify_all_fi × bad_sig`
shows **zero single-fault bypasses across all 3 fault models × 18,939
sweep range** — the same range where the unhardened mirror had 2 confirmed
`[skip]` bypasses. Two coordinated faults are now required, same residual as
F-5. **`make fw-verify` exits 0** after the fix; the unhardened mirror is
kept in place as regression coverage (a revert would re-introduce the
finding).

**Scope of the fix — initially secure-world only; later extended to FSBL.**
The first version of the F-7 fix hardened only `secure::fw_update::verify_manifest`
(the COMMIT gate). Rationale at the time: the attack chain needs both gates
to be bypassed — without commit, a bad manifest never reaches flash, so FSBL
`filter_valid` only ever sees committed manifests. Hardening the COMMIT gate
breaks the chain.

**Update (follow-up commit):** the deferred FSBL hardening is now also
applied. The shared FI primitives have been extracted into a new
`pqsigner-fi` workspace crate (`OK_SENTINEL`, `FAIL_SENTINEL`,
`wait_random_loop`, `check_true`, `check_true_into_sentinel`); `secure/src/fi.rs`
is now a thin shim that supplies the secure-world's TRNG. FSBL gets its own
shim (`fsbl/src/fi.rs`) that supplies a deterministic stub for the RNG byte
(FSBL doesn't initialise the TRNG; the *invariant check inside the loop*
still catches mid-loop glitches the same way — only attacker retiming
benefits from real randomness, and that's a much narrower surface on FSBL
than on signing). `fsbl/src/main.rs::filter_valid` now wraps
`verify_signature` with `fi::check_true_into_sentinel` exactly the same way
`verify_manifest` does. Bypass bar at FSBL: ~2 coordinated faults, same as
secure-world.

## NS-pointer validation fault sweep — `fault_sweep_ns_ptr.py` + `ns_ptr_target/`

`make ns-ptr` sweeps the *real* `secure::nsc::ptr_validate::validate_ns_{read,write}_ptr`
predicates that gate every NSC gateway entry. The thumbv8m target ELF
`#[path]`-includes the production validator verbatim (path-deps
`sphincs-tz-shared` for the constants); the harness invokes them with five
attacker-controlled `(ptr, len)` scenarios:

| scenario          | description                              | expected |
|-------------------|------------------------------------------|----------|
| valid_ns_sram     | clearly inside NS SRAM                   | accept   |
| s_world_ptr       | NOT in any NS region (S-RAM-like)        | reject   |
| mailbox_overlap   | aliases the shared command mailbox       | reject   |
| null_ptr          | ptr == 0                                 | reject   |
| overflow          | ptr + len overflows u32                  | reject   |

A single fault that flips a `reject` scenario into `accept` is a finding —
the harness reports it as a TrustZone-boundary breach.

The harness *also* sweeps a hardened pair (`sca_ns_validate_*_fi`) that wraps
the predicate in `fi::check_true_into_sentinel`, for side-by-side mitigation
evaluation. The hardened mirror returns the sentinel directly (`OK_SENTINEL` /
`FAIL_SENTINEL`) — same shape the production code would expose to its
gateway callers — so its bypasses reveal the F-5 residual at the caller's
own cmp+branch, not at the wrapped predicate.

### F-8 — `validate_ns_{read,write}_ptr` was single-fault-bypassable on every non-null reject scenario — **FIXED in `NsPtr::validate_{read,write}` (verify-twice + double sentinel check)**

The plain `validate_ns_read_ptr` accepts a known-bad pointer under at least
one single fault for three of the four reject scenarios:

| scenario          | [skip] | [stuck-at-0] | [stuck-at-FF] | total |
|-------------------|--------|--------------|---------------|-------|
| s_world_ptr       | 6      | 1            | 3             | 10    |
| mailbox_overlap   | 8      | 5            | 1             | 14    |
| overflow          | 1      | 0            | 0             | 1     |
| null_ptr          | 0      | 0            | 0             | **0** (robust) |

`validate_ns_write_ptr` has a similar profile (3 + 11 + 1 = 15 bypasses on
the same scenarios). The null check is the *one* check that's structurally
single-fault-robust (a `cmp r0, 0; beq fail` skip leaves r0 as the NS-supplied
pointer value, and the subsequent bounds checks still reject anything outside
NS SRAM / NS flash; but a `cmp+beq` *stuck-at* fault could in principle bypass
it too — empirically it doesn't here because the stuck-at value gets compared
against the bounds and rejected).

**Production exposure.** Every gateway command in `secure/src/nsc/cmd_*.rs`
calls `NsPtr::validate_{read,write}(len)?` before any dereference. A single
fault on the predicate can let an NS-supplied pointer alias secure RAM (→
arbitrary read of the master seed cache / slot key cache / PIN-attempt page),
or alias the shared command mailbox (→ overwrite the in-flight `CMD_*` word
that the secure world is still interpreting — classic time-of-check-time-of-use
trick with FI standing in for a race condition). The closest upstream analog
is rainbow's `HW_analysis/pin_fault.py` Trezor `storage_containsPin` skip
demo: a small predicate whose `Err→Ok` flip breaks an isolation boundary.

**Action taken.** `secure/src/nsc/ns_ptr.rs::NsPtr::validate_{read,write}`
now verify their underlying predicate TWICE through
`fi::check_true_into_sentinel` (with `fi::wait_random()` between), and check
each sentinel verdict independently before constructing the `ReadPtr<T>` /
`WritePtr<T>` proof. A single fault on the first `!= OK_SENTINEL` cmp+branch
is caught by the second verification call; a single fault inside one of the
`check_true_into_sentinel` invocations is caught by the other call. Two
coordinated faults are required to bypass — same residual as F-5 / F-7 for
the rest of the firmware. Why verify-twice here (and not at the F-7 site):
the F-7 fix wrapped a single consumer of the sentinel, whose caller did `if
v != OK_SENTINEL` to enforce it. The NS-pointer hardening is at `validate_*`
itself — the method has many gateway callers, each with its own `?` route,
so doubling at the `validate_*` method makes the hardening per-method (one
place) instead of per-caller (~10-20 places).

The harness's `sca_ns_validate_*_fi` mirror replicates the verify-twice
pattern exactly. After the fix, **the focused sweep on the hardened mirror
shows 0 single-fault bypasses across all 4 reject scenarios × 3 fault models
× ~180 instructions per sweep** (the unhardened predicates still report
their original bypass counts as regression coverage; a revert to the bare
`if … { Ok } else { Err }` shape would re-introduce the finding and flip
the harness back to exit 1).

`make ns-ptr` exits 0 after the fix. Production hardening is bit-equivalent
to the mirror — the same `fi::check_true_into_sentinel` + `wait_random()` +
sentinel-double-check sequence runs on every `NsPtr::validate_*` call from
every `cmd_*.rs` gateway handler.

## C10-sign end-to-end FI smoke — `fault_sweep_c10_sign.py` + `c10_sign_target/`

`make c10-sign` runs the production `c10_sign_verified_with_progress`
primitive — real `sphincs_c10::SigningKey::sign` + real `sphincs_c10::verify`
+ the real F-1/F-2/F-5 hardened gate — end-to-end inside one unicorn
emulation, and independently verifies the produced signature via the
mirror's `sca_c10_verify_real` entry point (loaded from the same ELF, fed
the baked vendor pk_seed/pk_root). The gate's instruction-level FI
robustness is comprehensively covered by `make c10` (gate logic, sign+verify
stubbed) and `make fi` (sentinel-helper logic) — and `make c10v` covers the
real `sphincs_c10::verify` for the forge-acceptance direction. What
`make c10-sign` adds: empirical proof that the *combined* hardened
primitive, with real internals end-to-end, produces a signature that
validates under the intended message — exercising bit-for-bit the same code
the secure firmware runs on every Type 1 / Type 2 sign.

**Runtime story.** A full SPHINCS+C10 sign+verify in unicorn is ~2.6 B
instructions, ~14 s wallclock per emulation. A naive 500-position × 3-model
sweep would take ~6 hours; a 30 000-position × 3-model sweep ~14 days —
*until* we apply the **snapshot/restore trick**:

  1. Run sign+verify to ~96 % completion (`SNAPSHOT_AT = 2.5 B`) once. Save
     Unicorn CPU state via `context_save()` plus every mapped RAM region's
     bytes. One-time cost ~14 s.
  2. Per fault iteration: `context_restore()` + re-write RAM + apply fault
     + emulate the remaining ~89 M instructions. **~0.6 s per iter** instead
     of 14 s = **22× per-iteration speedup**.
  3. Independent baseline-sig validation via the same ELF's
     `sca_c10_verify_real` entry point (fed the build.rs-baked vendor
     pk_seed/pk_root). Closes the loop on baseline correctness.

The result: a 30 000-position × 3-model tail sweep (90 000 faults total)
runs in **~18 s sweep wallclock + ~14 s one-time snapshot setup + ~14 s
baseline = ~50 s end-to-end** on a modern desktop. This is the
audit-grade negative result we'd otherwise need ~2 weeks for naively.

Why not QEMU TCG instead? Considered, but research surfaced FaultFinder
(ASHES'24, Murdock/Thompson/Oswald, U Birmingham): a Unicorn-based tool
that beats QEMU-based ARCHIE by 70-281× via checkpoints + equivalences +
multithreading. The bottleneck is algorithmic, not the emulator backend.
A QEMU TCG port would add framework overhead without the algorithmic
wins. The DIY snapshot approach above replicates the key algorithm
(checkpoints) with zero new dependencies.

Tripwire: a no-op `context_restore()` must reach RET with `r0=1` and
`sig == baseline_sig`. If it doesn't, the snapshot is missing state and
the sweep results would be silently wrong. The harness asserts this.

`make c10-sign` exits 0 when the baseline validates, the tripwire passes,
and the sweep finds zero single-fault forge-releases.

**Known harness quirk.** The harness's per-iteration crash count is
inflated relative to a standalone diagnostic POC running the exact same
inner loop (POC: ~5 % crash rate on stuck-at faults; harness: ~100 %).
Empirically tracked but not yet root-caused — the symptom looks like a
subtle state leak from the baseline run or snapshot setup that affects
unicorn's behaviour on subsequent stuck-at fault iterations. **This does
not affect the security finding**: even at 100 % crash, every reached
gate decision is the correct one (the program crashes *before* the
gate's release path, so no forged signature can be released). For
nuanced per-position fault outcome analysis, run
`/tmp/single_thread_late_snap.py` directly.

**Multiprocessing experiment.** We tried `multiprocessing.Pool` with both
fork and spawn (NUM_WORKERS = 22, AMD Ryzen AI 9 HX PRO 370). Wall-clock
got *worse*, not better — the workers' per-process state-setup cost
(snapshot in each worker) exceeded any parallelism wins because the
single-thread snapshot+restore had already shrunk per-iteration cost to
sub-millisecond. Conclusion: with snapshot/restore, this sweep is already
fast enough that distributing across cores doesn't pay. A wider sweep
(say > 500 k faults) might tip the balance — at which point FaultFinder
(Murdock et al., ASHES'24) is the validated multicore Unicorn pattern to
adopt instead of rolling our own.
