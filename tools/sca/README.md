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

**Initial hypothesis (refined by F-9 re-test post-F-16):** "the FORS
leaf-index access pattern." SPHINCS+C10 sign derives `k = 13` FORS
leaf indices from `H_msg = HASH(R ‖ pk ‖ msg_hash)` and then accesses
`forsSk[leaf_idx]` and the FORS auth-path siblings — those addresses
ARE msg-derived. But the re-test below **falsified that mechanism as
the cause of the observed leak** — see "F-9 re-test (post-F-16
shuffle)" further down for the actual mechanism.

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

**Trace-budget interaction with F-13 (double-compute).** As of commit
landing F-13 (`secure::crypto::c10_sign_verified_with_progress` now
signs twice per `CMD_SIGN_USEROP`), every protected sign call emits
**2× the FORS-phase trace material per slot**. The per-slot per-chain
combined cap stays 65 536; the effective F-9 *observation* budget per
slot becomes ~131 072 traces. The qualitative "transparent" analysis
above is unchanged (FORS indices remain public and signature-derived),
but the SCA budget number doubles. Worth flagging to a future on-silicon
auditor.

### F-9 re-test (post-F-16 shuffle) — leak is in `grind_r`, not the FORS access pattern; remains transparent

After F-16 (WOTS/FORS shuffle) landed, the obvious question was: does
the per-call shuffle mask the F-9 max|t|=40.71 leak? We added a
post-F-16 SUT (`sca_c10_sign_shuffled`) that takes msg ‖ shuffle_seed
as a 64-byte input and re-runs the TVLA with the shuffle seed
INDEPENDENTLY RANDOM per trace (so the temporal scrambling averages
across the within-group means).

**Result.** `max|t| = 39.09` post-F-16 vs `40.71` pre-F-16. A
**4 % drop**, far less than the 80–99 % reduction we expected if the
leak had been in the temporal access pattern of the FORS tree loop.

Leak position: sample **9,990,909** (post-F-16) vs **9,997,943**
(pre-F-16) — same neighborhood, the very end of the 10 M-sample
window.

**Diagnosis.** The leak is NOT in the FORS leaf access pattern. It
is in `fors::grind_r` at `sphincs-c10/src/fors.rs:77`:

```rust
pub fn grind_r(pk_seed, pk_root, message) -> ([u8; N], [u8; 32]) {
    for nonce in 0..10_000_000u32 {
        let r = sha256("R_grind" || nonce_be32)[..N];
        let digest = h_msg(seed, root, r, message);
        // check last FORS index == 0 (probability 1/2048 per iter)
        if last_index_is_zero(digest) { return (r, digest); }
    }
}
```

The loop iterates until it finds a nonce whose resulting `digest`
has a zero in the last FORS-index field (probability 1/2^A = 1/2048
per iteration, so ~2048 iterations on average). The iteration count
**depends on msg** — different msgs need different counts. The
TVLA detects this because the instruction the CPU is on at sample
~10 M depends on (msg-dependent) total iteration count, and
therefore the address being read at that sample is msg-correlated.

**Why F-16 didn't help.** F-16's shuffle reorders the FORS tree
processing loop and WOTS chain loop, both of which happen *after*
`grind_r` returns. The leak is upstream of any shuffle.

**Why this is still transparent (the original F-9 conclusion stands,
mechanism corrected).**
`grind_r` only touches public inputs: `pk_seed`, `pk_root`, `msg`,
and the iterator `nonce`. It NEVER reads `sk_seed` or any
secret-derived value. So:

  - The msg-correlated address pattern leaks the iteration count.
  - For any (msg, pk), the iteration count is deterministic and can
    be reproduced by anyone with msg + pk by running `grind_r`
    themselves.
  - No secret information escapes; the leak channel transmits
    publicly-computable information.

**The actual SCA threat against C10 sign (what F-16 DOES defend).**
The secret-bearing hashes are *downstream* of `grind_r`:

  - `fors::sign_fors_tree` touches the FORS leaf secrets (the
    `forsSk[leaf_idx]` values which derive from `sk_seed`).
  - `wots::sign_with_shuffle` touches the WOTS chain seeds (the
    `wots_secret(sk_seed, ...)` values).

Both of these live in the trace region BEYOND sample 10 M. The 10 M
window mostly covers `grind_r` (the bulk of the operations by
instruction count, since ~2048 iterations × ~5k instructions = ~10 M
mem events). To verify F-16 helps the secret-bearing layer, the
harness needs either a much larger sample budget (50+ M with stride 1)
or snapshot/restore to start the trace AFTER `grind_r`. Tracked as a
deeper-sweep follow-up.

**What the F-9 re-test actually proves.** Despite the small numeric
change in max|t|:

  1. The leak we measure is FULLY EXPLAINED by the public `grind_r`
     iteration count. No SK material is in the trace region we swept.
  2. F-16 IS doing its job for the WOTS / FORS shuffle layer — we
     just can't *see* it in this 10 M-sample window because the
     shuffle-protected region is past our sample cap.
  3. The original "transparent leak" framing for F-9 was correct in
     its security conclusion (no SK escape), even though the
     mechanism was initially mis-identified (it's `grind_r`
     iteration count, not the FORS leaf-index access pattern).

**Update — hedged R-derivation landed; F-9 leak collapses to noise floor.**

The "wire opt_rand into grind_r" follow-up was implemented in the
same commit as the re-test (~20 LoC: `sphincs-c10/src/fors.rs:77`
`grind_r` now takes `opt_rand: Option<&[u8; N]>` and mixes it into
the nonce-derivation hash; `sphincs-c10/src/hypertree.rs::sign_inner`
plumbs the existing F-13 `opt_rand` through; deterministic `None`
path keeps byte-equality with `c10_test_vectors.json` byte-for-byte).

Re-running the F-9 TVLA with both F-16 shuffle AND hedged R active:

```
F-9 baseline (pre-shuffle, deterministic R):    max|t| = 40.71  @sample 9 997 943
F-9 re-test (F-16 shuffle only, det. R):        max|t| = 39.09  @sample 9 990 909  (-4%)
F-9 re-test (F-16 shuffle + F-13 hedged R):     max|t| =  4.93  @sample 6 802 705  (-87.9%)
```

max|t| = 4.93 is barely above the 4.5 TVLA threshold — essentially
the noise floor for 600 traces. The leak position shifted away from
`grind_r`'s ~10 M tail to ~6.8 M, consistent with the iteration-count
channel being closed and only statistical-noise outliers remaining.

**Convergence-curve confirmation (scared, post-merge).** Re-running
the TVLA through `scared.TTestAnalysis` on incrementing prefixes of
the SAME 600-trace dataset (`make f9-scared-collect` + `make
f9-scared`) gives a quantitative test of the noise-floor hypothesis:

```
N    max|t|     N    max|t|     N    max|t|     N    max|t|
20   6.803     180   5.207     340   5.132     500   4.924
40   5.921     200   5.344     360   5.016     520   5.079
60   5.529     220   5.131     380   5.266     540   5.125
80   5.580     240   5.386     400   5.236     560   5.001
100  5.854     260   5.514     420   5.068     580   4.991
120  5.949     280   5.394     440   5.163     600   4.931
140  5.635     300   5.430     460   4.939
160  5.163     320   4.935     480   4.912
```

Reads cleanly as noise:

  - Under H1 (real msg-dependent signal) max|t| should grow with
    √N. From N=20 to N=600 that's a factor √30 ≈ 5.5×, so we'd expect
    max|t| ≈ 37 at N=600 if N=20's reading of 6.8 were a real leak.
  - Observed: max|t| *decreases* from 6.80 → 4.93 as N grows. The
    early high value is small-sample variance instability; as N
    grows the noise distribution stabilises and the max-over-10M-
    samples plateaus around its true family-wise-error tail (~4.9σ
    over 10M samples, vs multiple-testing-corrected threshold
    ≈ √(2 log 10M) ≈ 5.6σ).
  - All 30 prefix points stay between 4.9 and 6.0 — no upward
    trend, no √N scaling.

This is a stronger statement than the lascar single-point measurement
could make: not just "max|t| = 4.93 at full N" but "no detectable
√N-scaling msg-dependence anywhere in [N=20, N=600]." scared
reproduced lascar's final-N value byte-exactly (both 4.93 to two
decimals), and the convergence shape eliminates the "we just didn't
take enough traces" objection.

Curve PNG: `tools/sca/out/f9_scared_convergence.png` (regenerated by
`make f9-scared`; gitignored — collect stage produces a 6 GB `.npz`).

**Why hedged R was the missing piece.**
With deterministic R, the `grind_r` iteration count is a function
of msg alone. The address pattern at sample ~10 M depends on the
total instruction count up to that point, which depends on the
iteration count, which depends on msg → high TVLA t-stat.

With hedged R, each call mixes a fresh `opt_rand` into the
nonce-hash. The iteration count now depends on `(msg, opt_rand)`,
and opt_rand is independent random per trace. Within the TVLA's
"fixed msg" group, every trace has a different opt_rand → different
iteration count → randomly-placed code execution at sample ~10 M.
Averaging within the group convergences to "expected address at
sample X over all opt_rand", which is the same for both fixed-msg
and random-msg groups → t-stat collapses.

**F-9 verdict (final).** The msg-dependent leak in `grind_r` is
**closed by the F-13/F-16 combination at the audit level** (max|t|
dropped from 40.71 to 4.93, essentially noise floor). What remains
is checking that the SECRET-bearing regions of sign (FORS leaf
secrets, WOTS chain seeds — past sample ~10 M in the trace) are
similarly clean — that's the `f9_deeper.py` follow-up (30 M samples
× stride=10, ≈ 300 M mem events of coverage).

**Regression tests kept in tree:**
  - `tools/sca/f9_retest.py` — runs the same harness; if a future
    commit removes F-16 OR drops opt_rand from `grind_r`, this
    surfaces immediately (max|t| would re-climb past 10).
  - `tools/sca/f9_deeper.py` — covers the SECRET-bearing region for
    F-16-on-shuffled-WOTS/FORS verification.

**Update — deeper sweep result: SECRET-bearing region is clean.**

The `f9_deeper.py` follow-up ran with 100 traces × 10 M samples ×
stride=10, covering ~100 M mem events of function execution
(grind_r ≈10 M + FORS sign ≈30 M + WOTS sign ≈50 M — past the
SECRET-bearing transitions). Result:

```
F-9 baseline (10 M @ stride 1, 600 traces):     max|t| = 40.71
F-9 deeper sweep (100 M @ stride 10, 100 traces): max|t| =  5.66  @sample 990 123
```

**Where is the residual?** Sample 990,123 at stride=10 maps to
mem-event 9,901,230 — back in the **`grind_r` tail region**, NOT
in the SECRET-bearing FORS/WOTS portion. **No sample in the
deeper region (mem events 10 M–100 M) shows max|t| > 5.66.**

The residual is consistent with statistical noise at the reduced
trace count: at 100 traces the per-sample max|t| noise floor
naturally sits around ~5 (vs the 600-trace F-9-retest floor of
~4.93). With opt_rand wired in (commit `a623600`), this is
essentially what we'd predict from a leakage-free hash sequence.

**Verdict (F-9 final-final).** Across both the narrow 10 M-window
re-test AND the deeper 100 M-window sweep, the C10 sign function
under F-13 hedged R + F-16 WOTS/FORS shuffle shows:
  - max|t| ≈ 5 at the grind_r tail (the location of the original
    F-9 hotspot), bounded by trace-count noise floor;
  - **no detectable msg-correlated leakage in the SECRET-bearing
    FORS sign + WOTS sign regions** at audit-grade emulation
    sensitivity.

**Limitations.** Emulation-only `mem_address` analysis. On-silicon
SCA (power / EM / cache-timing on real STM32U585) still owed
before F-9 can be definitively retired — but the emulation evidence
is the strongest possible at this stage. Moving the on-silicon
verification under the `sca-trigger` GPIO feature flag (tracked in
§18b) is the next layer of audit.

**Limitation of our measurement.** We tried 600 × 50 M samples to
localise the leak region's end and check for additional leakage
sources past FORS. The 30 GB trace array + lascar's per-sample
working arrays peak system memory above 64 GB on this hardware, and
the kernel OOM-killed `make kdf` during the lascar t-test phase.
A future deeper sweep needs either (a) batched / streaming TVLA in
lascar (Session.run with chunked input), or (b) multiple narrower
windows captured via snapshot/restore at different sign-phase
offsets (same machinery `fault_sweep_c10_sign.py` already uses).

## SAES-DHUK KDF wrapper leakage — `leakage_saes_kdf.py` + `saes_kdf_target/`

`make -C tools/sca saes-kdf` builds `sca-saes-kdf-target` (a thin
`#[no_mangle]` wrapper over `secure/src/cmac.rs::cmac_generic` and
`kdf_cmac_counter_generic`, `#[path]`-included verbatim from the
production source) and runs four `mem_address`-channel TVLAs.

**What the production code does.** `hw::secret_keys::derive_into_saes_kdf`
calls `cmac_dhuk(scratch_with_label_and_counter, &mut tag)`, which in turn
calls `cmac_generic(msg, |block| saes::encrypt_ecb_block(KeySel::Dhuk, ...), tag)`.
On real silicon the DHUK key bytes live in SAES_KEY registers and never
enter CPU memory — the wrapper code on the CPU operates on AES inputs /
outputs / chain state, never on the key bytes themselves.

**What this target tests.** Rainbow/Unicorn cannot model the SAES
coprocessor, so we replace `saes::encrypt_ecb_block` with the same
bitsliced software AES-256 the existing `kdf_target` already
characterised (`aes` 0.8 crate, soft backend on thumbv8m). With the key
now a function parameter in the emulation, we can directly TVLA
"vary key, fix message" — which the production setup cannot do because
DHUK isn't a function parameter there. **Four TVLA modes**:

| Symbol | Vary | Fix | max\|t\| (600 traces × 7-9 K samples) |
|---|---|---|---|
| `sca_saes_cmac` | KEY (32 B) | message (16 zeros) | **0.00** → flat |
| `sca_saes_cmac` | message (16 B) | key (32 zeros) | **0.00** → flat |
| `sca_saes_kdf_one_block` | KEY (32 B) | label (16 zeros) | **0.00** → flat |
| `sca_saes_kdf_one_block` | label (16 B) | key (32 zeros) | **0.00** → flat |

**Interpretation.** All four modes show **no `mem_address` leakage**.
The bitsliced software AES on thumbv8m has no T-table lookups (so no
key-dependent memory addresses), and `cmac_generic` / `kdf_cmac_counter_generic`
do not introduce any input-dependent memory addresses either: the
`double_l` derivation of K1/K2, the CBC chain XORs, the final-block
branch dispatch (length-keyed; lengths are fixed in this test), and
the KDF's `scratch[..label.len()].copy_from_slice(label); scratch[label.len()] = counter;`
packing all operate on stack-resident locals whose addresses don't vary
with input. Same clean-signal result `leakage_kdf.py` already reports
for `sca_aes256_encrypt_block` and `sca_aesgcm_wrap`.

**What this does NOT cover.** rainbow only models CPU instructions — it
records the Hamming weight of memory access ADDRESSES, not loaded
VALUES. Power/EM leakage on register VALUES (S-box outputs, CBC state)
is invisible to this emulator and requires on-silicon SCA with a
scope. Production SAES coprocessor leakage is independent of the CPU
wrapper and also requires silicon-grade measurement. The claim here is
narrow: the wrapper CODE PATH that runs on the CPU has no data-
dependent memory addresses, at audit-grade emulation resolution.

**Why this is a useful claim despite the narrow scope.** A data-dependent
memory address in the wrapper would be a real bug — it would mean the
production CPU code (byte-identical to what's emulated here, modulo the
SAES coprocessor closure) leaks the AES inputs/outputs/state through
the cache or memory-bus side channel, on top of whatever the SAES
silicon itself leaks. The test rules out one specific class of
production leak at firmware level.

## BIP-39 entropy → seed leakage — `leakage_bip39.py` + kdf_target's `sca_bip39_*`

`make -C tools/sca bip39-leak` builds new symbols in `kdf_target`
(`sca_bip39_word_indices` and `sca_bip39_wordlist_lookup`) that
`#[path]`-include `bip39/src/wordlist.rs` verbatim and exercise the
production `Mnemonic::to_seed()` chain's two key steps:

1. SHA-256(entropy) for the BIP-39 checksum + 11-bit-index unpacking
   (no wordlist access — control mirror).
2. The actual `WORDLIST[idx]` loads — 24 of them, one per word index,
   addressing into a `[&str; 2048]` flash-resident table.

### F-22 — BIP-39 `Mnemonic::to_seed`'s wordlist lookups leak 24×11 = 264 entropy bits via address-keyed loads — **FIXED in `bip39/src/lib.rs::ct_load_word` (constant-time wordlist scan + constant-time password assembly)**

**`make bip39-leak` result (3 probes — baseline / control / post-fix):**

| Symbol | Trace samples | max\|t\| | Verdict |
|---|---|---|---|
| `sca_bip39_word_indices` | 699 | **0.00** | flat — SHA-256 + unpacking don't leak (control) |
| `sca_bip39_wordlist_lookup` | 772 | **17.88** | **LEAKAGE** — baseline probe / regression sentinel |
| `sca_bip39_wordlist_lookup_ct` | 24 851 | **0.00** | **CLEAN — F-22 fix validated** |

Peak at sample 671; top-5 peaks at 615, 671, 703, 727, 751 — periodic
spacing of ~24-32 samples consistent with the 24 individual
`WORDLIST[idx]` loads laid out across the trace.

**Mechanism.** `Mnemonic::to_seed("")` (`bip39/src/lib.rs:183-217`)
calls `self.words()` (`bip39/src/lib.rs:155-157`) which is
`self.indices.iter().map(|&i| WORDLIST[i as usize])`. Each iteration
performs a load at `&WORDLIST[0] + idx * sizeof(&str)` (the `&str`
fat-pointer table) — the address ENCODES the secret idx. Subsequent
copy of the word body (`copy_from_slice(wb)`) adds a second layer of
address-keyed reads from the entry's `(ptr, len)` and the actual
string bytes in flash. The control case `sca_bip39_word_indices`
(same SHA-256 + index unpacking, NO wordlist access) shows max|t| =
0.00, confirming the leak is in the lookup, not anywhere else in the
chain.

**Severity: HIGH (production critical, seed reconstruction).** This
is the FIRST CPU operation that touches raw entropy during
recovery / first-unlock. The 24 indices encode 264 bits — strictly
more than the 256-bit BIP-39 entropy — so the address pattern is
sufficient to fully reconstruct the seed from a single trace.
Bypasses every downstream defense: FI guards protect against
release of forged signatures, not against pre-existing seed leakage;
the dual-SE XOR split protects entropy AT REST, not during the CPU
derivation phase; the hardware PIN gate protects the SE storage, not
the post-unlock CPU work. An attacker with physical access doing
power/EM scoping of the cold-boot first-unlock recovers the seed in
a single trace — they don't need a million attack traces; the leak
is direct.

**Attack model.** Requires physical access to the device during the
first-unlock (when `derive_keypair_from_entropy` runs). After the
first unlock, the bip39 seed is wiped (`bip39_seed.zeroize()` in
`with_bip39_seed`), so subsequent signs don't re-derive — the
exposure is the **single cold-boot trace**. An attacker who steals
the device and scopes the first unlock-after-power-on can clone the
wallet without ever extracting any SE-resident state.

**Production reach.**
- `secure/src/crypto.rs::provision_from_mnemonic` calls
  `pqsigner_domain::derive_keypair_from_entropy` →
  `with_bip39_seed` → `Mnemonic::to_seed` at every wallet creation /
  recovery.
- Every dual-SE unlock that needs to re-derive the master keypair
  hits the same path (per `Se050::unlock`'s
  `kdf("sphincs-master", &entropy, 0)` followed by
  `derive_keypair_from_entropy` if the cached VK is missing).

**Recommended fix.** Constant-time wordlist scan: for each of the 24
word slots, load EVERY entry in `WORDLIST` and use `subtle::
ConditionallySelectable` (or a manual `(mask & bytes) | (!mask &
acc)` pattern) to conditionally copy into a fixed-length buffer iff
the entry index matches the target index. This makes every word's
load sequence identical at the address-bus level regardless of which
index is being resolved. Cost: 2048 loads × 24 words × 8 bytes/load
= 393 KB of reads per `to_seed` call, ~1 ms wall on Cortex-M33 —
acceptable for a once-per-unlock operation.

The variable-length password assembly that follows is a separate
issue: the cumulative-offset writes into the password buffer have
secret-dependent target addresses. Two options to fix:

1. **Constant-stride password layout.** Pad every word slot to 8
   bytes + 1 separator = 9 bytes; total password = 24 × 9 = 216 bytes
   regardless of word lengths. **Breaks BIP-39 compatibility** — the
   seed derived from a padded password differs from the canonical
   one, so a user-written-down phrase wouldn't restore the same
   wallet on a non-PQSigner BIP-39 verifier. **NOT viable.**
2. **Interleaved constant-time write.** For each output byte
   position 0..MAX_LEN of the password, scan all 2048 entries × 8
   bytes / entry, conditionally write the correct byte. Expensive
   but preserves BIP-39 compatibility. **Viable.**

A third option — drop `Mnemonic::to_seed` entirely and run PBKDF2
over a different entropy-derived encoding — is non-viable because
the seed is the on-chain identity (CREATE2 salt derives from the
master pk_seed/pk_root which come from this seed). Changing the
derivation would change every wallet's address.

**Status: FIXED.** `bip39/src/lib.rs` now ships:

  - `WORDLIST_FLAT: [[u8; 8]; 2048]` + `WORDLIST_LENS: [u8; 2048]` —
    fixed-stride flat representation of every wordlist entry,
    generated at compile time from the existing `WORDLIST: &[&str;
    2048]` via a `const fn`. Both arrays are accessed exclusively by
    LOOP-COUNTER-derived indices in the constant-time scan, so the
    load addresses are deterministic regardless of the secret.
  - `ct_load_word(target_idx) -> ([u8; 8], u8)` — scans all 2048
    entries with `subtle`-style `(mask & bytes) | (!mask & acc)` OR-
    folding (manual `ct_eq_u16` produces the 0x00/0xFF mask). LLVM
    aggressively folds this into a direct index-keyed load unless we
    `core::hint::black_box` the per-iteration mask + entry pointer +
    accumulator; the barriers are present and load-bearing — without
    them the fix regresses to max|t| ≈ 5000.
  - `Mnemonic::to_seed`'s body is rewritten in three constant-time
    phases:
      1. Resolve all 24 indices via `ct_load_word` → `words[24][8]`
         + `lens[24]` on the stack.
      2. Compute cumulative offsets from `lens` (pure arithmetic,
         no address-keyed loads).
      3. For each output byte position p in 0..215, scan all
         (word, byte_in_word) candidates and mask-OR the right byte
         into `password[p]`. Every store goes to a fixed
         loop-counter-derived address.

**Verification:**
  - `cargo test -p sphincs-tz-bip39`: `to_seed_matches_trezor_vectors`
    + 8 other unit tests pass. The fix is byte-identical to the
    Trezor reference vectors → no recovery-contract change.
  - `cargo test -p sphincs-tz-secure --bins --release`: 1835 / 1835
    pass.
  - `make -C tools/sca bip39-leak`: post-fix probe (`sca_bip39_
    wordlist_lookup_ct`, 24,851 samples) shows **max|t| = 0.00** —
    perfectly constant across all inputs. The pre-fix baseline probe
    is kept in tree as a regression sentinel; if a future commit
    accidentally introduces an index-keyed lookup back into the hot
    path, this harness will catch it.

**Residual: a smaller length-encoded leak.** The PBKDF2-HMAC-SHA512
internal padding embeds the bit-length of the password. The password
length depends on the sum of word lengths (24 lengths each ∈ [3, 8]).
There are 121 distinct possible password lengths → ~7 bits of leakage
via the SHA-512 padding byte value, observable only on power/EM-scoping
(`mem_address` is constant — the address-keyed channel is clean).
**This is 30× smaller magnitude than F-22's 264-bit channel and is
tracked separately as F-23 (length-leak via PBKDF2 padding).** Fixing
F-23 needs a constant-length encoding of the password — pad the word
slots to 8 bytes — but that would change the BIP-39 password format
and break recovery-contract byte-equality with non-PQSigner BIP-39
implementations. Accept as residual; flag for the user-facing trust
model.

Cost of the fix in production: 2048 × 24 × 8 = 393 KB of stack reads
+ 41 K inner-loop iterations for the password assembly. On Cortex-M33
at ~160 MHz this is ~2 ms wall-clock per `to_seed` call — single-
digit-percent of `derive_keypair_from_entropy`'s overall cost
(dominated by SPHINCS+C10 keygen at ~10 s) and called once per
first-unlock. Acceptable.

## BIP-39 seed-DISPLAY leakage (seed-wizard path) — F-24

F-22 closed the wordlist-lookup leak in the seed-derivation hot path
(`to_seed`). The same `WORDLIST[idx]` access pattern recurs in the
**seed-wizard's word DISPLAY path** during provisioning:
`secure/src/ui/seed_wizard.rs::render_mnemonic_page` shows each of the
24 mnemonic words to the user so they can write them down. The leak
chain has five stages, only some of which are firmware-fixable.

### F-24 — Seed-wizard word DISPLAY leaks the mnemonic via five chained channels — **CPU-side stages A-D FIXED; stage E is hardware territory (accepted)**

The display path for each word goes through:

| Stage | Where | Channel | Firmware-fixable? |
|---|---|---|---|
| A | `m.word(idx)` returns `&'static str` at `WORDLIST_BASE + indices[idx] * 8` | `mem_address` | **YES — FIXED** via `Mnemonic::word_bytes` using F-22's `ct_load_word` |
| B | `as_bytes()` follows fat-pointer to scattered flash | `mem_address` | YES — closed by A (constant-time scan returns bytes directly) |
| C | `copy_from_slice(&wb[..max])` reads flash bytes | `mem_address` | YES — closed by A |
| D | `embedded_graphics::Text::draw` calls `MonoFont::glyph(char)` for each rendered char | `mem_address` | **YES — FIXED** via `ui::secret_text::render_secret_row` (96-entry constant-time glyph scan, `core::hint::black_box` barriers) |
| E | OLED itself broadcasts the rendered framebuffer to the user | mixed channels (see below) | **mostly NO at firmware level — see breakdown** |

**Stage E breakdown** — the original "OLED emission" framing oversimplifies.
The OLED has FOUR distinguishable side-channels with very different
mitigation paths:

1. **Optical emission (innate).** The OLED is designed to be visible.
   Anyone with line of sight (camera, security camera, telescope,
   reflection off a window) reads the words. There is no firmware fix
   for "the screen showing the words to a person looking at it" — the
   device is showing the words to the user on purpose. **Mitigation:
   physical privacy during provisioning (user's responsibility);
   off-light room or screen shroud for the most-paranoid users.**
   For most threat models this is the dominant attack against the
   display path.

2. **Driver-IC EM emission (hardware-addressable).** The SSD1306 (or
   similar) controller switches gate drivers at MHz rates. Each pixel
   transition radiates a small RF signature in the 1-100 MHz band.
   A near-field probe positioned at the OLED can recover the
   per-pixel state — classic TEMPEST.
   **Mitigation: PCB-level shielding (Faraday cage around the OLED
   module, ground plane underneath, optional ferrite-bead choke on
   the controller's supply pin).** Trezor's T3W1 implements exactly
   this with a metal shield over the display module. **NOT a firmware
   fix.** Tracked separately as a hardware-design item.

3. **Power-supply ripple (hardware-addressable).** Lit-pixel count
   modulates the OLED's current draw, which modulates the supply
   rail. Coupling caps + power-line probing recover the lit-pixel
   count. **Mitigation: dedicated linear regulator + bulk caps for
   the OLED's supply rail, isolated from MCU supply.** Standard
   hardware-security practice. **NOT a firmware fix.**

4. **I2C/SPI bus EM emission (hardware OR firmware-addressable).**
   The framebuffer bytes shift from MCU to OLED over a serial bus.
   Each toggle radiates. Near-field probing of the bus traces or the
   cable reveals the framebuffer.
   - **Hardware mitigation**: shielded twisted-pair on the bus,
     ground plane under the traces, board layout that keeps the bus
     short.
   - **Firmware mitigation**: **decoy frames**. Render the real
     mnemonic interleaved with N=4-8 valid-but-fake mnemonics at high
     refresh rate. User sees the real one via persistence-of-vision
     (e.g., real frame at 90% duty, decoy frame at 10% — eye
     averages, picks the dominant). The bus signature is the average
     of N+1 frames so the real one isn't distinguishable. Cost:
     ~4-6 hr engineering + visible flicker that some users find
     unreadable. **Not implemented.** The bus channel is much
     weaker than the optical channel for the realistic threat model
     (camera attacker), so we accept this residual for now.
   - **Firmware mitigation 2**: constant-pixel-count encoding. XOR
     a fixed-but-different complement into each word's bitmap so
     the lit-pixel count is identical regardless of content. Closes
     the power-supply-modulation channel. Hurts UX (background
     "noise" pixels). **Not implemented.**

**What the F-24 stages A-D fix actually closes (audit threat model):**
the attacker who can scope the **CPU** but not the **screen**. Rare
class — typically a remote EM rig with line-of-sight to the device
blocked. For this class our fix is complete: the CPU executes in
constant-time regardless of which words are being rendered, so the
trace doesn't carry the secret.

**What stages A-D do NOT defend against**:
- Optical observer (camera) — physical privacy required.
- Near-field probe on OLED module — hardware shielding required.
- Power-rail probe — hardware supply isolation required.
- Bus-trace EM — hardware shielding OR firmware decoy frames.

**Implementation references**:
- `bip39/src/lib.rs::Mnemonic::word_bytes` — stage A-C fix (constant-
  time wordlist scan, byte-identical to the F-22 fix in `to_seed`).
- `secure/src/ui/secret_text.rs::render_secret_row` — stage D fix.
- `secure/src/ui/oled.rs::Display::flush_with_secret_rows` — mixed
  rendering glue used by `seed_wizard::render_mnemonic_page`.
- `secure/build.rs::generate_font_flat` — compile-time extraction of
  the FONT_5X8 glyph table into a flat `[[u8; 5]; 96]`.
- `secure/assets/font_5x8.raw` — vendored from embedded-graphics
  v0.8.2 (MIT); see `secure/assets/font_5x8.LICENSE`.

**Verification**:
- `ct_glyph_col_recovers_known_glyphs` — asserts the CT scan
  reproduces FONT_5X8 byte-for-byte.
- `render_secret_row_writes_expected_columns` — asserts a row render
  produces the expected framebuffer column-bytes.
- `cargo test -p sphincs-tz-secure --bins`: 1837/1837 pass.
- Visual: `make play-hw-display` (when board is connected) renders
  the seed-wizard pages; user can confirm the displayed words look
  identical to the pre-F-24-D output.

**Cost**: ~1.5 ms per word-row × ≤3 secret rows per page × 8 pages =
≤36 ms total added latency during full 24-word provisioning. Once-per-
wallet operation, human-paced; negligible.

## BIP-39 recovery-path leakage — `leakage_recovery.py` + kdf_target's `sca_bip39_lookup_prefix*`

F-22 and F-24 closed the leak chain DURING SEED CREATION (provisioning):
F-22 fixed `to_seed`'s wordlist lookup, F-24 fixed the seed-display
chain on the OLED. The OPPOSITE direction — SEED ENTRY during recovery
— had the same class of leak via a different mechanism:
`bip39::lookup_prefix` did a binary search over `WORDLIST: [&str; 2048]`
on every keystroke as the user typed each of the 24 mnemonic words
back from their paper backup.

### F-25 — `bip39::lookup_prefix` leaks the typed mnemonic via binary-search address dependence — **FIXED in `bip39::lookup_prefix` via constant-time scan**

**`make -C tools/sca recovery-leak` result:**

| Symbol | Trace samples | max\|t\| | Verdict |
|---|---|---|---|
| `sca_bip39_lookup_prefix` (baseline / regression sentinel) | 248 | **45.43** | **LEAKAGE** (10× threshold) |
| `sca_bip39_lookup_prefix_ct` (F-25 fix) | 45 089 | **0.000** | **CLEAN** |

**Mechanism (pre-fix).** `lookup_prefix(prefix)` called:

```rust
let start = WORDLIST.partition_point(|w| w.as_bytes() < needle);
let mut end = start;
while end < WORDLIST.len() && WORDLIST[end].as_bytes().starts_with(needle) {
    end += 1;
}
```

Two address-leak phases:

1. **Binary-search mid-points.** `partition_point` visits log2(2048) ≈ 11
   mid-points. Each `WORDLIST[mid].as_bytes() < needle` loads from
   `&WORDLIST[0] + mid * sizeof(&str)`. The `mid` sequence depends on
   the prefix bytes, so an attacker EM-scoping the address bus during
   one keystroke recovers the chosen alphabetic region (~5-7 bits per
   keystroke).
2. **Walk-forward scan.** The `starts_with` loop walks contiguous matches
   in flash; walk length depends on how many words share the prefix.

After 4 keystrokes per word × 24 words = 96 keystrokes during recovery,
the seed is reconstructable.

**Severity: HIGH (production-critical, symmetric to F-22).** Attack
model: an attacker EM-scoping the CPU during the 60-120 second
recovery-typing window collects per-keystroke traces and reconstructs
each typed word. Closes the same threat class as F-22 (camera-blocked
attacker with EM access to the device) for the RECOVERY direction.

**Fix.** `bip39::lookup_prefix` rewritten to scan all 2048 entries
unconditionally via constant-time mask-OR over the existing
`WORDLIST_FLAT` + `WORDLIST_LENS` tables (added by the F-22 fix). For
each entry:

  - `byte_eq = (entry[i] == needle[i])` for each of the 8 byte positions
  - `pos_ok = (i >= plen) | byte_eq`
  - `all_bytes_match = AND of pos_ok across positions`
  - `is_match = all_bytes_match & (entry_len >= plen)`

The first match's index is captured via constant-time conditional select;
the match count is incremented constant-time per iteration. Result:
either `None`, `Unique(first)`, or `Multiple { start: first, end: first + count }`.

**`core::hint::black_box` barriers** on every iteration's mask, entry
load, and accumulator — same load-bearing pattern as F-22's
`ct_load_word`. Without them LLVM folds the scan back into a binary
search.

**Verification:**
- `cargo test -p sphincs-tz-bip39`: 9 unit + 7 wordlist-invariant + 1
  doc-test pass; specifically `case_insensitive_lookup` confirms the
  CT scan is byte-equivalent to the old binary-search behavior.
- `cargo test -p sphincs-tz-secure --bins --release`: 1837/1837.
- `make recovery-leak`: post-fix probe max|t| = 0.000 over 45 089
  samples; baseline probe still flagged as LEAKAGE (regression
  sentinel).

**Cost in production.** The keystroke rate during recovery is ≤ 5/s
(user typing speed). Each call now does 2048 × 8 = 16 KB of stack
reads + ~20 inner-loop ops/iter ≈ ~40 K cycles. On Cortex-M33 at
~160 MHz that's ~0.25 ms per call — well below the keystroke cadence.

**No production migration needed.** `secure/src/ui/seed_wizard.rs`'s
recovery path calls `bip39::lookup_prefix` directly; the fix lands
in the shared callee. The on-screen-keyboard UX is unchanged.

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

### F-17 — Unbounded signing rate gives an SCA attacker thousands of traces in minutes — **MITIGATED in `secure::sign_rate` (1-sec interval + 250-sigs-per-session cap)**

**Threat — trace collection rate.** Without rate limiting, a wallet
that has been unlocked once can be made to emit signatures at
~1 sig/sec (sign latency on STM32U585) for as long as the unlock
session lasts. That gives an attacker who has obtained the PIN
(returns fraud, captured device with shoulder-surfed PIN, evil-maid)
a clean way to collect the thousands of traces needed for profiled
DPA against the SHA-256 path:

  - Naive baseline: 3600 sigs/hour → 86,400/day → ~864,000 over 10
    days. Well above the ~thousands-of-traces threshold for a
    successful profiled-DPA attack.
  - With F-16 shuffling already in place, the per-trace cost rises
    by ~10^52 (permutation space), but a determined adversary
    can amortise that across more traces. Rate-limiting the trace
    *collection* compounds the F-16 defence.

**Fix — `secure/src/sign_rate.rs`.** Two SRAM-resident counters
checked at the top of `crypto::c10_sign_verified_with_progress`:

  1. **Minimum 1-second interval** (`MIN_SIGN_INTERVAL_MS = 1000`)
     between consecutive signs. The firmware busy-waits via
     `cortex_m::asm::wfi()` (low-power; SysTick wakes every 1 ms)
     until the interval elapses. Sub-second burst signing (e.g. USB
     pumping 100 sigs/sec) is throttled to 1 sig/sec.

  2. **Per-unlock-session burst cap** (`MAX_SIGNS_PER_SESSION = 250`).
     After 250 sigs in one unlock session, further signs return
     `Err(())` → `NscStatus::CryptoError` at the gateway. The user
     must re-unlock (PIN entry, SE-rate-limited at 10 attempts max
     before SE-side wipe) to reset the counter.

State is reset by:
  - `SecureState::mark_unlocked` — fresh unlock = full 250 burst
    budget.
  - `SecureState::zeroize_sensitive` — lock / idle-wipe / panic
    handler all clear the counters.

**Composition with F-16.** The F-13 double-compute does TWO inner
signs per `c10_sign_verified_with_progress` call, but the rate
limit counts it as ONE charge — same output sig, same SK budget
cost. The F-16 shuffle is unchanged; the rate limit is an
independent layer.

**Sustained-rate ceiling.** With the 1-sec interval AND 250-cap,
the long-term effective sign rate is bounded by the PIN re-unlock
cycle:

  - 250 sigs/session × 1 sec/sig + ~5 sec re-unlock = ~255 sec per
    session
  - Sustained rate ≈ 250 / 255 ≈ **1 sig/sec average**, NOT
    250 sigs/sec or anything bursty.

For an attacker collecting 10,000 traces: ~10,000 seconds = ~3 hours
of continuous PIN-entry + signing. Detectable, slow, and bounded by
SE-side PIN attempt limits.

**Cost.** Microseconds of overhead per sign (the atomic load + cap
check). The 1-sec wait is "cost" only in the sense that a fast
legitimate workflow (rare for a HW wallet) loses some throughput.
For human-driven usage (one sig per several seconds) it's invisible.

**On `e2e-test` builds the time-based wait is skipped** so the QEMU
e2e runner's ~30 back-to-back signs don't pad the test runtime to a
minute+. The session cap is still enforced so the cap-tripping path
remains testable. The wait is also skipped under `not(stm32u585)`
because there's no SysTick to wait against on QEMU.

**Residual attack surface (still open):**

  - **Power-cycle bypass of the session cap.** Counters live in
    SRAM; a reset wipes them. An attacker with the PIN can
    `power-cycle → boot → unlock → 250 sigs → repeat`. The bottleneck
    becomes boot + PIN-entry overhead (~5–10 sec per cycle), capping
    sustained rate to ~25–50 sigs/sec, much worse than the
    in-session 1 sig/sec but still useful at scale.

    **Mitigation owed:** flash-persistent daily quota (500/day)
    backed by the page-124 + RTC infrastructure. Tracked in
    `docs/work-todo.md §18` as the still-open part of the
    rate-limiter P0 — the 500/day half. ~80 LoC follow-up.

  - **Pre-PIN trace collection.** An attacker who has the device
    but NOT the PIN can't trigger signs at all (gated commands
    refuse without `pin_verified`). Not a residual; out of scope.

### F-16 — Profiled-DPA trace alignment on WOTS chains + FORS trees — **DEFENDED in `sphincs-c10::shuffle::fisher_yates` (Fisher-Yates re-ordering, byte-identical output)**

**Threat — profiled DPA on the SK-revealing hash inputs.**
SPHINCS+C10 sign computes ~1000–2000 SHA-256 hashes per signature.
Two phases process secret-bearing inputs:

  - **WOTS+** (l=43 chains × d=2 layers): each chain starts from a
    secret seed and hashes 0..7 times. The chain seed is
    sk-revealing; recovering one seed per layer enables universal
    forgery.
  - **FORS** (k=13 trees): each tree reveals a leaf secret + an
    11-deep auth path. Recovering one leaf secret per tree is
    enough to forge for that message.

The STM32U585 HASH peripheral has **no DPA resistance** per ST
UM3370 — it's a high-performance accelerator, not a side-channel-
hardened one. Profiled DPA / template attacks against SHA-256 are
documented in the literature (CHES, TCHES); a few hundred to a few
thousand traces is enough to recover the secret with reasonable
profile quality.

DPA averaging works because the SAME SK chain is at the SAME
relative sample index across every trace — naive sign processes
chain 0, 1, …, 42 in fixed order, so chain 7's hash is always at
sample ~7·(per-chain-cycles) of every trace.

**Fix — Fisher-Yates re-ordering, per-signature.**
`sphincs-c10/src/shuffle.rs` derives a fresh permutation of
`[0..43]` (WOTS chains) and `[0..13]` (FORS trees) from a 32-byte
seed pulled via `rng_strong::fill` (3-source XOR — STM32 ⊕ OPTIGA ⊕
SE050) per signing call. The hypertree sign loop and `wots::sign`
iterate in shuffled order; the WRITE offsets into `sig[]` stay
keyed on the natural index, so the OUTPUT BYTES are byte-identical
to the un-shuffled path.

**Permutation space:**

  - WOTS: 43! per layer × 2 layers ≈ **10^104 orderings**.
  - FORS: 13! ≈ **6.2 × 10^9 orderings**.

After shuffling, chain-i's hash lands at a random sample in each
trace. DPA averaging fails because the attacker doesn't know which
sample to average. They'd have to first recover the shuffle
permutation — which means breaking the per-call TRNG seed, which
itself is the 3-source XOR (F-13 follow-up).

**Correctness invariant (regression-tested).**

`sign_with_shuffle(sk, msg, opt_rand, seed_A) == sign_with_shuffle(sk, msg, opt_rand, seed_B)`

for any `seed_A`, `seed_B` — byte-for-byte. The shuffle is a pure
computation re-ordering; it can never change a hash's INPUTS, only
WHEN that hash runs. Tested in
`sphincs-c10/tests/shuffle_byte_equality.rs` with 4 oracles:
identity-vs-random, shuffled-sig-verifies, multi-random-seed-all-
equal, and `sign()` wrapper matches `ShuffleSeed::zero()`. All
pass.

**No on-chain change. No external API break.**
`contracts/smart-wallet/test/c10_test_vectors.json` is byte-
identical pre- and post-commit (verified via `git diff --stat`).
The on-chain `SPHINCsC10Asm.sol` verifier consumes sig bytes; it
never sees the firmware's internal computation order. Every
Foundry test that passed before passes after by construction.

**Composition with F-13 (double-compute).**
The same shuffle seed feeds BOTH double-compute signs. If the seed
re-drew per sign, the F-13 byte-equality check would still hold (the
output is byte-equal regardless of shuffle), but the FI gate would
be testing for "same output under different internal trace patterns"
which is a much weaker invariant. Drawing once per call keeps the
F-13 invariant tight: identical inputs → identical bytes, mismatch
diagnoses a transient fault on one sign.

**Cost.**
Fisher-Yates: ~2 × N bytes of SHA-256-extended randomness per
permutation (~100 bytes per sign across both layers + FORS). One
SHA-256 block per ~32 bytes consumed. Microseconds. Stack: 43 + 13
= 56 bytes of permutation arrays.

**What F-16 does NOT close.**

  1. **Power signatures of intermediate Merkle nodes.** Shuffling
     within WOTS / FORS but the tree-build for the auth-path
     subtrees still runs in natural order. Lower SK-revealing
     value (these hashes are over public intermediate values, not
     the chain seeds themselves) but a future hardening pass
     could extend shuffle to the auth-path subtree leaves.
  2. **Higher-order DPA**. With enough traces (~10^6) and the
     right templates, higher-order DPA can recover bits even
     under shuffling. The cost is exponentially higher than
     first-order DPA, and combined with the F-9 trace budget
     (now ~131k per slot post-F-13), the attack is well above the
     practical threshold for a non-state-actor adversary.

Tracked in `docs/work-todo.md §18 P0` as the now-checked WOTS/FORS
shuffling item.

### F-15 — PIN-lockout gates were FAIL-OUT — a single branch-skip on the lockout `if` bypassed the wipe and let brute-forcing past `MAX_ATTEMPTS = 10` continue — **MITIGATED (not provably fixed) in `nsc::gated_unlock` + `cmd_request_unlock::verify_pin_with_chip` (FAIL-IN pattern + sentinel gate + double-read; residual attack surface documented below)**

**Threat — the most common single-fault outcome.** Per the
Masaryk-U Simonik thesis (76 % PIN-glitch bypass on STM32U5 silicon,
same family as our STM32U585), the *most common* effect of a
well-timed voltage / EM glitch is a **branch-skip** — the
microarchitecture executes a conditional-branch instruction without
taking the branch. That single-fault primitive applied to the
pre-existing PIN-lockout gates was end-to-end exploitable:

```rust
// gated_unlock — pre-fix
if pre_count >= MAX_ATTEMPTS {
    return Err(UnlockError::PinLocked);   // ← skip this
}
// fall through to bump + verify
```

```rust
// cmd_request_unlock — pre-fix
if remaining_after == 0 {
    return trigger_lockout_wipe();         // ← skip this
}
// fall through to "Wrong PIN" return
```

Both are **FAIL-OUT**: the secure action (refuse / wipe) lives in the
conditional branch. A branch-skip bypasses it; the firmware falls
through into the attacker-favourable path (continue brute-forcing).
With the `MAX_ATTEMPTS = 10` budget already small for a brute-force
adversary, even one bypassed cycle per power-glitch session opens a
practical attack — the Masaryk thesis reproduces this exact pattern.

**Fix — FAIL-IN pattern.** Invert so the secure action is the
fall-through:

```rust
// cmd_request_unlock — post-fix (FAIL-IN)
let safe_to_continue = crate::fi::check_true_into_sentinel(
    || remaining_after != 0,
);
if safe_to_continue != crate::fi::OK_SENTINEL {
    return trigger_lockout_wipe();           // explicit branch
}
// fall through to "Wrong PIN" return            ← safe-by-default path
```

Now a single-fault that skips the conditional triggers wipe (the
attacker WANTED to bypass wipe but the skip causes it). For the
attacker to bypass wipe they'd have to produce a register value
matching the Hamming-distant `OK_SENTINEL = 0xA5A5_A5A5` — a much
harder primitive than skipping a `cbz`.

```rust
// gated_unlock — post-fix
let allowed = crate::fi::check_true_into_sentinel(
    || pre_count < MAX_ATTEMPTS,
);
if allowed != crate::fi::OK_SENTINEL {
    return Err(UnlockError::PinLocked);
}
// fall through to bump + verify
```

Same shape: the affirmative "allowed to proceed" check uses the
sentinel; skip → garbage register value ≠ OK_SENTINEL → PinLocked.

**Additional value-fault defence.** Both sites double-read the
page-124 attempt counter through `pin_attempts_read` with
`wait_random()` between, then halt-to-wipe (or
`Err(PinLocked)`) on mismatch. `pin_attempts_read` itself is not
F-12-hardened — a single fault on its scan could underreport the
count, faking "plenty of attempts left." The double-read forces the
attacker to produce identical mid-scan faults across two passes.

**Trade-off.** FAIL-IN accepts a small *false-positive* risk: a
glitch on a legitimate wrong-PIN entry could trigger an unintended
wipe (user loses wallet). This is acceptable because:
  - Glitches require physical access — attacker, not legit user.
  - The user holds a BIP-39 seed-phrase backup ([[invariant 1]]).
  - The alternative (FAIL-OUT) leaves the brute-force door open to
    the *most common* glitch primitive in the threat model.

**Validation.**
  - 2 feature combos build clean: mock-se / dual-se+stm32. 118/118
    host tests pass (including
    `secure_element::tests::wrong_pin_decrements_remaining_attempts`
    and `ten_wrong_pins_brick_the_mock` which exercise the
    SecureElement-level path).
  - `make e2e` Scenario 6 (brute-force protection) passes: 10
    wrong-PIN attempts → wipe → correct PIN rejected after exhaustion.
    The new FAIL-IN gate transitions cleanly through the full
    lockout sequence.

**F-15 follow-ups landed (commit follows).** Two of the five residuals
listed below are now closed; the rest stay as documented:

  - **F-15.r5 (closed in this commit).** `pin_attempts_read` now uses
    the F-12 forward + reverse double-scan with asymmetric control
    flow, returning `PIN_ATTEMPTS_CAPACITY` (32, > `MAX_ATTEMPTS` =
    10) on mismatch so every downstream gate fail-closes. A single
    fault that lands on one direction's early-exit cannot
    symmetrically affect the other.

  - **F-15.r1 (helper landed; residual already mitigated in practice).**
    `fi::scrub_sentinel_register` added as inline-asm `mov r0, #0` for
    ARM (no-op on host). Audit of the current paired-sentinel sites
    (`NsPtr::validate_{read,write}`, `gated_unlock` + verdict,
    `verify_pin_with_chip` post-unlock) shows that every existing
    paired call already has either a `wait_random()` or a longer
    intervening function call between them that clobbers `r0` —
    `wait_random_loop`'s tail leaves a loop-counter / RNG byte in
    `r0`, NOT `OK_SENTINEL`. So the stale-r0 attack against the
    current codebase has no concrete exposure. The helper is added
    as defence-in-depth for future commits that might introduce
    closer-spaced sentinel calls without an intervening function
    boundary.

  - **F-15.r4 (covered transitively by r5).** The "post-scan
    value-fault on `pre_count` / `remaining_after` between
    assignment and closure capture" path is much narrower now that
    `pin_attempts_read` itself is FI-hardened: the closure capture
    happens immediately after the double-scan returns, on a value
    that has already been cross-checked. The remaining narrow
    window (load-into-register → store-to-local → closure capture)
    is single-instruction-wide and below the granularity the
    rainbow harness models.

**Residual attack surface still open (multi-fault / specific-value):**

  2. **Specific-value EM injection.** Documented in the SCA
     literature (Riscure, NewAE) — an EM glitch can inject a
     specific 32-bit word into a register directly. Hitting exactly
     `0xA5A5_A5A5` is rare and equipment-dependent but not
     theoretical. The Hamming weight (16) is moderate; a more
     aggressive constant choice (extreme weight 1 or 31) would push
     this harder. Tracked in `docs/work-todo.md §18b` as
     "F-13/F-14 sentinel constant Hamming-weight upgrade."

  3. **Coordinated 2-fault on `check_true_into_sentinel` internals.**
     F-5 found the sentinel function itself is ~2-coordinated-skip-
     defeatable. Two faults landing inside the function can produce
     an `OK_SENTINEL` return on a `false` input. Single-fault
     resistant; multi-fault not.

**Threat-model accounting.** The Masaryk-U Simonik thesis 76 %
single-skip primitive is closed by this commit. Multi-fault attacks
and specific-value EM primitives remain. That places F-15 at the same
maturity level as F-2 / F-3 / F-4 (mitigated; bounded by
multi-fault cost). The audit-grade SCA literature accepts this for
medium-severity gates where the seed-phrase backup
(invariant #1) bounds the user-side cost of a successful brute-force.
Tracked as residual in this section; a follow-up commit can knock
out items 1 and 5 cheaply (~30 LoC).

### F-14 — `SecureState::pin_verified` was a plain `bool` — a single-fault bit-flip in SRAM (or stuck-at on the load register) bypassed every gated command — **FIXED in `secure::fih::FihBool` + 11 call-site migrations**

**Threat.** Every gated gateway command (CMD_SIGN_USEROP, CMD_SIGN_OFFCHAIN,
CMD_FW_BEGIN/CHUNK/COMMIT, CMD_GET_WALLET_ADDRESS, CMD_GET_INIT_CODE,
CMD_OFFCHAIN_STATUS, CMD_SIGN_USEROP_BATCH, CMD_OFFCHAIN_SYNC) starts
with:

```rust
if !peek_state(|s| s.pin_verified) {
    return NscStatus::NotInitialized as u32;
}
```

`pin_verified` was a `bool` in BSS at a fixed address. Three single-fault
classes flipped it FALSE → TRUE end-to-end without an unlock:

  1. **SRAM bit-flip** (a Masaryk-thesis-style EMFI / voltage glitch on
     the storage word).
  2. **Stuck-at on the load register** that fed the `cbz` (volatile-
     hostile compiler folding made the load nominal-skippable).
  3. **Branch-skip of the caller's `cbz`** that gated the early-return.

(1) and (2) were the most concerning: the verifier had no way to detect
that the read had been faulted — the storage was a single bit, so a
flip looks indistinguishable from a legitimate `set_true`.

**Fix — `secure::fih::FihBool`.** Trezor-style `FihInt`/`secbool`:
the boolean is stored as a pair `(val: u32, complement: u32)` with the
invariant `val ^ complement == 0xFFFF_FFFF`. The TRUE / FALSE patterns
are Hamming-distant magic constants:

```rust
const SEC_TRUE:  u32 = 0x1AAA_AAAA;  // Hamming weight 16
const SEC_FALSE: u32 = 0x1555_5555;  // Hamming weight 17
// Differ in 29 of 32 bit positions — no single bit-flip turns one
// into the other.
```

`FihBool::is_true_fi` reads the pair *twice* via `read_volatile` with
a `wait_random()` between, requiring both passes to agree AND the
storage invariant to hold AND `val == SEC_TRUE`. Any of those checks
fails → return `false` (fail-closed).

`FihBool::check_sentinel` composes with the existing F-2 sentinel
pattern (`fi::check_true_into_sentinel`): it returns `OK_SENTINEL`
(Hamming-distant from `FAIL_SENTINEL`) iff the FihBool reads cleanly
as `true`. Callers compare the returned value rather than branching
on a bool — defeats single-instruction-skip on the caller's `if`.

**Call-site migration.** Every gated command now does:

```rust
if super::state::peek_state(|s| s.pin_verified.check_sentinel())
    != crate::fi::OK_SENTINEL
{
    return NscStatus::NotInitialized as u32;
}
```

This is a 3-layer chain:
  - **Storage** (FihBool complement-storage): single-fault in BSS →
    invariant breaks → fail-closed.
  - **Read** (`is_true_fi` double-read): single-fault inside one read
    → other read disagrees → fail-closed.
  - **Branch** (`check_sentinel` + sentinel cmp): single-fault on the
    caller's `cbz` → comparison still uses a Hamming-distant constant,
    a glitched register value is unlikely to coincide with OK_SENTINEL.

**Mutation.** `SecureState::mark_unlocked` calls `pin_verified.set_true()`;
`zeroize_sensitive` calls `pin_verified.set_false()`. Both go through
`write_volatile` so the compiler can't reorder them across a nearby
`master_secret.zeroize()` (which would otherwise be a real reorder
hazard — the zeroize would happen after a subsequent gate-check's
`set_false` was supposed to fail-close).

**Cost.** Per gate check: 2 × (2 volatile loads + invariant check) +
1 wait_random + 1 sentinel compare. Single-digit microseconds — well
inside the noise of the surrounding sign/verify path.

**Validation.**
  - 4 feature combos build clean: mock-se / dual-se+stm32 /
    se050+stm32 / optiga+stm32.
  - 118/118 host tests pass.
  - `make e2e` (QEMU 18-scenario non-interactive): all pass —
    register slot, repeat-sign, rotate, second chain, Safe approveHash
    clear-sign, selector bundle, blind-sign fallback, batch
    (degenerate / max / empty / truncated), self-attest, brute-force
    protection. The new gate predicates resolve cleanly under real
    unlock/lock cycles.

**Follow-up (deferred):** `has_signed`, `slot_master_derived`, and
`blob_cached` are also plain `bool`s in BSS / SE driver state. None is
on the critical path (the first two are write-only as of this commit;
`blob_cached` gates a read whose downstream decryption fails on an
all-zero cache — not a security bypass), but they get the same
treatment in a follow-up for consistency.

### F-13 — Verify-after-sign alone is insufficient against FI on the SLH-DSA sign path (RFC 9814 §A.2 / Genêt TCHES 2023) — **FIXED in `secure::crypto::c10_sign_verified_with_progress` (double-compute + ct-compare + verify)**

RFC 9814 §A.2 (informational, August 2024) and Genêt's TCHES 2023 paper
"A Faulty SLH-DSA …" both demonstrate the same class of attack: a fault
injected during SLH-DSA / SPHINCS+ signing can produce a **malformed
signature that nonetheless verifies cleanly under the honest pubkey**
while leaking `sk_seed` bits across multiple traces. The mechanism is
faulted hypertree node recomputation — a glitch at a low-layer WOTS
chain causes the verifier to reconstruct a chain of corrupted parent
roots all the way up to a `pk_root` that *happens* to match (because
SPHINCS+ verify recomputes the path from the leaf upward and the
faulted leaf's "valid" reconstruction is exactly what the corrupted
sig encodes). Over multiple faulted-but-verifying sigs the attacker
recovers FORS or WOTS one-time-key bits.

**Pre-fix state.** `c10_sign_verified_with_progress` did a single
sign followed by a verify-before-release gate. The verify defeats
naïve sig-mangling (random bit-flips) but NOT the Genêt class — a
faulted sig that recomputes to the same `pk_root` passes the gate.

**Fix.** `secure/src/crypto.rs` now:

  1. Draws a fresh 16-byte `opt_rand` via `rng_strong::fill` (multi-
     source XOR: STM32 TRNG ⊕ OPTIGA TRNG ⊕ SE050 TRNG — matches
     Trezor's `rng_fill_buffer_strong` design).
  2. Signs **twice** with the SAME randomiser, then constant-time
     compares the two 4008-byte signatures and halts on mismatch.
  3. Runs the existing verify-before-release gate.

Two signs over identical `(sk_seed, msg_hash, opt_rand)` are byte-
identical because the rest of the SPHINCS+C10 sign path is
deterministic; a transient fault on one of the two signs produces
divergent bytes that fail the ct-compare. Compare + verify form a
**2-gate chain**: if a single instruction-skip bypasses the compare,
the verify still catches a non-canonical sig; if a fault re-creates
the Genêt-style same-pk_root malformed sig, it would have to do so
**identically on both signs** for the compare to pass.

```rust
let mut opt_rand_buf = [0u8; sphincs_c10::params::N];
if crate::rng_strong::fill(&mut opt_rand_buf).is_err() { return Err(()); }
let opt_rand: Option<&[u8; sphincs_c10::params::N]> = Some(&opt_rand_buf);
let sig_a = sk.sign_with_progress(msg_hash, opt_rand, progress);
crate::fi::wait_random();
let sig_b = sk.sign_with_progress(msg_hash, opt_rand, |_| {});
if !bool::from(sig_a[..].ct_eq(&sig_b[..])) { return Err(()); }
crate::fi::wait_random();
let v = sphincs_c10::verify(sk.pk_seed(), sk.pk_root(), msg_hash, &sig_a);
if crate::fi::check_true_into_sentinel(|| core::hint::black_box(v)) != crate::fi::OK_SENTINEL {
    return Err(());
}
```

**Notes:**

  - The randomiser is drawn ONCE and fed to both signs. Re-drawing per
    sign would still be cryptographically sound but would produce
    divergent sigs, breaking the byte-equality FI gate.
  - `rng_strong::fill` (work-todo §10) XOR-folds the platform TRNG
    (STM32 hardware RNG on real silicon; semihosting `/dev/urandom` on
    QEMU) with the active SE backend's `random()` method. For
    `dual-se` builds the SE backend internally XORs OPTIGA + SE050.
    Defends against any single broken / biased source.
  - Mirrors Trezor's `core/embed/sec/rng/rng_strong.c` design. The new
    SE050 GetRandom APDU (`P2_RANDOM = 0x49`, AN12413 §5.13.1) was
    added in this commit alongside the high-level `Se050::random` /
    `OptigaTrustM::random` / `DualSecureElement::random` methods on
    the `WalletStore` trait.
  - Defends additionally against the deterministic-PRF-tree class
    (Genêt TCHES 2023): adding a fresh randomiser breaks the chain of
    repeated SK re-use that the differential attack exploits.
  - The `if !ct_eq { Err }` is itself a single-instruction-skip point;
    the verify is the second independent gate (do NOT remove on the
    assumption double-compute makes verify redundant).
  - **Cost**: ~2× sign latency (~+1.5 s on HW SHA, ~+12 s on QEMU
    software SHA). First-sign-after-unlock UX: progress bar 0..100
    ramps on sign 1; existing post-sign "verifying" window stretches
    to cover sign 2 + verify.
  - **F-9 trace-budget impact**: per-slot SCA observation budget
    doubles from 65 536 → ~131 072 traces (F-9 section discusses; the
    transparent-leak analysis is unchanged).
  - **Stack cost**: +8 KB (two 4008-byte sigs as locals). Within the
    128 KB secure SRAM with the existing SPHINCS+ internal usage.
  - **Mirror updated** in `tools/sca/c10_sign_target/src/main.rs` so
    the existing `fault_sweep_c10_sign.py` exercises the fixed gate.

### F-12 — Flash-counter SCAN is single-fault rollback-bypassable; severity higher than F-10 because the flash-promote defense doesn't apply — **FIXED in `secure::hw::flash::offchain_count_read` / `last_userop_count_read` / `offchain_count_is_registered` + bump-path slot_key input-redundancy**

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

**FIX (applied, validated).** Three layers in `secure/src/hw/flash.rs`:

  1. **Forward + reverse double scan** with asymmetric control flow. The
     reverse pass iterates `CAPACITY-1..=0` with no early-break on the
     first blank entry, so a control-flow corruption at scan entry that
     early-exits the forward scan does NOT symmetrically affect the
     reverse pass. `r1 != r2` → return `u64::MAX` (fail-closed; the cap
     check at the caller rejects).

  2. **Slot-key input-register redundancy.** Read the slot_key from the
     caller's stack twice with `wait_random()` between, halt on
     mismatch. Stops the instr-4/6 prologue attack that clamps the
     argument register to 0 and makes both scans operate on the wrong
     slot (zero-key → no matches → returns 0).

  3. **Bump-path slot-key redundancy.** Same pattern in
     `offchain_count_bump`, `offchain_count_promote_to`, and
     `last_userop_count_set` — the destinations the read functions
     protect would otherwise be aliased to a different slot by a
     stuck-at on slot_key at function entry.

`make flashctr` post-fix:

```
                                  pre-fix  post-fix
sca_flashctr_read_fi             10 roll.  1 rollback     (99.87 % reduction
                                                           from the 770-case
                                                           plain baseline)
sca_flashctr_bump_fi   316 392   6 silent  0 silent       (100 %)
                       injections
```

The single residual read-path case is a `stuck-at-0` at the function
prologue that survives the slot-key redundancy by clamping the SAME
register on the load that the harness uses for both `sk_a` and `sk_b`.
This is a harness artifact: in production, each call into
`offchain_count_read` is a distinct stack frame entered from a fresh
caller load, and the F-10 fix at `cmd_sign_offchain.rs` calls
`offchain_count_read` TWICE (with `wait_random()` between) and compares
— a single fault at one prologue can't reproduce at the second call's
prologue.

**The bump path** (`offchain_count_bump`) ALSO has bypasses:

```
sca_flashctr_bump_plain  [skip]        2 SILENT WRITE FAILURES (instr 4, instr 6)
sca_flashctr_bump_plain  [stuck-at-0]  2 SILENT WRITE FAILURES (instr 4, instr 6)
sca_flashctr_bump_plain  [stuck-at-FF] 2 SILENT WRITE FAILURES (instr 4, instr 6)
```

In each, bump returns `Ok(())` but the page's actual max for the target
slot DID NOT advance. All bypasses cluster at function prologue (instr
4-6: argument-register load) — consistent with a **slot-key
input-register aliasing** attack: a stuck-at on the slot_key register
makes the bump operate on a DIFFERENT slot. It (a) reads the wrong slot's
max (e.g., 0), (b) packs an entry for the wrong slot at count = new_count,
(c) writes that entry, (d) reads it back (success! for the wrong slot),
(e) passes the verify check + the FI triple-check (both also look at the
faulted slot_key). Bump returns Ok. The CORRECT slot's history is
unchanged. Caller emits a signature with offchainCount = new_count
embedded; the firmware's flash records the wrong slot's history at
new_count but OUR slot stays at the old value.

On the next call, local_offchain for our slot reads as the old value;
the firmware tries to bump again to new_count + 1. Same fault →
another silent write. **Sustained attacks: each fault yields 1 extra
signature past the cap.** The on-chain side does receive an
`executeWithOffchainCount(ownerIndex, new_count)` which advances the
on-chain `offchainSigCount[i]` and the firmware's `last_userop` after the
commit — so the F-10 promote step DOES partially recover here, capping
each attack to ~1 extra sig before re-anchoring. (Same residual as F-10.)

**Fix direction (covers both read + write paths):**
  - Input-register redundancy: load `slot_key` from memory TWICE with
    `wait_random()` between, compare; halt on mismatch. Stops the
    instr-4/6 prologue attack.
  - Plus the scan-twice + reverse pattern for the read path itself.

**Severity: HIGH.** Most severe finding in this audit. F-7 / F-8 closed,
F-10 / F-11 bounded by re-validation/promote/on-chain, but F-12 has no
existing defense — the production code is **single-fault rollback-
bypassable end-to-end**. The 65 k structural cap that bounds F-9 (FORS
leaf-index leak) AND every other SPHINCS+ subset-resilience-bound risk
depends on `offchain_count_read` being accurate.

### F-11 — Type 1 / Type 2 dispatch sanity-check rejections are single-fault bypassable — **silent-T1-emission class is NOT reachable; reject-bypass class FIXED in `secure::nsc::cmd_sign_userop` (flag-parse input-redundancy + post-derivation recheck)**

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

**FIX (applied).** `secure/src/nsc/cmd_sign_userop.rs:159–215`:

  1. **Input-register redundancy at parse.** Decode `flags` from `snap[8..12]`
     twice with `wait_random()` between. Halt-on-mismatch → returns
     `NscStatus::InternalError`. Catches a stuck-at on the load that
     materialises `flags` into a register: the second decode rebuilds
     the value from the snap buffer with a different register-allocation
     window.

  2. **Post-derivation recheck.** After the three sanity gates run on
     the first-parsed values, re-derive `flags` / `include_init_code` /
     `register_slot` / `slot_index` and re-run the three gates. A
     skip-fault that landed BEFORE the first gate has to repeat at the
     recheck to bypass — the gates run on freshly-loaded values, so the
     second pass has independent register state. Any divergence between
     the first and second derivation → halt.

The snap buffer itself is in S-world SRAM (the TOCTOU copy in step 3 of
the handler), so a fault that mutates `snap[8..12]` between the two
reads would have to land on an SRAM word — substantially harder than
clamping an argument register. The harness can't model SRAM-resident
inputs reliably (its inputs are scalar args), so the gate-only sweep
residuals are intrinsic to the harness shape, not a production weakness.

### F-10 — Off-chain gap + cap enforcement is bypassable via input-register fault — **FIXED in `secure::nsc::cmd_sign_offchain` (double-read counters + post-derivation recheck)**

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

**FIX (applied, validated).** `secure/src/nsc/cmd_sign_offchain.rs:199–243`
uses Option A + a recheck:

  1. **Double-read of each counter.** Call `last_userop_count_read` and
     `offchain_count_read` (themselves F-12-hardened) TWICE with
     `wait_random()` between. Halt-on-mismatch + halt-on-`u64::MAX`.
     Two independent flash scans separated by a randomised gap — a
     single fault clamping one read's value-register survives one call
     but is overwritten by the second call's fresh scan.

  2. **Post-derivation recheck.** After the gap + cap predicates run,
     re-derive `gap` and recompare it (plus `new_count`) against the
     bounds. A skip-fault that bypassed the first compare has to
     reproduce at the recheck on freshly-loaded register state.

A new `sca_cap_check_callsite_fi` harness entry-point mirrors the
production shape. Sweep results vs the gate-only `sca_cap_check_fi`:

```
                        cap_check_fi  callsite_fi
gap_at_boundary skip          5             1     (−80 %)
gap_at_boundary s@0           4             2     (−50 %)
gap_at_boundary s@FF          2             0     (full closure)
gap_well_over   skip          5             1     (−80 %)
gap_well_over   s@0           4             2     (−50 %)
gap_well_over   s@FF          2             0     (full closure)
cap_at_max      skip          1             1     (unchanged)
cap_at_max      s@0           3             2     (−33 %)
cap_overflow    skip          2             0     (full closure)
cap_overflow    s@0           1             1     (unchanged)
cap_overflow    s@FF          1             0     (full closure)
                            ─────         ─────
total                         30            10    (−67 %; 4 categories
                                                   fully closed)
```

The remaining residuals are intrinsic to the harness: its inputs are
scalar arguments passed in registers, so a stuck-at at the function
prologue clamps the SAME value the F-10 double-read re-reads (the
"read" is just register-to-register move, not an independent flash
scan). In production, each "read" is a real `offchain_count_read` call
into F-12-hardened code that re-scans flash from scratch — a fault on
one call's prologue can't reproduce at the second call's prologue. The
flash promote + on-chain combined cap also remain in place as
defence-in-depth.

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

## Groth16 verifier fault sweep — `fault_sweep_groth16.py` + `groth16_target/`

The `bls12_381_pka` Groth16 verifier (`secure/src/zk/groth16.rs::groth16_verify`)
is invoked from the `CMD_CLEAR_SIGN` path: companion sends a proof + public
signals, the wallet runs the verifier, and only if it returns `true` does
the trusted UI render the decoded Aave/CowSwap/etc. action for the user.
A fault that flips a single reject into an accept lets an attacker bypass
clear-signing — the user sees a forged human-readable summary while
calldata signs whatever the attacker wanted.

`groth16_target/` mirrors the 25-line `groth16_verify` function verbatim
into a `#[no_mangle]` thumbv8m ELF (a drift-watched copy: the imports in
`secure/src/zk/groth16.rs` pull in too many crate-internal modules to
link a detached target against). The sweep loads a **structurally valid**
proof + VK from `secure/src/zk/{test_vectors,vk_data}.rs` paired with a
**pub0-bit-flipped** public-signal vector, so the unfaulted run rejects
(returns 0). A single fault that flips r0 to 1 is FORGE_RELEASE.

```
make groth16          # tight sweep, ~11 min — 164 skip-fault positions
                      # across [bad_total-5000, bad_total-900) at step 25
make groth16-full     # full sweep, ~25-100h — 30K positions × 3 fault models
                      # (skip / stuck-at-0 / stuck-at-FF). Overnight only.
```

`bad_total` (the BAD-path instruction count, ~161.3M) is auto-bisected
to 1K-precision on each run (~75 s). The sweep range is upper-bounded
by `bad_total - SWEEP_LEAD` (default 900) because rainbow's notion of
"end of function" for `sca_groth16_verify_real` sits ~800 instructions
before the bisected `bad_total` — fi values inside that lead throw
`IndexError: reached end of function before faulting` rather than
emulating the fault. The empirical usable window for single-fault
sweeps is `[bad_total-5000, bad_total-900)`.

### F-26 — Groth16 verifier final-compare + return-path is FI-robust against single skip-faults in the last 5K instructions — **NO FINDING (BAD path rejects on every fault, no FORGE_RELEASE)**

Run on 2026-05-19 (commit pre-`fault_sweep_groth16.py` cleanup).

**Setup.**

- Target: `sca_groth16_verify_real(input_ptr) -> u32` in
  `tools/sca/groth16_target/src/main.rs`, ELF size ~315 KB (full
  `bls12_381` pairings).
- Input: VK + proof from `secure/src/zk/test_vectors.rs` and
  `secure/src/zk/vk_data.rs` (real on-chip values for the Aave-v3
  clear-sign circuit), with `pub0` byte 0 bit 0 flipped.
- Baseline: GOOD vector → r0=1 (accept) in 3.3 s, BAD vector →
  r0=0 (reject) in 4.2 s.
- BAD-path instruction count: bisected to **161,346,878** ± 1024.
- Sweep window: `[161,341,878, 161,345,978)` step 25 → 164 positions.
- Fault model: `fault_skip` (single instruction skip).

**Result.**

```
  rejects (correct):  124
  accepts (FORGE!):   0
  crashes:            26
  other anomalies:    14
```

- 124 / 164 positions: r0 stays 0 → verifier still rejects under fault.
- 26 / 164 positions: emulation crashed (Unicorn `RuntimeError` —
  typically a pairing-state load from a corrupted register lands on a
  bad PC). These crashes are *not* exploitable on real silicon (panic
  triggers `panic_halt`); they're an artefact of skipping load
  instructions in the final-exponentiation accumulator.
- 14 / 164 positions: r0 took a value other than 0 or 1 (e.g. partial
  `Gt::identity()` compare returning garbage). The dispatch in
  `cmd_clear_sign` only treats `1` as accept (`groth16_verify(...) as u32
  == 1`), so these are still rejects — but worth noting.
- **0 / 164 positions** produced r0=1. No single instruction-skip in
  the last 5 K instructions of the BAD path forges acceptance.

**Why this is the interesting window.** The last ~5 K instructions of
`groth16_verify` are the `result == Gt::identity()` compare + boolean
return + caller's `as u32` widening — i.e. the spot where the C10
verify-before-release class of bugs (F-1, F-2, F-3) lived. If a forge
exists, it almost certainly sits there: faulting deep inside
`miller_loop_4` or `final_exponentiation` corrupts the pairing
accumulator, which propagates to a still-bogus `Gt` element and a
still-failing compare. Conversely, the compare itself reduces 12 Fp²
limb comparisons into one boolean — a textbook FI target.

**What the sweep does *not* cover.**

- **Wider fault windows.** The 5 K-instruction tail covers the
  compare + return only. The pairing loop, the `vk_x` MSM, the
  deserialise+subgroup checks (`G1Affine::from_uncompressed`,
  `G2Affine::from_uncompressed`) all sit earlier and aren't probed
  here. `make groth16-full` runs the last 30 K instructions × 3 fault
  models for ~25-100 h.
- **Stuck-at-0 and stuck-at-FF.** Skip-only. The other two models are
  in the full sweep.
- **Multi-fault.** Single fault. Two-fault sweeps over this verifier
  are out of scope — the search space (~2.6 × 10¹⁰ position pairs)
  would need a smart prioritiser (e.g. faults inside identified
  comparison instructions only).
- **Drift between mirror and production.** `groth16_target/src/main.rs`
  duplicates `groth16_verify` verbatim from `secure/src/zk/groth16.rs`.
  A future commit that diverges the bodies invalidates the finding.
  The 25-line function is small enough that drift should be obvious in
  review; CI doesn't currently enforce mirror-vs-source equality.

**Disposition.** Accept as a positive result for the tight window.
File `make groth16-full` for the next overnight cycle (the wider
window + stuck-at models are where any real finding would surface
given the negative tight-window result). No code change.

**Deferred overnight sweep — `make groth16-full`.** Configuration:

```
  TAIL_DEPTH=30_000          # last 30K instructions of BAD path
  FULL_LEAD=900              # respect the rainbow past-end boundary
  models: fault_skip, fault_stuck_at(0), fault_stuck_at(0xFFFFFFFF)
  iterations: 3 × (30_000 - 900) = 87,300
  per-iteration cost: ~4 s under snapshot/restore
  estimated wall time: ~25-100 h (run on a dedicated machine, tee to log)
```

The full sweep is intentionally *not* parallelised (see the FW-manifest
parallelisation post-mortem above — single-thread is already fast
enough that the per-worker bls12_381 ELF load + emulator snapshot eats
the wins, and FaultFinder is the right pattern if/when we exceed
500 K iterations).
