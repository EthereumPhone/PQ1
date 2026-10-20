# Kontrol / KEVM scoping — closing the model-to-bytecode gap (D)

> **UPDATE 2026-10-20 (audit freeze): 31 proofs, re-run on the freeze
> bytecode.** `removeOwnerAtIndex` was deleted from the wallet, so every proof
> about removal was replaced:
> - `KontrolOwnerTable` (7): the three removal proofs (installed-pointwise,
>   unset-index reject, EntryPoint gate on removal) became one,
>   `prove_removed_selector_does_not_dispatch(address,uint256,bytes)`: a call
>   carrying the old selector `0x89625b57` reverts for every caller and
>   changes no storage.
> - `KontrolBootstrapUnremovable` (3), restated:
>   `prove_bootstrap_unchanged_by_addOwner(bytes)` (an EntryPoint-dispatched
>   `addOwnerBytes` never writes index 0),
>   `prove_bootstrap_removal_selector_does_not_dispatch(address,bytes)`, and
>   `prove_bootstrap_reinitialize_rejected(bytes,bytes)`.
> - Validate 7, Execute 8 and Factory 6 are unchanged in name; they ran on the
>   new bytecode.
>
> A3.4 is now 10 proofs (12 before). Two of the three restated bootstrap
> proofs overlap owner-table proofs (the removed selector, re-initialisation),
> so the independent coverage is smaller than the count suggests; the third
> (`addOwnerBytes` never writes index 0) is the bootstrap-specific one. The
> runner pins all 31 identities
> (`run_kontrol.sh` `EXPECTED_PROOFS`) and exports
> `FOUNDRY_DYNAMIC_TEST_LINKING=false` (Foundry 1.8 links test libraries
> dynamically by default, which the `deployCode` cheatcode path rejects).
> Receipt: `kontrol/sessions/kontrol-session-2026-10-20.txt`. Sections 2 and
> 4 below describe the removal proofs as they were and are kept for history.

**Status: A3.2 + A3.3 + A3.4 FULLY DISCHARGED ON BYTECODE (2026-06-15; 33/33
KEVM proofs as of 2026-07-17) — only A3.1 (verifier ∀-signature) remains, and is
intractable under symbolic SHA-256 (out of scope).** **UPDATE 2026-07-19
(fv-deep-review-2026-07-19 F9): the wired count was re-measured against the
tree — 33 `prove_*` functions across 5 harnesses (KontrolValidateUserOp 7,
KontrolExecute 8, KontrolOwnerTable 9, KontrolFactory 6,
KontrolBootstrapUnremovable 3), so the 33/33 discharge matches the tree
exactly; the 2026-07-18 sweep's "38 `prove_` functions" was a miscount.
`run_kontrol.sh` now carries a pinned proof-identity baseline
(`EXPECTED_PROOFS`, all 33 `<Contract>.<function>` ids) and fails after
`kontrol prove` unless every expected id has exactly one version-0 record that
is PASSED with an explicit `admitted: False` in `kontrol list`. The
authoritative runner rejects a caller-supplied `MATCH`, deletes the persistent
proof store with `kontrol clean --proofs`, and proves the exact
`Kontrol.*\.prove_` set with `--reinit`; stale or duplicate versions therefore
cannot satisfy a partial run. `--self-test` exercises twelve positive/negative
parser controls without the K backend. Archived `kontrol list` text is not an
independent proof receipt and has no public validation mode; only the
authoritative clean/build/prove/live-list path establishes freshness.** The four control-flow bridge axioms are now
proven directly on the deployed PQSmartWallet/Factory bytecode by an engine
independent of Halmos with no hand-written `LeanModel.sol` mirror — so the
hand-transcription TCB element of A3.3/A3.4/A3.2-exec-single is retired (Halmos stays the
fast LOCAL/manual gate — NOT CI-run; the per-PR bytecode tripwire is the codehash-freeze
test). NOTE (2026-07-02): A3.2-**validate** and A3.2-exec-**batch** use a CONCRETE
well-formed wrapper in Kontrol, so the wrapper-decode / selector-role-split / full-frame
transcription of `LeanValidateUserOpModel.sol` is NOT independently re-established for them —
that transcription stays a Halmos-only, eye-auditable TCB element (see the A3.2 status_detail
in AXIOM_STATUS.json). **UPDATE 2026-07-17 — the three STRUCTURAL wrapper-decode gates are
now ∀-SYMBOLIC in Kontrol (no longer concrete-by-construction).** Three new revert-shaped
rules in `KontrolValidateUserOp.t.sol` — `prove_validate_rejects_{bad_offset, bad_innerlen,
bad_tailpad}` — make exactly one wrapper word symbolic-and-malformed and prove
`validateUserOp` returns FAILURE for EVERY such value: `offsetField != 0x40`
(`_validateSignature` L428, ∀ `uint256`), `innerLen != C10_SIG_LEN` (L429, ∀ `uint256`),
and a nonzero ABI tail-pad (L433, ∀ `bytes32` low-24-bytes, masked by `2^192-1`). All three
fire BEFORE the verifier CALL + `sphincsDigest`, so they are hash-free; each sets
`c10.setValid(true)` + a well-formed slot callData so the reject is provably the decode
gate's, not the verifier's (the canonical-wrapper `prove_validate_slot_nonbypass` is the
well-formed⇒success other half). All PASSED under KEVM, non-vacuous. So the three STRUCTURAL
gates leave the concrete-by-construction / Halmos-only eye-auditable TCB list. STILL
Halmos-only / documented increments (NOT closed here): selector-role-split with a SYMBOLIC
selector, the full owner-frame probe, the H-3 calldata-ownerIndex parity (slot success path —
reaches verify+hash), all-tail-symbolic innerSig in the success rules, and the
fully-symbolic UNSET ownerIndex (a permanent both-engine blocker — dynamic-bytes getter
`NotConcreteError` on a symbolic key). A3.2-validate is now 7/7. Breakdown: A3.4 owner-table = 12/12; A3.2-exec = 8/8; A3.3 factory
= 6/6; A3.2-validate (the non-bypass I-1: validate succeeds ⟺ cap-gate ∧
verifier-accepts, ∀ verdict + counters, slot + bootstrap roles; + unset-owner +
EntryPoint rejects; + the three ∀-symbolic wrapper-decode reject rules of the
2026-07-17 UPDATE above) = 7/7 in `kontrol/test/KontrolValidateUserOp.t.sol`.
A3.4 owner-table = 12/12 KEVM proofs; A3.2-exec
(execute / executeBatch) = 8/8 in `kontrol/test/KontrolExecute.t.sol`
(EntryPoint gate, anti-impersonation no-credit-revert ∀ ownerIndex, self-target
reject, the `setOffchain` pointwise gate ∀-counters, credit one-shot/replay-guard,
atomicity on a reverting target, batch self-target reject, batch dispatch
witness); A3.3 factory = 6/6 in `kontrol/test/KontrolFactory.t.sol`
(`createAccount` ⟺ precondition iff with symbolic chainId + verifier verdict +
real CREATE2 deploy/postconditions; N-mask×2 / duplicate / wrong-chain reject
witnesses; already-deployed early-return ⟺ chain-ok). The transient
validated-credit is stamped by a CONCRETE `validateUserOp` call + valid mock
(KEVM computes `sphincsDigest`'s SHA-256 via its `[concrete]` precompile rewrite
— no symbolic-hash wall); the factory keeps the master keys concrete (the
CREATE2 salt is `sha256(master)`) and models the verifier as a symbolic-`valid`
mock. Gotchas recorded below.
The K backend is now
installed (multi-user Nix → `kup install kontrol`; kontrol 1.0.247 / K v7.1.333,
pulled prebuilt from `k-framework.cachix.org` — `nicola` was added to Nix
`trusted-users` so the cache is used instead of a multi-hour source build).
`kontrol build` + `kontrol prove` run live, and **all three bootstrap-unremovable
rules PASS under KEVM symbolic execution against the deployed `PQSmartWallet`
runtime bytecode**: `prove_bootstrap_unremovable_from_entrypoint(bytes)` (∀
symbolic `expected`), `prove_bootstrap_unremovable_exact_bytes`, and
`prove_bootstrap_remove_rejected_non_entrypoint(address,bytes)` (∀ caller).
Run via `make -C contracts/verification verify-kontrol` (or
`contracts/verification/kontrol/run_kontrol.sh`); ~5 min build + prove.

**A3.4 (owner-table) is now FULLY discharged** — 12/12 rules PASS under KEVM
across two harnesses (`kontrol/test/KontrolBootstrapUnremovable.t.sol` +
`KontrolOwnerTable.t.sol`), mirroring `test/halmos/HalmosMultiOwnable.t.sol`
rule-for-rule: `addOwnerBytes` pointwise (∀ symbolic 64-byte content) + length
gates (63/65 reject) + EntryPoint gate; `removeOwnerAtIndex` installed-pointwise
(∀ symbolic `expected`) + unset-index reject (∀ index ≥ 2) + bootstrap-
unremovable (∀ caller, ∀ expected, exact-bytes) + EntryPoint gate; `initialize`
one-shot + fresh-proxy pointwise. All proven DIRECTLY on the deployed bytecode
by an engine independent of Halmos — no hand-written `LeanModel.sol` mirror —
so the **transcription-TCB element of A3.4 is retired** (Halmos stays as the
fast CI gate). Corresponds to invariant #6 + the Claim-2 owner-set-integrity
Lean theorems.

> **Gotchas recorded for the next harnesses (A3.2/A3.3):**
> 1. **chainid** — KEVM's default `block.chainid` is **1** (not forge's 31337);
>    `MockSPHINCSVerifier`'s M14 deploy guard reverts off a local chain, so
>    `setUp` reverts at the mock constructor unless `vm.chainId(31337)` is the
>    first `setUp` statement.
> 2. **storageLayout** — kontrol SILENTLY SKIPS a contract ("non-compatible JSON"
>    → "Test identifiers not found") if its foundry artifact lacks
>    `storageLayout`. A prior plain `forge build` leaves harness artifacts
>    without it and kontrol's incremental build won't refresh them. `run_kontrol.sh`
>    now `rm`s the staged harness artifacts before `kontrol build` so they
>    recompile under kontrol's `--extra-output storageLayout`. (Don't plain
>    `forge build` before a kontrol run.)
> 3. **prove matcher and proof-store freshness** — `kontrol prove` has no
>    `--match-contract`; the authoritative runner uses the exact
>    `--match-test 'Kontrol.*\.prove_'` selector and rejects `MATCH`
>    overrides. It first runs `kontrol clean --proofs`, then proves with
>    `--reinit`; the receipt checker requires exactly one version-0, PASSED,
>    explicitly non-admitted record for every pinned proof identity.
> 4. **checked-add overflow** — a fully-symbolic scalar (e.g. `newOffchainCount`)
>    lets a Solidity 0.8 checked add (`slotUsesNow + newCount`) overflow 2²⁵⁶ on
>    some path, which reverts via a panic rather than the intended gate (and the
>    harness's own `wantSuccess` add overflows too). Bound such scalars to their
>    reachable range (`vm.assume(newCount <= MAX_SLOT_USES)`) — faithful, since
>    anything above is uniformly rejected, and it keeps full boundary coverage.
> 5. **symbolic-calldata dynamic arrays** — a symbolic scalar arg passed to a
>    call with dynamic-array args (`executeBatchWithOffchainCount`) makes the
>    whole ABI calldata symbolic; on the SUCCESS path KEVM reads each element's
>    CALL `value` (`values[i]`) via a `#range` over that symbolic buffer it can't
>    simplify to 0, leaving an undischargeable branch. (Revert-shaped batch rules
>    dodge it — they revert before the value read.) Worked around by proving the
>    batch SUCCESS path with a CONCRETE instance and delegating the ∀-gate
>    coverage to the single-execute rule (identical `_setOffchainSigCount` call)
>    + the symbolic batch self-target rule. Documented inline in `KontrolExecute.t.sol`.

The sections below record the (now-historical) install assessment, the
ready-to-run proof artifact, and the realistic per-axiom effort estimate for
replacing each Halmos A3.* bridge with a Kontrol proof.

Date: 2026-06-14. HEAD: `2329abe`. Host: Ubuntu, 24 cores, 90 GiB RAM,
clang/gcc present; `uv` present; **no nix, no docker, no kup, no K backend**.

---

## 1. What Kontrol is, and what it needs

Kontrol (Runtime Verification, `runtimeverification/kontrol`) drives **KEVM**
symbolic execution of **EVM bytecode** straight from Foundry tests. A test
function named `prove_*` / `test_*` / `check*` whose arguments are symbolic is
discharged for **all** inputs in its constraint envelope by the K
backend + an SMT solver (Z3), so a passing rule is a proof over the deployed
runtime bytecode — the same class of guarantee Halmos gives, from a
**different, independent engine**. Using two engines on the same bytecode
property is exactly the kind of cross-check that strengthens the
model-to-bytecode bridge (gap D).

Kontrol has **two layers**:

1. **`kontrol` Python package** (pip/uv-installable). The CLI, the Foundry
   integration, the KCFG bookkeeping. This **installed cleanly** here.
2. **The K Framework backend** — `kompile`, `llvm-kompile` (the LLVM backend
   compiler), `kore-rpc-booster` / the Haskell backend (the symbolic
   rewriting + SMT driver), plus the compiled KEVM semantics and the
   blockchain-k-plugin crypto lib (`krypto.a`: libff, cryptopp, secp256k1,
   c-kzg/blst). This is **native (OCaml/Haskell/C++), not Python**, and is
   the install blocker.

The canonical install of layer 2 is `kup` (a Nix-based package manager) which
pulls **prebuilt** backend binaries from RV's cachix binary cache, or the
`runtimeverification/kontrol` **Docker** image. The README itself notes the
first run is "30m to 1h" and multi-GB even on the happy path.

---

## 2. Install assessment on this host (the blocker, with evidence)

### 2a. The Python CLI installs and runs — layer 1 OK

```
$ uv pip install -e /home/nicola/repos/kontrol      # into /tmp/kontrol-venv
Resolved 75 packages ... Installed ... kontrol==1.0.0
$ /tmp/kontrol-venv/bin/kontrol --help
usage: kontrol [-h] {version,build,load-state,prove,show,list,...}
```

`/home/nicola/repos/kontrol` is the **kontrol source checkout** (git, on
`09c4ad87`), not a venv or a built install. `pyproject.toml` pins
`kevm-pyk@git+...evm-semantics@v1.0.912` and the CLI entry point
`kontrol = "kontrol.__main__:main"`.

### 2b. Every real command fails on the missing K backend — layer 2 BLOCKED

```
$ kontrol version
  proc_res = run_process_2(['kompile', '--version'])
FileNotFoundError: [Errno 2] No such file or directory: 'kompile'

$ kontrol build
RuntimeError: K is not installed

$ which kompile kore-rpc-booster kprove krun       # → nothing
$ which nix docker kup                              # → nothing
```

### 2c. The documented from-source backend build also fails — no shortcut

`kdist` *targets* exist (`kontrol-kdist list` →
`evm-semantics: llvm/haskell/plugin/...`, `kontrol: base/keccak/aux/full`),
but **building any of them invokes the K toolchain**, which isn't there:

```
$ kevm-kdist build evm-semantics.plugin
# copies the blockchain-k-plugin (krypto) and runs `make -j8`:
make: llvm-kompile: No such file or directory     # ← K LLVM backend compiler
...
RuntimeError: Build failed: evm-semantics.plugin
```

The plugin Makefile *starts* compiling the native crypto deps it ships
(libff via cmake, cryptopp, c-kzg/blst), proving clang/cmake/gcc are fine —
but it cannot finish without `llvm-kompile` and the rest of the K release.
That release is distributed as Nix derivations / `.deb` packages, **not** a
pip wheel; building K itself from source needs GHC/stack (Haskell backend) +
the LLVM backend toolchain and is a multi-hour job not attempted here.

### 2d. Why "in reasonable time" fails

The only feasible paths are (i) install the Nix daemon system-wide
(`bash <(curl https://kframework.org/install)` → Determinate Systems Nix
installer, needs root/systemd, multi-GB) then `kup install kontrol`
(30m–1h, multi-GB from cachix); or (ii) Docker
`runtimeverification/kontrol`. Neither nix nor docker is on this host, and
installing the Nix daemon is a system-level change outside the scope of a
verification subagent. **This is the honest blocker for the live proof run.**

---

## 3. Can Kontrol parse our contracts? — YES (validated)

`contracts/smart-wallet` is a standard Foundry project (`foundry.toml`,
`remappings.txt`, `lib/` submodules, `via_ir = true`, solc 0.8.28).
`kontrol build`'s first step is `forge build`; that step **passes**:

```
$ forge build              # in contracts/smart-wallet
# compiles all of src/ + test/ clean (only lint warnings)
```

So the **parse / artifact** half of Kontrol is unblocked here — the only
missing piece is the KEVM backend that consumes those artifacts. (Caveat:
`via_ir` + 0.8.28 are recent; Kontrol generally tracks current solc, and
KEVM works from the deployed bytecode + the solc AST, both of which forge
emits, so no parse obstacle is expected.)

---

## 4. The first proof: a tractable property + ready-to-run artifact

**Property chosen:** *the bootstrap owner at index 0 can never be removed*
(security invariant #6 / Lean `Wallet/Invariants.lean :: cannot_remove_bootstrap`).
Deployed guard: `PQMultiOwnable._removeOwnerAtIndex` →
`if (index == 0) revert CannotRemoveBootstrap();`, plus the EntryPoint
access gate on the external `PQSmartWallet.removeOwnerAtIndex`.

**Why this is the right Kontrol first target (and NOT the verifier):**
- **No SHA-256.** `removeOwnerAtIndex(0, _)` reverts before any hashing, so
  Kontrol never has to interpret the `0x02` precompile. (The verifier A3.1
  ∀-signature is intractable under an uninterpreted hash even for Kontrol —
  explicitly out of scope per the task.)
- **No unbounded loop.** One storage read + a keccak compare never reached on
  the index-0 arm. Bounded path → tractable for the SMT solver.
- **Deployment state is cheap to seed.** A real `initialize(...)` (no factory
  `createAccount`, which hashes for the CREATE2 salt + slot-0 squat digest —
  axiom A3.3, out of scope) installs storage byte-identical to production.
- It is a **meaningful security invariant**, not a toy, and it has a direct
  Lean refinement target + an existing Halmos analogue
  (`HalmosMultiOwnable.t.sol :: check_removeOwner_bootstrap_unremovable`), so
  a Kontrol pass is a genuine **second-engine cross-check** of gap D.

**Artifact:** `contracts/verification/kontrol/test/KontrolBootstrapUnremovable.t.sol`
— three rules, arguments symbolic by default (Kontrol idiom; no Halmos
`svm.*`):
- `prove_bootstrap_unremovable_from_entrypoint(bytes expected)` — EntryPoint
  caller, ∀ 64-byte `expected`: MUST revert `CannotRemoveBootstrap`, owner 0
  + counters unchanged.
- `prove_bootstrap_unremovable_exact_bytes()` — strongest adversary: hands the
  exact installed bootstrap bytes (the value that *would* pass the keccak
  compare if the guard were absent); still reverts → certifies the guard runs
  before the bytes check.
- `prove_bootstrap_remove_rejected_non_entrypoint(address caller, bytes expected)`
  — ∀ non-EntryPoint caller: reverts `NotFromEntryPoint`.

**Runner:** `contracts/verification/kontrol/run_kontrol.sh` — checks for
`kompile`, stages the harness into the smart-wallet Foundry project (so
remappings/libs resolve), then `kontrol build` + `kontrol prove --use-booster`.

### 4a. Validation actually performed here (no K backend)

The harness was compile-checked and run against the concrete + fuzzed EVM
(forge), which is the strongest validation possible without the backend and
establishes the floor a `kontrol prove` would generalize:

```
$ forge build  (harness staged in test/)         → exit 0, artifact
                                                    out/.../KontrolBootstrapUnremovable.json emitted
$ forge test --match-contract KCCConcrete -vv     # prove_* renamed test_* to run
[PASS] test_bootstrap_remove_rejected_non_entrypoint(address,bytes) (runs: 256)
[PASS] test_bootstrap_unremovable_exact_bytes()
[PASS] test_bootstrap_unremovable_from_entrypoint(bytes) (runs: 256)
Suite result: ok. 3 passed; 0 failed; 0 skipped
```

The only step left is to swap the forge fuzzer (256 samples) for KEVM
symbolic execution (∀ inputs). The harness is written in pure forge-std
cheatcodes (`vm.assume`/`vm.prank`/`vm.expectRevert`/`assertEq`) — all
natively supported by Kontrol — so **no harness changes** are needed once a
backend is present; just run `run_kontrol.sh`.

### 4b. Expected outcome once a backend is available

This property is squarely in Kontrol's comfort zone (bounded, hash-free,
revert-shaped). High confidence all three rules pass with default settings
(`--use-booster`, modest `--smt-timeout`). The exact-bytes and non-EntryPoint
rules are essentially constant-path; the symbolic-`bytes` rule branches only
on length (constrained to 64) and never reaches the keccak. Risk is low.

---

## 5. Replacing each Halmos A3.* bridge with a Kontrol proof — effort + blockers

Halmos currently discharges 38 bytecode rules across A3.2/A3.2-exec/A3.3/A3.4
(+ A3.1 input-gates only). Kontrol could re-discharge the **same** surface as
an independent second engine. Per-axiom assessment:

| Axiom | Surface | Kontrol effort | Principal blockers |
|---|---|---|---|
| **A3.4** (owner table: add/remove/initialize, read parity) | `HalmosMultiOwnable.t.sol`, 7 rules | **Low** (~1–2 days after backend). The bootstrap-unremovable rule here is the first slice. | The `mapping(uint=>bytes)` getter on a **symbolic** index is the same ceiling Halmos hits (length of default-empty bytes is path-dependent); installed indices stay concrete singletons. Kontrol's `kevm.symbolicStorage` + `--symbolic-immutables` can sometimes push past this, but expect the same concrete-rep enumeration on the unset partition. |
| **A3.3** (factory `createAccount` ⟺ precondition) | `HalmosFactory.t.sol`, 5 rules | **Medium.** | `createAccount` computes **`sha256`** twice (CREATE2 salt + slot-0 squat digest). Kontrol models `0x02` via a `#precompiled` rule but reasoning is over an **uninterpreted SHA-256** — the precondition equivalence holds as long as the property doesn't need SHA-256 *values* (it doesn't: it's about *which* bytes are hashed + the address-derivation control flow). Needs the SHA-256 abstraction wired (Kontrol has `lemmas` for this) + LibClone CREATE2 address arithmetic, which KEVM handles natively. |
| **A3.2** (`validateUserOp` pointwise vs Lean model) | `HalmosValidateUserOp*.t.sol`, 12 rules | **Medium–High.** | (1) The success path reaches `sphincsDigest` → **SHA-256 over symbolic UserOp fields**; must abstract `0x02` to an uninterpreted function (Kontrol supports this) or etch a stub as Halmos does. (2) The **external verifier CALL** must be modeled — either etch a symbolic-returning mock (Kontrol can make the return symbolic) to prove "success ⇒ verifier returned true", mirroring Halmos's `OracleSPHINCSVerifier`. (3) `ownerAtIndex` symbolic-key ceiling again on the unset partition. (4) Loop/branch budget across the dispatch — bounded but heavier; tune `--max-depth`/`--max-iterations`. |
| **A3.2-exec** (`execute{,Batch}WithOffchainCount`) | `HalmosExecute*.t.sol`, 11 rules | **Medium.** | The money path reads only **word-typed counters + the transient `tload` credit** (no bytes getter), so it is genuinely ∀-`ownerIndex` for Kontrol too — *better* suited than `validateUserOp`. Blocker: the **external CALL** byte-delivery (axiom A4) — Kontrol models `CALL` faithfully so this is an asset, but the batch loop needs a bound (`--bmc-depth`). |
| **A3.1** (`SPHINCsC10Asm.verify` functional ∀-signature) | full verifier | **Intractable — do NOT attempt** (per task). | The verifier is ~hundreds of SHA-256 invocations over a 4008-byte signature (WOTS+ chains, FORS, hypertree). Under an **uninterpreted** `0x02` the ∀-signature theorem is not provable (the SMT solver has no SHA-256 semantics); under an **interpreted** SHA-256 it is astronomically out of reach for any symbolic engine. This is precisely the gap A3.1 leaves `-partial` and why it stays a Lean/KAT obligation, not a Kontrol target. Kontrol can at most re-do the **input-gate** rules (`HalmosVerifier.t.sol`, 3 rules) — Low effort, same caveat. **NB (2026-06-16):** "no symbolic engine can" ≠ "no proof exists". A **deductive Lean interpreter-refinement** (induction on loop-iteration count, hash kept opaque — *not* symbolic search) closes the ∀-signature model↔spec equality without an interpreted-hash engine; the upstream SPHINCS- `/verity` demonstrates it (`c13_refines_spec`). That is a Lean obligation (the `contracts/verity/` scaffold), orthogonal to Kontrol. See [`A3_1_CLOSURE_PATH.md`](A3_1_CLOSURE_PATH.md). |

**Cross-cutting blockers for the whole port (all surmountable except A3.1):**

1. **K backend install** (§2) — the gating prerequisite. One-time:
   `kup install kontrol` or Docker. Everything below assumes it's done.
2. **SHA-256 / `0x02` handling.** Every success path that reaches
   `sphincsDigest` hashes. Kontrol's approach is an uninterpreted-function
   lemma for the precompile (preferred — keeps it sound and matches what the
   Lean model + Halmos do) or `vm.etch` a constant stub (as
   `HalmosWalletBase._stubSha256` does). Either way the SHA-256 *correctness*
   stays a separate axiom (A1), identical to the current setup.
3. **Deployment-state seeding.** Same trick as Halmos: skip the hashing
   factory path, bring the wallet up with a real `initialize`, get
   production-identical storage. For factory rules (A3.3) you must seed via
   `createAccount` and therefore engage the SHA-256 abstraction.
4. **`mapping(uint=>bytes)` symbolic-key ceiling.** A disclosed engine limit
   shared by Halmos; Kontrol inherits it. Installed indices stay concrete;
   word-typed counters/credit are genuinely symbolic.
5. **Loop bounds.** Batch/dispatch loops need explicit `--bmc-depth` /
   `--max-iterations`; all our loops are statically bounded so this is tuning,
   not a soundness gap.
6. **Runtime.** KEVM proofs are **far slower** than Halmos (minutes–hours per
   rule vs seconds–minutes). Budget CI accordingly; the value is the
   independent second engine, not speed.

---

## 6. Bottom line

- **Is Kontrol usable here?** The CLI yes; the prover **no, not on this host**
  — the K backend needs Nix or Docker, neither installed, and the from-source
  backend build dead-ends on missing `llvm-kompile`. Definitive, reproducible
  (§2b/2c).
- **Did the first proof pass?** Not under KEVM (no backend). The harness is
  written, compiles into Kontrol's artifact set, and **passes concrete +
  fuzzed** (3/3, 256 runs) — the strongest available signal that a
  `kontrol prove` would succeed. Turnkey via `run_kontrol.sh` once a backend
  exists.
- **What would the full Halmos→Kontrol port take?** A3.4 low, A3.3/A3.2-exec
  medium, A3.2 medium-high, **A3.1 intractable (excluded)**. The one hard
  prerequisite is the backend install; the recurring technical work is the
  SHA-256 abstraction and the symbolic-mapping ceiling, both already solved in
  the Halmos harnesses and directly transferable. Recommended sequencing:
  land the backend → prove this bootstrap rule end-to-end (validates the
  toolchain on our code) → port A3.4 → A3.2-exec → A3.3 → A3.2; keep A3.1 in
  Lean/KAT.

## 7. Files

- `contracts/verification/kontrol/test/KontrolBootstrapUnremovable.t.sol` —
  the proof harness (3 rules).
- `contracts/verification/kontrol/run_kontrol.sh` — turnkey build+prove runner
  (guards on `kompile` presence).
- `contracts/verification/docs/KONTROL_SCOPING.md` — this document.
