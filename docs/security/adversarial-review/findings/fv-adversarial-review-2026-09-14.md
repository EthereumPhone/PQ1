---
surface: fv
date: 2026-09-14
status: in-review
workflow: single bounded three-reviewer discovery wave plus coordinator reproduction
---

# Formal-verification adversarial review — 2026-09-14

**Decision: FIX the assurance controls.** Eight findings were retained: six
medium findings and two low findings. No wallet exploit, Lean kernel
inconsistency, or HIGH-severity implementation defect was established. The
current headline theorem checks, but several surrounding gates accept evidence
they are intended to reject, and the default proof-mutation campaign cannot
start. These are assurance failures, not a demonstration that the current
headline proofs depend on an injected false axiom.

This is the owner-requested FV discovery pass, not an implementation, merge, or
shipment review. No remediation was applied. All experiments used disposable
copies; the original product/proof sources and frozen review target were
unchanged. Only review artifacts and the findings catalogue entry were added.
Follow-ups were published to six existing GitHub issues; the exact comment
URLs and successful write receipts are in
[tracker-updates.json](fv-2026-09-14/tracker-updates.json).

## Identity and review execution

- Original branch: `feat/pq1-board-target`; base HEAD
  `d15426e3dcf04e68fb97a6a2800ec2690d12ed8d`.
- Snapshot including working-tree changes and untracked source/test inputs:
  `aab89656690cf4b15a543b21e58a3ad4f918ec16`, tree
  `b46ba54f308283ceefa9852ee0f2730b2d039929`.
- Snapshot and complete scratch evidence:
  `/tmp/pq-fv-review-20260914-gx635_x9/`. Unrelated untracked session archives
  and bench tooling were excluded; the exact exclusions are in
  [receipt.json](fv-2026-09-14/receipt.json).
- Active surface: FV claim soundness. Slices: Lean statement/axiom meaning;
  extraction and implementation correspondence; model and gate integrity.
- All reviewers received the same 2,793-byte prompt, SHA-256
  `aa30eed854f3a73ee885c5e348d7c0adb9da33d3f3743580d6fa4c45d9f49ec5`.
  They received no prior verdicts or other reports. Each had 900 seconds and
  800 words; no follow-up review turns or cross-adjudication occurred.

| Reviewer | Requested configuration | Result | Runtime | Report |
|---|---|---|---|---|
| GPT-5.6 SOL | `gpt-5.6-sol`, `ultra` | FIX | 226 s, 280 words | [raw](fv-2026-09-14/sol.txt) |
| Claude Opus 5 | `opus`, `xhigh` | FIX | 194 s, 708 words | [raw](fv-2026-09-14/opus.txt) |
| Kimi K3 | `kimi-code/k3`, `max` | FIX | 708 s, 546 words | [raw](fv-2026-09-14/kimi.txt) |

The initial three processes started together. SOL's first attempt could not
execute any source-read command because nested Bubblewrap namespace creation
failed. Its sole mechanical retry used the skill's documented Landlock
fallback, the same prompt, and the same outer read-only snapshot mount. The
initial 62-word GAP is not counted as a source review. CLI versions were Codex
0.154.0, Claude 2.1.270, Kimi 0.39.1, and Bubblewrap 0.9.0; the launcher offline
self-test and concrete dry runs passed. Opus runtime names `claude-opus-5`
and also records auxiliary Haiku usage; no fourth review report was requested.
The launcher provides procedural non-disclosure and read-only candidate
mounts, not separate host homes or strict same-UID filesystem blindness.

## Confirmed findings

### F1 — MEDIUM: the new extracted-axiom census still admits false assumptions

**Location:**
[`lint_extracted_axiom_census.sh:125–149`](../../../../contracts/verification/scripts/lint_extracted_axiom_census.sh).
**Tracking:** [#676](https://github.com/EthereumPhone/PQ1/issues/676).

The declaration regex recognizes only lines beginning with `axiom`; it misses
`private axiom`. Its allowlist compares unqualified short names without binding
namespace, source file, type, or exact multiplicity. Both of these forms pass:

```lean
namespace CensusBypass
private axiom UndisclosedFalse : False
theorem allClaims (P : Prop) : P := False.elim UndisclosedFalse
end CensusBypass
```

```lean
namespace CensusBypass
axiom keccak256_pure : False
theorem allClaims (P : Prop) : P := False.elim keccak256_pure
end CensusBypass
```

**Executed:** ordinary `axiom UndisclosedFalse : False` was rejected (exit 1);
the private form and reused-name form elaborated successfully and passed the
census (exit 0). More strongly, importing the private-axiom module from
`extracted/Extracted.lean` left the complete `make -C contracts/verification
verify-extracted` gate green, including all 66 headline closure checks and
their negative controls. The baseline passed too. The injected theorem is
outside those 66 headlines; this does not refute their individual allowlists.

**Smallest correction:** census all admitted declaration forms, bind fully
qualified identity/file/type, enforce exact membership and multiplicity, and
include top-level import roots in the quarantine check. Prefer elaborated
environment enumeration with explicit coverage of modules outside the default
build. Add the private and reused-name examples as negative controls.

Evidence: [gate results](fv-2026-09-14/axiom-census-poc.json),
[full-gate results](fv-2026-09-14/extracted-census-e2e.json),
[injected module](fv-2026-09-14/CensusBypass.full-gate.lean).

### F2 — MEDIUM: duplicate TLA checksum entries hide a deleted invariant

**Location:** [`tla/run_combined.sh:14–16`](../../../../contracts/verification/tla/run_combined.sh),
with the same check in `run.sh` and `run_pin.sh`.
**Tracking:** [#668](https://github.com/EthereumPhone/PQ1/issues/668).

The gate compares the number of `.cfg` files with checksum lines, then checks
only the listed hashes. Duplicate entries can therefore replace another
configuration's coverage while preserving both counts.

**Executed against real TLC:** baseline `run_combined.sh` exited 0. Removing
`INVARIANT INV_ONCHAIN_CAP` from `cb_onchain_cap.cfg` correctly produced exit 2.
Replacing its checksum line with a second unchanged `cb_margin_noreset.cfg`
checksum line then produced exit 0 and `all 3 expected outcomes matched`, with
the on-chain-cap invariant still absent. No checksum was calculated for the
weakened file. [Results](fv-2026-09-14/tla-cfg-poc.json).

**Smallest correction:** reject duplicate and noncanonical paths, compare the
exact unique path set to the expected configuration set, then verify hashes.
Retain the plain deletion as a control and add this duplicate-entry mutation.

### F3 — MEDIUM: the default proof-mutation campaign aborts before testing

**Location:**
[`check_proof_mutations.py:111`](../../../../contracts/verification/scripts/check_proof_mutations.py)
and [`proof_mutations.json`](../../../../contracts/verification/lean/scripts/proof_mutations.json).
**Tracking:** [#674](https://github.com/EthereumPhone/PQ1/issues/674), incomplete A2-demotion integration.

The manifest was updated for the A2 axiom-to-theorem change, but
`EXPECTED_MUTATION_DEFINITIONS_SHA256` still pins the base version.

**Executed:** `make -C contracts/verification verify-proof-mutation` exited 2
after the Lean build, before any mutation or canary. The base manifest hashes
to the expected `170dad9e…68e15`; the snapshot hashes to
`1ce0292e…77a3f`. The selected count and ID set still match. This is a proper
fail-closed rejection, but the required anti-vacuity evidence is unavailable;
the same target is invoked by `nightly.yml:349`.
[Failure transcript](fv-2026-09-14/proof-mutation-default.txt).

**Smallest correction:** review the changed mutation definitions, synchronize
their checker-owned digest, then execute the default campaign. Updating a pin
alone is not evidence that the mutations work.

### F4 — MEDIUM: a direct `BreaksHash` axiom bypasses the flagship gates

**Location:**
[`lint_fv_invariants.sh:282–300`](../../../../contracts/verification/scripts/lint_fv_invariants.sh)
and the source-axiom accounting in `check_ledger_consistency.py`.
**Tracking:** [#675](https://github.com/EthereumPhone/PQ1/issues/675).

The firewall excludes several ways to consume a hash-break token, but permits
an unconditional new axiom producing it. The ledger does not reject every new
project axiom outside its advertised closure set.

**Executed:** a new module imported by `SphincsCVerify.lean` declared
`axiom freeBreak : Crypto.BreaksHash` and proved
`theorem vacuousReduction (P : Prop) : P ∨ Crypto.BreaksHash := Or.inr freeBreak`.
The Lean build, FV lints, axiom lint, and live diagnostic ledger checker all
exited 0. The new theorem's closure explicitly contains `freeBreak`; the
existing headline closures remain unchanged. Thus an unadvertised reduction
can become unconditional without disturbing the tracked headline checks.

**Smallest correction:** exact project-wide axiom identity/type accounting for
the flagship tree, with this unconditional-token example as a negative
control. Do not ban legitimate conditional reduction conclusions.
[Module](fv-2026-09-14/ReviewBreakToken.lean),
[FV lints](fv-2026-09-14/break-token-fvlints.txt),
[axiom lint](fv-2026-09-14/break-token-axiomlint.txt),
[ledger](fv-2026-09-14/break-token-ledger.txt).

### F5 — MEDIUM: TLC failures are classified from banners despite abnormal exits

**Location:** [`tla/run_combined.sh:24–27`](../../../../contracts/verification/tla/run_combined.sh),
also `run.sh:24` and `run_pin.sh:26`.
**Tracking:** [#668](https://github.com/EthereumPhone/PQ1/issues/668).

All three runners discard the JVM exit status. **Executed:** a wrapper invoked
the real `/usr/bin/java` unchanged and then returned 42. The three underlying
runs returned 0, 0, and 12 respectively; every wrapper returned 42, yet
`run_combined.sh` exited 0 and reported all expected outcomes matched.
[Runner output](fv-2026-09-14/tla-exit42.txt),
[child statuses](fv-2026-09-14/tlc-child-exit-statuses.txt).

**Smallest correction:** require the pinned engine's verdict-specific exit code
as well as the expected result/invariant identity. An invariant violation is
an intentional negative result, so rejecting every nonzero exit would also be
incorrect. This is harness fault injection, not an observed TLC engine failure.

### F6 — MEDIUM: contradictory CryptoVerif results collapse to success

**Location:** [`scripts/check_protocol_models.py:305–313`](../../../../scripts/check_protocol_models.py).
**Tracking:** [#666](https://github.com/EthereumPhone/PQ1/issues/666).

`parse_cryptoverif` overwrites an earlier verdict for the same query key. The
live caller checks this collapsed dictionary and a success banner, with no raw
result-count or duplicate check.

**Executed parser/control input:**

```text
RESULT Could not prove secrecy of seed
RESULT Proved secrecy of seed
All queries proved.
```

It returns `{'secrecy of seed': True}` and an empty identity-diff list. The
failure line alone is correctly rejected. This demonstrates acceptance of an
ambiguous transcript; no failing current CryptoVerif model was demonstrated.
[Results](fv-2026-09-14/cryptoverif-duplicate-poc.json).

**Smallest correction:** reject duplicate/conflicting identities and enforce
the expected raw result coverage, including a permanent contradictory-output
negative control.

### F7 — LOW: Verity's sorry ratchet misses Lean's `admit`

**Location:** [`contracts/verity/Makefile:65`](../../../../contracts/verity/Makefile).
**Tracking:** [#673](https://github.com/EthereumPhone/PQ1/issues/673).

**Executed:** the exact ratchet awk program counts zero for
`theorem acceptedFalse : False := by admit`. Verity's pinned Lean 4.22.0 accepts
that file with exit 0 and a `declaration uses 'sorry'` warning. Thus an added
proof hole need not increase the ratchet. [Results](fv-2026-09-14/verity-admit-poc.json).

The complete Verity build was not executed. This tree is disclosed research
scaffolding with existing holes, so the finding is narrower than a failure of
the main Lean proof. Count compiler-reported `sorryAx` dependencies or all
accepted admission forms against the explicit baseline.

### F8 — LOW: the assurance case still calls A2 a consumed axiom

**Location:** [`ASSURANCE_CASE.md:306–315`](../../../../contracts/verification/docs/ASSURANCE_CASE.md).
**Tracking:** [#674](https://github.com/EthereumPhone/PQ1/issues/674).

The table calls deployed EntryPoint equivalence “consumed,” and the following
paragraph still includes A2 in `theft_free`'s kernel premises. The actual
theorem and live closure no longer consume an A2 axiom. `THE_CLAIM.md` correctly
states that deployed EntryPoint correspondence remains an external assumption.
The source and closure reproduce stale assurance text, not a newly discovered
EntryPoint exploit. Synchronize the assurance case with the controlling claim
document; a new bytecode-proof campaign is not required to correct the text.

## Claims not retained as blockers

- **Unwired Verity CI (Kimi HIGH):** absence of a workflow invocation is real,
  but this research scaffold's limited enforcement is disclosed. It does not
  establish a HIGH defect in the active Lean safety proofs. Retained as a
  scope note with #673, not a new blocker.
- **Missing deployed EntryPoint proof (SOL HIGH):** source and the controlling
  claim document explicitly retain that correspondence boundary. The novel
  snapshot defect is stale A2 accounting (F8), not an undisclosed whole-device
  or deployed-EntryPoint theorem. HIGH was not sustained.
- **Tamarin restrictions not hash-pinned (Opus MEDIUM):** adding a restriction
  equal to the theorem can make the model assumption do the proof's work.
  However, the actual gate promises lemma-formula/verdict identity, and its
  `formula_hash` “semantic edit” wording refers to that formula. No Tamarin
  mutation was executed and no violation of a whole-model pin contract was
  established. Whole-model/restriction pinning remains an unverified
  hardening note. It is not evidence that the current model is vacuous.
- Both Opus and Kimi described the TLA checksum gate as surviving inspection.
  The coordinator's executed duplicate-entry counterexample F2 overrides that
  source-only assessment; consensus was not used to decide findings.

## Evidence that survived and limits

The baseline Lean build passed. The headline `Spec/Theorems.lean` source was
also directly re-elaborated into a fresh output file, and the live diagnostic
ledger, exact headline closure checks, FV lints, and their applicable
self-tests passed. The complete baseline `verify-extracted` passed, including
its consumed-false-axiom, shrunk-closure and duplicate-dump negative controls.
Extraction freshness reported 16 pinned entries and one explicitly waived
stale Tx-Merkle extraction; no new hidden extraction drift was established.
Kani census, its nine tests, gate-enforcement checks, hardware-ledger checks,
C10 transcription checks, and protocol-checker self-tests passed. All 17 real
TLC configurations returned the expected positive or negative outcomes.
Ordinary undisclosed axioms and ordinary configuration deletion were rejected.

**Not established:** exhaustive theorem intent; a clean rebuild of every
imported module; independent kernel replay; full proof-mutation execution
(blocked by F3); current Aeneas regeneration; full Kani proofs or mutations;
the heavy decimal-format theorem; Halmos/Kontrol or deployed chain identity;
live ProVerif/Tamarin/CryptoVerif verification; external EasyCrypt research;
target binaries; physical CT/SCA/FI; hardware or production authority.
Build caches were copied and validated by Lake; no cache-only result is
described as a new independent kernel replay. The ledger command was
diagnostic, not the privileged authoritative launcher.

Every reviewer inspected only a subset within its bound; their raw GAPS are
part of this receipt. This review cannot conclude that the remaining stack is
sound or fully covered. The shortest next step is one bounded remediation of
the retained controls, followed by their negative controls and the repaired
default proof-mutation campaign before seeking a new implementation verdict.
