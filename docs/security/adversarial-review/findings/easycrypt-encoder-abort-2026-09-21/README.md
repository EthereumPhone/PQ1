# EasyCrypt C10 encoder and bounded signing receipt — 2026-09-21

The implementation at `47c9bb1edd4ee4386ac1f829f762a9d924df94fd` (tree
`553f3ff818a366a88a8b54fb5801c5205d08d852`) passes the full split certification
and has source-merge GO reports from Astra and Opus. Compare against master
`19ddfc401ac3ba6c473f628d7552a4f8bc45ddef`; PR #716 also includes the preceding
literature reassessment. The user substituted Astra for SOL and excluded Kimi.
This is a source-merge result, not a shipment or end-to-end security verdict.

The [first full replay](full-split-superseded-failed.log) on `03115874` failed:
WOTS_C_Multi's combined loop-exit SMT step produced a driver disagreement.
The correction makes mapped-list sizes and the completed-loop length explicit,
then applies the existing invariant. The theorem, premises and prover budgets
are unchanged. The corrected file passes [CLI](wots-cli-corrected.txt) and
[compile](wots-compile-corrected.txt), followed by a fresh complete replay and
fresh combined review on the corrected snapshot. The earlier GO reports did
not override the failed gate.

## Result and limits

The actual consumer encoder is defined, its digit order and target 205 are
proved, and its predicate is connected to the exact CountDS acceptance mass
for independent uniform input. Bounded signing represents exhaustion as no
signature and agrees with the existing signer and oracle state on successful
searches. The separate IID law preserves both exhaustion and successful-event
mass. No new project axiom or admit was introduced. The existing inventoried
FORS_C_TreePort admit remains subject to its prior containment boundary.

The manual EasyCrypt model, finite Rust correspondence checks and targeted Lean
kernel check remain separate evidence. This batch does not regenerate Aeneas
extraction or prove a Lean/EasyCrypt bridge. A failure-aware end-to-end reduction,
real shared-SHA-256/adaptive-history coupling (including FORS truncated R), and
numerical EUF-CMA bounds remain open in #100/#295. The combined playbook sweep
remains deferred in #509.

## Evidence

- [Full split replay](full-split.log): 66 proof files under both drivers,
  1,332 declaration pins, 1,201 statements, 64 controls, no driver disagreement,
  unchanged input identity `946053f3a3915a95a5556a0a08a93fb7`.
  The wrapper also verifies 20 source bindings and both Rust correspondence
  tests: 210 transcript cases and 259 digit inputs.
- [Fast split gate](fast-split.log), [gate registration](gate-enforcement.log)
  and [22 gate regression groups](gate-enforcement-tests.log) pass.
- [Targeted Lean build](lean-wots.log) and [axiom dump](lean-wots-axioms.log)
  pass. `extract_digits_spec` and `extract_digits_lt` use only `propext`,
  `Classical.choice` and `Quot.sound`. The [selected source/output hashes](selected-extraction-pins.json)
  match the extraction registry; this is a pin check, not regeneration.
- [Astra](astra.txt) and [Opus](opus.txt) report no blocking findings.
  [Runtime receipt](receipt.json) records exact identities, prompt hash,
  report hashes, timings and limitations.

The initial Astra leg could not access source because its nested Bubblewrap
command backend failed. The one permitted same-model mechanical retry used
legacy Landlock inside the unchanged outer read-only mounts and completed
within the original 15-minute aggregate bound. It used the identical prompt.
The [initial gap report](astra-initial-gap.txt) is preserved. No provider policy
refusal occurred in this wave. No Kimi request or extra reviewer was launched.

Opus noted conservative historical wording. The feasibility introduction is
aligned with its already-reviewed implementation section in the final receipt
commit; historical WOTS_C_Real and generic BadEncCountermodel comment cleanup is banked on #100. No formal
source, behavior, acceptance gate or reviewed claim boundary changes in that
editorial/receipt commit (workflow section 10, coordinator classification).

## Hosted CI disposition

Focused gate registration, main Lean FV, secure host tests, firmware target,
QEMU, Miri and cargo-vet pass. Broad CI remains red on unrelated baseline
failures: hardware ledger #660, PinState freshness #661, curation receipt and
fuzz lockfile #711, and Foundry installer #717. The Foundry failure was also
confirmed on the exact master base. The [job-level disposition](ci-disposition.json) records the observed causes and log hashes.
The affected workflows, proto/xtask/fuzz sources and Solidity sources are unchanged by this batch. No gate was weakened
or bypassed, and no broad CI-green claim is made.
