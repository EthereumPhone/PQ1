# FV assurance-control remediation — 2026-09-14

**Status (2026-09-15): all eight retained fixes are implemented; required
executable gates pass. The fresh SOL/Opus/Kimi wave returned GO within its bounds.
The owner authorized publication on `feat/pq1-board-target`; this commit contains
the reviewed fix files, required FV prerequisites and evidence.**

Final source snapshot: `b616e22d11ef0aa3689bc574a96fe24b7d63cca7`, tree
`ef385c4516afcc67429bb71ee124a9c767b153b0`. The [receipt](fv-remediation-2026-09-14/receipt.json)
binds the 23 product files, patch, checks and review disposition.

Active surface: formal-verification evidence acceptance. Phase D: one bounded
remediation batch, authorized by the owner's request to fix the retained review
findings. Baseline HEAD `d15426e3dcf04e68fb97a6a2800ec2690d12ed8d`, branch
`feat/pq1-board-target`; discovery snapshot
`aab89656690cf4b15a543b21e58a3ad4f918ec16`. The discovery
[report](fv-adversarial-review-2026-09-14.md) owns the eight findings and six
tracker links. Source-input digests and dirty-state manifest are recorded in
`/tmp/pq-fv-fixes-20260914-iddnxo7n`. No conflicting requirement was found among the active
owner documents; THE_CLAIM.md owns the A2 statement, and the workflow owns review
cadence. The FV playbook supplies the applicable negative controls.

## Bounded slices and evidence

1. F1/F4, #676/#675: exact axiom inventories for both Lean projects. Reject
   hidden/private declarations, same-name additions, changed types/namespaces,
   missing declarations, and quarantine imports. Retain the existing closure
   checks. Prefer a conservative source census with pinned axiom-bearing modules
   plus an elaborated declaration inventory over extending ad hoc declaration
   regexes. Imported declarations and unbuilt source need distinct coverage;
   the 42-GB heavy extracted proof remains outside the default build envelope.
2. F2/F5, #668: one shared TLC harness validates a unique, complete canonical
   config path set and hashes, process status, and exact expected invariant
   result. Run all 17 configurations and duplicate/omission, wrong-result,
   conflicting-output and abnormal-exit regressions.
3. F3/F6/F7, #674/#666/#673: review and re-pin the existing mutation definitions,
   execute the default eight-mutation campaign; reject duplicate or malformed
   CryptoVerif results; count `admit` and `sorry` in the Verity ratchet. Run
   parser controls and actual Lean/Make rejection probes.
4. F8, #674: align ASSURANCE_CASE.md with the proved in-model A2 theorem and the
   separate, still external deployed-EntryPoint assumption.

The fail-closed invariant is that incomplete, contradictory or changed evidence
cannot earn the prior success claim. This changes verification tooling and
assurance prose, with no firmware, wire format, persistent state, signing
eligibility, hardware operation, deployment, or production-authority change.
No new cryptographic assumption is introduced. Existing source changes are
preserved. Mutation experiments and review run in disposable snapshots, and
only this batch's edits are overlaid into the working tree. Rollback removes
those edits, without resetting user work.

## Closed Phase-D completion checklist

1. Mandatory: focused regressions, both Lean builds and axiom gates, FV invariant
   lints, ledger consistency, default proof mutations, the three TLC suites,
   protocol-parser self-test and live CryptoVerif where installed, Verity build
   and ratchet. Preserve exact commands, outcomes and any tool limitation.
2. Freeze the combined candidate in a clean isolated clone. Review once with
   simultaneous SOL/Opus/Kimi under the workflow's 900-second/800-word bounds.
3. Reproduce concrete blocking findings locally, remediate and re-freeze/review
   if the implementation changes materially. Bank unrelated observations.
4. Preserve the review receipt, update the six existing issues with evidence,
   and hand back the reviewed fixes. Do not commit unrelated working changes.

The discovery evidence is reusable only for the pre-fix failures. A broader
combined playbook sweep and hardware/shipment gates remain later owner-triggered
assurance; they do not delay this source remediation stage.

## First implementation review and corrections

The candidate `eb398b7b85cffc14ed1c45dfb7c1cfdfafb89a1e` (tree
`8120c3bd802ed6106f5f3926e1efdc11952c6f32`) received Kimi GO, Opus FIX,
and SOL FIX. SOL's initial source-access GAP was retried once with the skill's
documented Landlock fallback. No report was fed to another reviewer.

Coordinator reproduction confirmed that Lean's zero-`#` raw string syntax
(`r"…"`) could desynchronize the scanner and hide an axiom or `admit`. Both
pinned Lean versions accepted the exact inputs; the extracted inventory gate
and actual Verity `ci` recipe returned zero before correction. The parser now
accepts zero or more `#`, and the exact probes are regressions. They fail the
corrected gates. This is a material correction requiring a new combined freeze.

Both reviewers also found older A2 closure claims earlier in ASSURANCE_CASE.md;
SOL identified the same stale claim in its linked TRUST_ASSUMPTIONS.md. Those
passages are corrected within F8's existing claim-consistency scope. The
deployment-faithfulness premise remains external. No new product surface or
cryptographic premise was added. Other mandatory evidence is reusable where
its code and inputs are unchanged; both affected Lean gates and Verity ci are
rerun after the scanner correction.

## Second implementation review and lexical correction

The next candidate `88818c79d83e8f73177d43c8edbc6393ce1e1ad2` (tree
`5e36ac92d2387ffefc0d1ee6459c70699ae32774`) received SOL GO, Kimi GO, and
Opus FIX. SOL again required the one documented mechanical sandbox retry.
Coordinator reproduction confirmed both reported scanner errors: a raw-string
match at the end of `leading_parser` and a character-literal match at the end
of `refine'` could erase a following real declaration. Related interpolation
cases with whitespace, comments, newlines, and `dbg_trace` demonstrated why a
prefix guess is insufficient.

The scanner now retains text under the union of possible literal interpretations
and removes only definite comments. It explores ordinary/interpolated strings
and both literal/code interpretations of possible raw and character starts.
Resource limits fail closed. Raw keyword absence avoids unnecessary scanning of
large hex-vector literals; quarantine-reference scanning has the same literal
component precondition. Inventories and hole budgets are unchanged.

All six inputs, each with an axiom and with `admit`, compile under both pinned
Lean versions (24 successful compilations). Four representative cases also
exercise the actual extracted inventory and default-built Verity ci before and
after correction: all eight old-gate runs returned zero; all eight corrected
gates rejected the added declaration/hole. Fixtures were restored in `finally`
blocks in the disposable validation checkout. These are local defensive gate
regressions, not tests against a deployed system. The concrete controls and
compiler output are retained in the receipt directory. This material correction
requires a fresh bounded review under workflow §10.

## Implemented fixes and executable evidence

| Finding / tracker | Final behavior and evidence |
|---|---|
| F1 / [#676](https://github.com/EthereumPhone/PQ1/issues/676) | Extracted source census pins all axiom-bearing module bytes, including private/namespaced declarations and unbuilt modules; the fresh default environment has an exact name/module/type inventory. Undisclosed private axioms and quarantine imports are rejected. |
| F2, F5 / [#668](https://github.com/EthereumPhone/PQ1/issues/668) | Shared TLC runner requires the exact unique set of 17 canonical config pins, matching hashes, expected process status, and unambiguous expected outcome. All 17 real outcomes pass; duplicate/omission and forced exit-42 controls reject in all three entry scripts. |
| F3 / [#674](https://github.com/EthereumPhone/PQ1/issues/674) | Re-pinned the reviewed mutation definitions to `1ce0292e6817e6d88ba9fbc5afc60e24c067043adc95d04ed94d4ea85dd77a3f`. All eight default mutations produce their expected build/closure outcomes. Definitions themselves were not changed. |
| F4 / [#675](https://github.com/EthereumPhone/PQ1/issues/675) | Main Lean has the same source and fresh-environment inventory discipline. A free BreaksHash witness fails the source gate; an elaborator-generated axiom with no literal `axiom` keyword fails the environment gate. Existing exact theorem-closure checks remain mandatory. |
| F6 / [#666](https://github.com/EthereumPhone/PQ1/issues/666) | CryptoVerif parses every RESULT line strictly and rejects duplicates, malformed/indented results, and contradictory evidence. Parser controls and live CryptoVerif 2.12 pass. |
| F7 / [#673](https://github.com/EthereumPhone/PQ1/issues/673) | Actual Verity ci counts `sorry`, `admit`, `sorryAx`, and `proof_wanted` in all source modules, including unbuilt Part A. Budgets remain 11 in Theorems and 1 in Merkle, zero elsewhere. Added admitted proofs fail the gate. |
| F8 / [#674](https://github.com/EthereumPhone/PQ1/issues/674) | ASSURANCE_CASE and TRUST_ASSUMPTIONS consistently distinguish the proved in-model A2 theorem from external deployed-EntryPoint faithfulness. No A2 axiom is added to closure or inventory. |

The [evidence directory](fv-remediation-2026-09-14/) contains commands, statuses,
negative controls, compiler output, raw reviewer reports, manifests, source
hashes, and the combined patch against the discovery snapshot. In particular:

- [Final affected gates](fv-remediation-2026-09-14/raw-gates.json):
  `verify-fv-lints`, `verify-extracted`, and Verity `ci` all return zero after the
  last scanner correction. Both exact environment inventories contain 27 axioms
  including dependencies; this does not authorize `sorryAx` in theorem closures.
- [Earlier unchanged gate evidence](fv-remediation-2026-09-14/final-gates.json):
  authoritative ledger wrapper, placeholder lint, TLC, protocol checks, and
  gate enforcement pass. The first gate-enforcement invocation mistakenly used
  Python `-S`, disabling its required PyYAML dependency; the recorded normal
  interpreter retry passes all 62 checks.
- [Proof mutation run](fv-remediation-2026-09-14/proof-mutations.log): all eight
  default mutants behave as declared, including exact closure drops for markers.
- [Negative controls](fv-remediation-2026-09-14/negative-probes.json),
  [24 compiler probes](fv-remediation-2026-09-14/lexical-compiler-probes.json),
  and [actual lexical gate probes](fv-remediation-2026-09-14/lexical-gate-probes.json)
  distinguish buildable inputs from parser-only test strings.

Evidence applies to source acceptance. `verify-extracted` retains its documented
FormatDecimalSpec heavy-build exclusion (about 42 GB kernel checking, separate
≥48 GB host target). Verity retains 12 existing holes and its default Part-B
build; this work does not claim completed proofs or shipment readiness. The
existing deferred combined FV playbook item
[#509](https://github.com/EthereumPhone/PQ1/issues/509) remains owner-triggered.

## Third implementation review and comment/boundary correction

Candidate `98446edc2b37cc5874f54cfe1091264ddc44eb3f` (tree
`01e56934a227bf3969e35c46b3e7b6f19fd5c39e`) received Opus FIX, SOL FIX,
and Kimi GO. All source-review reports finished within 425 seconds and 800
words. The same single mechanical sandbox retry was necessary for SOL. Kimi
prefixed its required verdict fields with a source-review summary; its unmodified
344-word report is retained. No majority vote was used.

Coordinator reproduction confirmed the two mechanisms: Lean consumes a third
character before scanning an outer block-comment body, and Python word
boundaries do not model adjacent Lean numeric/character/custom-syntax tokens.
The comment scanner now explores both two- and three-character opener readings,
with two-character nested openers. The census no longer guesses any token
boundary: it counts every retained substring. This deliberately pins the two
existing extracted `#print axioms` modules as well. Existing pinned module bytes
and both elaborated inventories are unchanged; no axiom or hole is added.
The manifest field is now `axiom_mentions`, reflecting the conservative count.

Nine new complete inputs (five axiom cases and four hole cases) compile under
both pinned Lean versions. All nine pass their applicable old actual gate, and
all nine fail their corrected gate. A source regression also checks the hidden
quarantine-import form. The prior literal/interpolation controls remain in the
suite. The updated source-inventory comparison is recorded in
[substring-source-repin.json](fv-remediation-2026-09-14/substring-source-repin.json).
This is a reproduced blocker correction within the original surface, requiring
another combined freeze and review under workflow §10.

## Fourth implementation review and removal of lexical interpretation

Candidate `1fb541057aa0244e8a6ce526de6e35fd16de0b2a` (tree
`ba33e1143822f0bf36676539b723e8d14a668077`) received Opus FIX, SOL FIX,
and Kimi GO. All source reports completed within 338 seconds and 800 words;
SOL again used its one documented mechanical sandbox retry. The reports are
retained unchanged, including Opus/Kimi's explanatory text outside the requested
verdict fields. Coordinator reproduction confirmed that custom tokens can
consume apparent comment markers and quoted-identifier openers, making a
context-free comment remover unsafe for this gate.

The final correction removes lexical interpretation entirely. Every raw
substring mention counts, including prose and strings. The source inventory
therefore pins 26 main-Lean and 39 extracted modules. All previously pinned
module hashes and both elaborated inventories remain unchanged. Quarantine
component references are rejected even in prose. The counter has linear work
in the input length and no ambiguity state machine or parse-budget exception.

Verity applies the same raw rule against its unchanged 11+1 budget, with no
comment allowances or hash exceptions. Six prose references in Theorems, Top,
and Hypertree were reworded to avoid false positives; proof statements and
bodies are unchanged. These necessary comment edits are part of F7's gate
correction. Both the source-module re-pins and the exact six replacements are
recorded in [raw-source-repin.json](fv-remediation-2026-09-14/raw-source-repin.json).
Future raw mentions in comments or strings can conservatively fail this gate.
An intentional edit to an axiom-pinned module requires a reviewed source re-pin;
no automatic re-pin path or increased assumption/hole allowance was added.

Ten complete custom-token inputs compile under both pinned Lean versions (20
compilations). All ten pass the old applicable actual gate and fail the final
raw-mention gate. The six regression groups retain every earlier literal,
comment, token-boundary and quarantine case, and check that prose/string
mentions cannot grant an extra Verity hole. The exact default build envelope
and separate elaborated/closure controls remain in force. This material blocker
correction receives a fresh bounded wave under workflow §10.


## Interrupted final-snapshot review (superseded by the authorized resumption)

The final candidate is `b616e22d11ef0aa3689bc574a96fe24b7d63cca7`, tree
`ef385c4516afcc67429bb71ee124a9c767b153b0`, compared for its last correction
against `1fb541057aa0244e8a6ce526de6e35fd16de0b2a`. The combined
[implementation patch](fv-remediation-2026-09-14/implementation.patch) is against
original discovery snapshot `aab89656690cf4b15a543b21e58a3ad4f918ec16`.
All 23 canonical product files match the frozen candidate; no main-worktree
commit or push was made. The isolated snapshot remains clean and unchanged.

The final wave used GPT-5.6 SOL `ultra`, Claude Opus 5 `xhigh`, and Kimi K3
`max`, with the same prompt hash
`7c03fc052c0b225cf62ac85de96d5e2df32e712eca76dce726ca48ef872843de`.
Requested limits were 900 seconds and 800 words. Offline adapter tests and dry
runs passed for Codex 0.154.0, Claude 2.1.270, Kimi 0.40.1, and Bubblewrap 0.9.0.
No reports were fed between reviewers. Read-only candidate/Git mounts and
separate output directories provide procedural non-disclosure, not strict
same-UID host isolation.

| Reviewer | Observed result | Timing and evidence |
|---|---|---|
| Opus | GO, no finding | 545 words; 285 s active timer but 62,384 s UTC span; [raw report](fv-remediation-2026-09-14/wave5-opus.txt) |
| Kimi | GO, no finding | 205 words; 382 s active timer but 62,481 s UTC span; [raw report](fv-remediation-2026-09-14/wave5-kimi.txt) |
| SOL | GAP | Initial namespace failure, then the sole documented Landlock retry; stopped at 654 s active / 62,754 s UTC span, no final report; [retry manifest](fv-remediation-2026-09-14/wave5-sol-retry-manifest.json) |

The host paused overnight after the wave began at 2026-09-14 16:43 UTC.
The launcher's monotonic timer excluded that pause. On resumption, the UTC
elapsed time exceeded the workflow's hard wall-clock cap. The coordinator
terminated the remaining SOL process group at 2026-09-15 10:10 UTC and preserved
[the interruption record](fv-remediation-2026-09-14/review5-host-suspension.json).
The completed GO reports support the source correction, but **this is not a
compliant completed final review wave**. No substantive blocker remains from
those reports; the missing/timing-limited review evidence remains a gate gap.

Workflow §10 and the bounded-review skill permit no further automatic retry
here. The shortest compliant next step is an explicitly owner-authorized fresh
bounded SOL/Opus/Kimi wave on this unchanged candidate, with elapsed time checked
across host suspension. That confirmation was requested while the coordinator
finished the receipt and tracker updates. No merge or production acceptance is
claimed. The broader combined playbook remains deferred in #509.

The six existing issues were updated with the implemented slices, validation,
and explicit final-review gap; none was closed. Exact comment URLs and write
receipts are in [tracker-updates.json](fv-remediation-2026-09-14/tracker-updates.json).

## Owner-authorized resumption — 2026-09-15

The owner explicitly authorized continuation after the laptop shutdown. One fresh
SOL/Opus/Kimi wave now reviews the unchanged final candidate with the same prompt.
All 23 product hashes and six owner/source-input hashes were checked unchanged,
so the completed executable evidence is reused. The session-local launcher clock
uses Linux CLOCK_BOOTTIME, which includes suspension; final receipts also check
UTC elapsed time against the 900-second bound. The prior interrupted wave remains
recorded above and in [wave5-receipt.json](fv-remediation-2026-09-14/wave5-receipt.json).

The [resumption record](fv-remediation-2026-09-14/review6-resumption.json) records
the authorization, adapter checks and single mechanical SOL retry. Claude Code
updated to 2.1.272; the offline self-test and inspected concrete dry run passed.
No source changed and no prior reviewer report was supplied to a fresh reviewer.


### Completed review and coordinator disposition

| Reviewer | Result | Elapsed including suspension | Words | Raw report |
|---|---|---:|---:|---|
| GPT-5.6 SOL, ultra | GO, no finding | 401.554 s | 10 | [SOL](fv-remediation-2026-09-14/wave6-sol.txt) |
| Claude Opus, xhigh | GO, no finding | 267.024 s | 591 | [Opus](fv-remediation-2026-09-14/wave6-opus.txt) |
| Kimi K3, max | GO, no finding | 314.286 s | 281 | [Kimi](fv-remediation-2026-09-14/wave6-kimi.txt) |

All three initial legs started within one millisecond at 10:32:33 UTC. SOL's
19-second mechanical source-access failure received its one documented retry,
which began at 10:33:17 UTC. Both CLOCK_BOOTTIME and independent UTC durations
are below 900 seconds. Target commit/tree, prompt equality, report hashes,
word caps, clean snapshot and all 23 canonical product hashes were verified.
Opus and Kimi supplied explanatory checks beyond the requested verdict fields;
their unmodified reports remain below the word cap. No further model round ran.

Coordinator decision: **GO for the eight retained source-remediation slices**.
There is no accepted blocker or unresolved mandatory review gap for this frozen
correction. The reviewer-local lack of repeated builds does not remove the
coordinator's already-green isolated gate evidence, whose inputs are unchanged.
The report and receipt preserve the interrupted wave as historical evidence;
the fresh completed wave supersedes its acceptance gap.

Opus also recorded a pre-existing boundary of the Verity research ratchet:
raw mention counting is not a complete elaborated-hole census. The pinned Lean
4.22 `Init/Tactics.lean` defines `stop` using `repeat sorry`; metaprogrammatic
constructors can likewise create holes without the four scanned raw forms.
The coordinator checked that definition and the current gate patterns. This
is not a new hole in this candidate or a regression in the reviewed raw-mention
contract; F7's demonstrated `admit` form is rejected. The broader semantic
census obligation stays open in #673. Two stale Makefile comment references are
also recorded there as editorial follow-up, without changing the frozen source.
The 12 existing holes and heavy-build exclusions above remain explicit.

The six remediation issue comments are refreshed to clear the review gap while
leaving their landing and broader obligations open. The deferred combined
playbook remains #509. This handoff does not make a merge or shipment claim.


## Authorized landing — 2026-09-15

The owner requested “push the fixes.” The publication slice is 23 remediation
files plus 14 existing FV prerequisites: the A2 theorem/closure/ledger/mutation
inputs, related Lean and Verity assurance documentation, and the complete TLC
config pins and documentation. All 37 files are byte-identical to their versions
in reviewed snapshot `b616e22d`. Unrelated firmware, parser, test, hardware,
CI/Kani and other pending edits remain in the main worktree.

The [landing receipt](fv-remediation-2026-09-14/landing-receipt.json) binds every
selected source hash and executable mode. All 191 tracked Lean/Verity files and
all TLC model/config inputs match the reviewed snapshot. The original model
verdicts stay bound to their recorded snapshot; no new implementation or source
re-pin was made during landing.

An isolated worktree at branch base `d15426e3` containing exactly this product
slice passed all eight [landing checks](fv-remediation-2026-09-14/landing-gates.json):
FV lints/main axiom inventory, extracted build/inventory/66 exact closures,
authoritative ledger consistency, Verity ci, gate-enforcement, protocol parser
self-test, live CryptoVerif 2.12, and all 17 TLC outcomes. This verifies that the
selected source is self-contained without the excluded working changes. The
landing gate-enforcement result uses the branch's existing checker/CI pair;
it does not claim to publish the separate pending CI/Kani hardening. The earlier
eight proof-mutation outcomes and negative controls remain applicable because
the exercised inputs are unchanged.

The Git commit carrying this record supplies the publication identity, and the
six linked issue threads receive that exact pushed commit. The broader Verity
semantic census (#673) and deferred owner-triggered assurance (#509) remain
open. This is a source-code push, with no deployment or shipment claim.
