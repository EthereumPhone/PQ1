# FV evidence remediation — 2026-09-16

Active surface: Kani / vendored EasyCrypt split evidence correctness. Phase B
selection into bounded Phase C, authorized by “Please fix all the findings”.
Base: d52679ac76b8a1bbc373a1749b8185fea8bb372f, feat/pq1-board-target.
Existing work is recorded in the external baseline.json and preserved; implementation
uses an isolated worktree with only the pending Kani changes overlaid.

Objective: mutation credit requires a passing original and one exactly selected
failing harness; certification checks every pinned dependency, unique declaration
pins and the supported toolchain, and current split checks have enrolled callers.

Slices: (1) Kani exact selection/verdict/baseline and multiline feature checks;
(2) EasyCrypt complete dependency targets, unique pins and toolchain contract;
(3) toolchain-free per-PR and pinned-container scheduled split gates with independent
registration; (4) affected counts and historical target/evidence descriptions.

Selected approach: retain existing proof scripts and research boundary; share small
static/target/toolchain checks rather than syncing the moving external research tree.
No firmware, persistent-state, wire, signing-authority or hardware behavior changes.
Container proofs use disposable copies, no existing container or checkout mutation.
No extra research proofs or wider assurance campaign; #509 remains deferred.
Named risks: substring result confusion (#685), hidden feature gating (#662),
unreplayed dependency proofs (#683), duplicate pin substitution (#684), ambient
prover drift (#686), unenrolled current artifact (#670), stale evidence (#677).
#659's existing re-anchor is included. #681's old WOTS admit is already removed;
remaining FORS admit and model/refinement limits remain explicit.

Mandatory evidence: offline regression controls; Kani exact selection collision and
original/mutant checks including amount predicate; static census; current split
integrity plus direct broken-dependency/EOF/tool-identity controls; full split gate
under the pinned image; gate-enforcement regressions and complete registration check.
Heavy Kani stays local; no exhaustive Kani rerun required by runner-only correction.
CI full-proof timeout must accommodate the measured full gate. No hardware resources
are affected. Historical receipts remain dated evidence, never a substitute run.

Closed Phase D checklist: freeze combined commit/tree; finish the above gates and
run one simultaneous SOL ultra / Opus xhigh / Kimi max wave (900 s /800 words),
parallelizing the independent full proof replay and source review as workflow
section 4 permits. Both must finish before landing. Then reconcile and
reproduce concrete blockers; remediate/re-freeze/re-review material changes; scoped
integration preserving unrelated changes; commit/push; minimal tracker resolution
and dated receipt. Existing owner authorization covers these reversible source fixes.
Rollback is a scoped Git revert; no history rewrite or hardware action is included.

Owners read without material scope/gate conflict (SHA256):
- CLAUDE.md: 07de25be685fd4315d6d5d47c01fc4ee52df1a4c5e89b3ab45fddcff9e028074
- docs/STATUS.md: b3dac08ad8f9698b6036d922efa8b7026b041439919da8ea364f4751346567de
- docs/planning-and-review-workflow.md: db0d0934b788d6defae2a688848f9eba67e50a00b55d6918418122ac3cfd331b
- docs/verification/fv-adversarial-review-playbook.md: 560c37790255c707eb45e86fd85148115891e7ac8bdf6503d7ed7aa87983c2ad
- docs/security/adversarial-review/README.md: 46edb43d06b534a091c98de1ce81f36357d88386a78c6637ea31f100f61615f4

## Phase C evidence (before final review)

Kani 0.67.0 metadata supplied all 43 fully qualified manifest selections. Offline
checks pass (11 census, six attribution/restoration tests). Real baseline/mutant
pairs pass for the canary, CoW field offset and native amount exactness mutations;
exact selection also isolates a passing harness from a deliberately failing
similarly named fixture. All mutated sources were restored.

The split static gate passes: 45 files, 1,077 unique pins, 993 statements, exact
assumption census, policy fence and named-application taint check. Pinned image
controls pass: a broken BinaryTrees proof fails directly but imports, and an
unfinished EOF proof fails requiring. Full replay is mandatory and still pending
at this pre-review record; no fresh complete certification is claimed here.
Input identity: d7baf671282ba725121f24d59962191c.

All 19 workflow/manifest regression groups and the checker self-test pass; 67
gates are registered. Make invocation guard controls pass. Historical draft pins
pass; missing Docker returns Make exit 2 immediately. A simulated successful
compile followed by a failed require is rejected by the historical driver;
this simulation is a shell control, not proof replay of the historical artifact.

The container image is 5,281,661,595 bytes (linux/amd64), the copied vendored
artifact 29 MiB; the nightly proof lane has a 240-minute ceiling. A fresh hosted
run is not yet evidence. Original canonical work: 185 changed/untracked files,
all hashes preserved before integration. No existing research container or
external checkout was modified.

## First implementation review and correction

Frozen candidate cd43416cea0f0eb387ad8c47137f1a9c2dd6cdbe, tree
6e1b7906481a44d41d6daa2da84b9488bba38043. SOL: GAP (729.826 s),
Opus: FIX (295.302 s), Kimi: GO with pending-proof gap (628.967 s).
All reports were within 900 s /800 words. SOL's initial 47.690 s leg had only
nested-namespace tool launch failures and was stopped; its one permitted
mechanical retry retained the outer read-only mounts and used legacy Landlock.
No provider refusal was observed. Runtime artifacts remain external until closure.

Coordinator reproduced Opus's abstract-theory import failure: `require Abstract.`
passes, `require import Abstract.` fails in the pinned image. The full gate's
probe now uses plain require; .ec and .eca open-proof controls still reject EOF.
The first full replay was deliberately stopped after 17 successful direct targets
because its later import probe was known to fail; it is not a green receipt.

The heavy-tier omission also reproduced: enabling kani-heavy with tier default
passed validation. Feature and tier must now agree, with regression controls.
Kani now has seven attribution/manifest groups plus 11 census groups.

The coordinator reproduced a same-finding #684 variant while reconciling unique
pin identities: substituting an existing op through a ./ path alias passed the
static guard after deleting emb_in's pin. Source identity still detected the edit;
this was not a full-gate pass. Exact pinned-cone paths now reject aliases, and a
sixth split regression group covers it. This is a concrete acceptance-check
failure within the existing pin slice, not a broader assurance campaign.

New input identity: df34cee6a883deafc1aef86c89d8c464. The correction requires a new combined review and a
fresh full replay; no verdict from the superseded snapshot authorizes landing.

## Second implementation review and correction

Candidate b969690e628407635673db11b2ba376cd1cfd838, tree
1bd2e4f194282bce10c73826b9c9c0c39608d151: Opus GO (530.287 s),
Kimi GO (560.332 s), SOL FIX (668.557 s). All remain conditional on the
full split replay. SOL again needed its one mechanical nested-namespace retry;
no substantive report, timeout or provider refusal was retried.

Coordinator confirmed the clean-environment blocker: the shared FV Makefile
requires the password-database home's elan lake shim at parse time. In the
pinned image without elan, Make exited 2 before the recipe. The nightly job now
uses the project's existing commit/hash-checked elan bootstrap, default toolchain
none, and its complete setup/checkout/invocation step sequence is pinned in the
gate contract. The same setup in a disposable clean container followed by the
split fast Make target passed. This is setup evidence, not a hosted workflow run.

The parser also accepted a synthetic completed failing verdict followed by an
explicit fatal tool diagnostic. It now rejects recognized fatal compiler/backend
and panic diagnostics across the full combined output, including ANSI coloring.
All six recorded real original/mutant outputs retain their correct classifications;
new negative controls cover errors before and after the coherent result. This is
a parser regression, not a claim that such a post-verification failure occurred
in the recorded Kani runs. Kani now has eight runner groups and 11 census groups.

These corrections do not alter any split proof input, tool image, driver flags
or df34cee6a883deafc1aef86c89d8c464. The ongoing full replay remains applicable.
A fresh combined source review is required. Full Kani nightly timing under the
300-minute ceiling remains a visible, fail-closed follow-up measurement.


## Final review, proof replay and landing

The final reviewed candidate is 775133e8abd3452bca952336bc8e31e452a7f7f5,
tree 2766afb8829e5f38935718c01f8365e4758e9153. The third combined wave
returned Opus GO (299.143 s /599 words), Kimi GO (561.520 s /504 words),
and SOL GAP with no findings (518.558 s /25 words). SOL's sole gap was the
independently running full split replay. Its initial namespace launch failure
received one mechanical retry, with the original prompt, model and outer
read-only mounts retained. Every accepted report was within 900 s /800 words;
no substantive answer or provider refusal was retried.

The full pinned-image replay subsequently completed with exit 0 and
`RESULT: GREEN`: 45/45 direct compilation targets, all 45 require checks,
45/45 second-driver files with zero disagreements, and the retained pin,
inventory, census, control, margin, fence and named-application taint checks.
The start and end input identity was df34cee6a883deafc1aef86c89d8c464.
Completion: 2026-09-16T14:07:33.612963+00:00; container lifetime: 84.43 minutes.
The exact image and compiler/25-prover inventory were checked before proofs.
This executable result discharges SOL's pending-proof gap; it does not change
or replace SOL's original report. Coordinator disposition: GO for this bounded
source/evidence-tooling fix. There are no remaining reproduced merge blockers.

The source patch was applied to the canonical working tree on
7a00a92eeeb723b070ba2c3a0021bcb173edf810, leaving the shared index untouched. The isolated
integration index reproduces every reviewed FV blob, with only disjoint,
already committed boot hunks additionally retained in the root Makefile.
The working tree also retains the unrelated pending deployment-profile gate
note. This receipt and its raw artifacts are the only subsequent FV additions.
The combined working-tree checks pass, including the unchanged split identity.
Pending work outside this slice was preserved. Review of this patch does not
review or certify the concurrent boot/lockdown changes.

Publication is scoped to `fix/fv-evidence-20260916`, based on the published
43cf620873b54670bbfbee6355685057856fad69. It excludes the unrelated
local ancestor commits. Applying the same reviewed patch changes exactly the
28 selected FV paths; the publication checkout retains its pre-existing status
document context. All executable FV inputs match the frozen review, and the
publication checkout passes the census, gate-enforcement and split-integrity
checks with the same df34cee6a883deafc1aef86c89d8c464 proof identity.

[Raw evidence](fv-evidence-remediation-2026-09-16/README.md), including the
original reports, prompts, runtime manifests, focused test logs and complete
proof log, is bound by the adjacent SHA256SUMS. The superseded partial first
proof run is explicitly labelled and is not credited as a green run.

Resolution scope: #659 re-anchors and exercises the native exactness-predicate
mutation; #662 enforces the local heavy tier and feature contract; #670 enrolls
the current artifact and adds EOF/failure controls; #677 corrects census and
evidence wording while retaining the dated parameter-harness receipt; #683
replays every pinned dependency; #684 rejects duplicate and aliased pins;
#685 requires a passing original, exact single-harness failure and no fatal
tool diagnostics; #686 pins and checks the toolchain. #670's original claim
that the old missing-Docker recipe exited zero was refuted: it eventually
exited 2; this fix makes that failure immediate and removes misleading output.
#681's named WOTS admit was already removed in 2c55ccc5, so that suspicion is
superseded rather than a newly discharged theorem in this patch.

Residual boundary: FORS_C_TreePort.extract_op remains an explicit admit;
named-application taint does not cover implicit SMT/clone dependencies.
The reductions remain conditional, with unreduced probabilities, no numerical
security bound and no machine-checked firmware serialization/bounded-grinding
refinement. Focused Kani checks are not a fresh full/heavy Kani campaign or a
hosted CI success. Hosted runtime measurements and the future ambiguous-name
census observation are banked in [#509](https://github.com/EthereumPhone/PQ1/issues/509#issuecomment-5698091621);
the broader owner-triggered assurance pass remains deferred.
