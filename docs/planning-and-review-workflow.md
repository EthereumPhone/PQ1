# Engineering planning and fast adversarial-review workflow

**Status:** active project process

**Owner:** this document

**Applies to:** non-trivial design, implementation, security, migration, and
hardware-facing work

This document defines how PQSigner work moves from an idea to a reviewed,
owner-authorized stage. It is intentionally shorter than a feature
specification: plans and review receipts point here instead of recreating the
process for every task.

Project invariants remain owned by [`../CLAUDE.md`](../CLAUDE.md). Current
security state remains routed through [`STATUS.md`](STATUS.md). Surface-specific
attack catalogs and finding formats remain owned by
[`security/adversarial-review/`](security/adversarial-review/README.md). This
document owns only planning, scope change, convergence, and the required fast
three-reviewer protocol.

Task-specific normative specifications and explicit owner decisions may impose
stricter gates and take precedence for their scope. Surface playbooks may impose
technical evidence requirements when their sweep is active, but they do not
auto-activate themselves or override this workflow's reviewer cadence. This
workflow cannot grant authority a more specific owner document withholds.

Preserved research candidates may contain the review choreography that was
current when they were frozen. Those embedded process clauses are historical
unless an explicit owner decision re-adopts them: this document controls the
current reviewer configuration, cadence, and finding-status authority. This
rule changes no technical requirement inside the preserved candidate.

## 1. Operating principles

1. **Security and correctness outrank elegance, schedule, and line count.** A
   mechanism forced by a named invariant or demonstrated failure mode is not
   overengineering merely because it is complex.
2. **Explore freely; accept selectively.** Agents and reviewers may investigate
   broad alternatives, new threats, and stronger requirements. YAGNI governs
   what becomes an accepted requirement or implementation, not what a model is
   allowed to consider.
3. **Choose the smallest design that satisfies the evidence-backed
   requirements.** Optional hardening remains visible as GitHub issues
   (`EthereumPhone/PQ1`; `work-todo.md` was retired 2026-07-19 — see its stub);
   it does not silently accrete into the active
   plan.
4. **Prefer reversible evidence before irreversible action.** Source analysis,
   host models, fault-injection models, resource spikes, QEMU, and
   non-destructive silicon checks precede OTP, option-byte, lifecycle, or
   factory-state mutations.
5. **Claims stop at the evidence boundary.** A host model does not prove
   silicon behavior; a link receipt does not prove worst-case stack; a model
   review does not approve production shipment.
6. **Preserve research without making it authority by accident.** Superseded
   designs remain clearly labelled as historical or research inputs. The
   selected plan names its exact authoritative artifacts.
7. **Review recommendations belong to an exact snapshot and stage.**
   Architecture, implementation, merge, and production recommendations are
   separate. None is inherited by a changed digest, and none replaces the
   owner or authorized maintainer's stage-transition decision.
8. **Batch implementation review at explicit phase boundaries.** A bounded,
   reversible Phase C campaign may contain several related implementation
   slices under one recorded scope and fail-closed authority contract. Each
   slice still earns proportionate executable evidence, but the complete
   three-reviewer wave runs on the frozen combined Phase D candidate,
   not after every commit or formatter addition. Expansion and authority
   triggers still stop the batch immediately. Keep one batch to a coherent
   feature family and normally **2–5 slices**; a larger campaign needs an
   explicit smaller review boundary rather than accumulating an open-ended
   diff.
9. **Playbooks are deferred assurance floors, not reviewer prompts.** The fast
   reviewers derive failures from the frozen source and short invariant list.
   The later combined lock-in pass uses applicable catalogs as a completeness
   check. A catalog row, status label, or claimed defense is never a premise.
10. **Finish the active stage before improving the process around it.** Once a
    candidate enters Phase D, the closure checklist is closed. Optional
    assurance, reviewer additions, documentation polish, tooling cleanup, and
    adjacent hardening are banked unless they were already a named gate or a
    concrete Section-5 trigger makes them stage-blocking. Review ceremony must
    remain proportionate to the stage being decided.
11. **Time-box exploration, never the truth.** Phase-D runtime and report caps
    are stop-new-exploration and synthesize-now limits, not automatic approval.
    Reviewers prioritize mandatory stage-impacting questions, report any honest
    gap at the cap, and stop. A gap may block a verdict; it does not authorize an
    unbounded campaign, extra reviewers, or repeated inspection of settled
    evidence.

The practical rule is: **do not suppress exploration, and do not implement
speculation as if it were a requirement.**

## 2. Classify the work before planning it

| Class | Typical examples | Minimum process |
|---|---|---|
| Routine and reversible | Local refactor, typo, isolated test, non-authoritative tooling | Scoped plan or direct change; proportionate tests and ordinary review |
| Security-sensitive or invariant-adjacent | Signing, parsing, trusted display, TrustZone, SE protocols, update selection, counters, wire formats | Written plan, threat/invariant mapping, executable evidence, and the three-reviewer wave below |
| Immutable, irreversible, or production-authority-bearing | FSBL, OTP, WRP/RDP/option bytes, SE lifecycle locks, factory keys, on-chain frozen interfaces | Three-reviewer architecture and implementation waves, explicit owner authorization for irreversible actions, resource and physical evidence, and a distinct shipment verdict |

If classification is uncertain, use the higher class until evidence narrows it.
Classification raises review depth; it does not grant authority to perform a
destructive action.

## 3. Required plan packet

A non-trivial plan must make the following reviewable before implementation:

1. **Objective and observable outcome.** State what becomes true when the task
   is complete.
2. **Baseline identity.** Record repository, branch, `HEAD`, dirty/untracked
   manifest, and any input document or artifact digest.
3. **Sources-of-truth preflight.** Follow `STATUS.md` owner links and record the
   path, revision or digest, authority scope, stated status, and evidence date
   for every requirement, task specification, surface playbook, hardware
   source, and prior receipt used by the plan. Check those active inputs for
   conflicting requirements, authority, gates, or evidence claims before
   freezing the packet. Neither document class nor publication date silently
   wins: quote any material conflict, identify the affected gate, and stop
   until the named owner resolves it or explicitly carries it as an open
   decision. Do not copy facts into a second owner.
4. **Named invariants and threats.** Say which invariant each mechanism serves
   and the concrete failure if it is absent.
5. **Scope and non-goals.** Name what may change, what is deliberately deferred,
   and the required stopping point.
6. **Assumptions, open decisions, and unknown physics.** Separate verified
   facts, model assumptions, product choices, and hardware questions.
7. **Alternatives and deletion candidates.** Include the smallest credible
   design, the selected design, and any mechanism whose necessity should be
   falsified before it becomes expensive.
8. **Authority and reversibility.** List external writes, deployment, flashing,
   OTP/lifecycle mutations, or factory operations. Identify which require a
   fresh owner decision.
9. **Resource and compatibility envelopes.** Record FLASH, RAM, stack,
   performance, wire/schema, persistent-state, and migration constraints that
   can disqualify a candidate.
10. **Implementation slices.** Prefer independently testable stages and keep
    physical backends behind pure interfaces until their evidence exists.
11. **Validation matrix.** Map each requirement and cut/failure point to an
    executable test, model, measurement, or deliberately open gate.
12. **Review and convergence gates.** State when the artifact freezes, which
    reviews are required, what blocks the next stage, and what gets banked.
    Include a closed, ordered Phase-D completion checklist. Mark each evidence
    item as mandatory for the requested stage, reusable unchanged evidence, or
    a later production/hardware gate; only the first category may delay that
    stage.
13. **Preservation and rollback.** Protect existing work, define the commit or
    branch strategy, and explain how a failed experiment is removed cleanly.

Plans may be concise. Completeness means every applicable question is answered,
not that every plan becomes a large specification.

## 4. Explore, decide, implement, and land

### Phase A — baseline and exploration

- Freeze or record the starting tree before parallel work.
- Read the source, tests, errata, and prior findings before proposing new
  mechanisms.
- Generate competing hypotheses and attack the assumptions behind them.
- Use disposable host models, deletion experiments, protocol sketches, or
  resource spikes when prose cannot decide the question.
- Mark every conclusion with its evidence level and every unanswered question
  as open.

Exploration may be broad and may discover new requirements. Exploratory code is
not production authority and should not be shared with immutable production
paths unless it passes the implementation process independently.

### Phase B — candidate selection and plan freeze

- Select the smallest candidate that satisfies the current named requirements.
- Explain why each non-obvious mechanism is retained.
- Record rejected alternatives and the evidence that rejected them.
- Record the selected plan, repository identity, tests already executed, and
  open gates. Do not build a separate review dossier.
- For security-sensitive work that establishes or changes signing authority,
  fallback policy, a trust boundary, persistent-state semantics, or an
  irreversible interface, obtain the required architecture review wave, then
  record the owner or authorized maintainer's stage decision before
  production-shared implementation.
- A maintainer may instead authorize a bounded Phase C implementation campaign
  under an already-selected authority and fail-closed contract. The plan must
  enumerate its slice IDs, cumulative compatibility/resource envelope, and
  Phase D stopping point. This permits implementation and testing, not merge or
  production claims, and it cannot be used to smuggle an unresolved product
  decision into code.

### Phase C — implementation and evidence

- Implement in reviewable slices; keep commits buildable and fail-closed.
- Keep one named product surface active. Record the included slice IDs and bank
  unrelated findings rather than switching campaigns mid-phase.
- Test behavior rather than source strings wherever behavior can be executed.
- Inject reset, torn-write, malformed-input, boundary, and fault cases wherever
  the threat model makes them relevant.
- Measure final combined artifacts rather than adding estimates from different
  worktrees or profiles.
- Preserve user changes and unrelated work; do not use broad cleanup or
  formatting as part of a security fix.
- Record exactly what was executed and what was only inspected.
- Do not launch an adversarial-review wave after each bounded slice.
  Accumulate relevant tests, generated artifacts, resource deltas, and residuals
  for the combined Phase D candidate.

The Phase C batch stops and returns to Phase B (or pauses for owner direction)
if a slice introduces any of the following outside the recorded campaign
envelope: new signing eligibility or downgrade/fallback authority; a new trust
boundary or host-controlled security fact; persistent-state or recovery
semantics; a wire/schema change requiring ecosystem migration rather than a
root-pinned compatible extension; an irreversible/external action; a failed
resource envelope; or another Section-5 expansion trigger. Ordinary root
rotation, compatible authenticated-IR extensions, additional fail-closed
  formatters, tests, and catalogue coverage may remain in the same batch when the
  plan explicitly allowed them.

### Phase D — frozen implementation review

- Stop all writers and freeze one exact candidate identity.
- Run the same required gates from a clean or isolated environment.
- Launch GPT-5.6 SOL, Claude Opus 5, and Kimi K3 simultaneously with the same short,
  clear-context prompt.
- Resolve findings, re-freeze, and apply the material/non-material re-review
  rule in Section 10.

Phase D is **closure mode**, not another exploration or implementation phase:

- Freeze the exact ordered checklist before launching reviewers. It contains
  only stage-relevant mandatory evidence, target identity, the required review
  legs, blocker remediation, re-review when required, landing, and the minimal
  owner-status/TODO receipt.
- Do not add a test campaign, reviewer, playbook campaign, formal-method track,
  documentation rewrite, or cleanup merely because it would improve assurance.
  Bank it unless it was already required for the requested verdict or a
  concrete Section-5 trigger makes it stage-blocking.
- Run focused tests while correcting findings and run the frozen combined gate
  set once on the candidate that will be reviewed. Do not repeatedly run the
  complete evidence matrix after every correction.
- Evidence is stage-fit. A merge review records absent production, hardware,
  factory, and destructive evidence as honest residuals unless the changed
  surface or a stricter gate specifically requires that evidence for merge.
  It does not collect shipment evidence merely because a playbook names it.
- Parallelize independent mandatory gates and the three reviewer commands.
  Keep only their raw outputs and a compact coordinator summary.
- Apply the Section-7 wall-clock and output caps to the single reviewer wave.
  At the deadline, accept the compact report or record that leg as unavailable;
  use only the focused completion path below for an unanswered mandatory check,
  rather than extending the active run into another campaign.
- If Phase D cannot progress on its recorded checklist, stop adding work and
  report the exact blocker, its evidence, and the shortest compliant route to
  either convergence or an owner decision.
- Every new checklist item needs a cited Section-5 trigger or stricter owner
  gate and a statement of why it cannot be banked. Without that receipt, the
  next action must come from the existing checklist.

The Phase D target is the combined Phase C candidate. The three reviewers inspect
that composed diff and affected callers. Full catalog-by-catalog reconciliation
is deferred unless a task-specific gate explicitly requires it for the current
stage. Before landing, add one owner-triggered TODO naming the primary and
intersecting playbooks to run later as a single lock-in campaign. A concrete
unsafe trace, stricter required command, or failed resource envelope remains a
current blocker and cannot be deferred under this rule.

That deferral survives handoff and session restart. A future session that reads
the TODO leaves the sweep deferred unless the owner selects it as the active
surface; intersection alone is not a reason to interrupt other product work.

### Phase E — landing and handoff

- Bind `GO` to the stage named in the prompt. A merge `GO` is not a production
  shipment decision and never performs or authorizes the action by itself.
- Land all load-bearing tracked and untracked inputs atomically.
- Re-run the identity and drift checks immediately before staging and after
  landing.
- Put reversible residual work on the GitHub issue tracker
  (`EthereumPhone/PQ1`, labels `source:work-todo` / `priority:*` /
  `surface:*`); put irreversible factory/silicon work in issues labelled
  `source:production-todo` (+ `ship-blocker` when it gates shipping). Both
  TODO files were retired 2026-07-19; originals are archived under
  `docs/archive/`.
- Record the evidence receipt and the exact remaining blockers.

## 5. Requirements and scope may expand

Reviewers are explicitly authorized to question the architecture, propose
deletions, explore stronger defenses, and surface missing requirements. Do not
prompt them to stay inside a possibly-wrong design merely to preserve schedule
or sunk cost.

A proposed expansion becomes a **candidate** when at least one of these applies:

- a concrete unsafe trace, exploit, counterexample, or reproducible failure;
- a named invariant or threat is uncovered or violated;
- verified silicon, errata, protocol, or deployment evidence invalidates an
  assumption;
- a requirement is unimplementable as written;
- measured FLASH, RAM, stack, timing, endurance, or power fails its envelope;
- a frozen interface, compatibility, migration, or recovery constraint requires
  it;
- the owner explicitly adds a product or assurance requirement.

Except for an explicit owner-added requirement, a candidate expansion enters
the accepted plan only after its trigger is independently substantiated at the
applicable evidence level and adjudicated. Destructive E6/E7 evidence is never
repeated merely to satisfy this sentence; it requires the separate authority
in Section 11. For security-sensitive work, substantiation includes coordinator
reproduction against source or executable evidence; a single reviewer's
unsupported trace or factual assertion is not enough.

For an expansion, record:

1. the trigger and evidence;
2. the smallest remedy and at least one deletion/simplification alternative;
3. the added trusted-computing-base, state, resource, test, and review cost;
4. which prior review recommendations and digests are invalidated;
5. whether new authority or an owner choice is required.

Ideas without one of these triggers are not discarded. Classify them as
optional hardening, research, or future product work and bank them. This is the
YAGNI boundary: it prevents speculative accretion while leaving the models free
to discover something important.

Material expansion beyond the user's authorized outcome, or any new
irreversible/external action, pauses implementation for owner approval. A new
security requirement within the existing outcome may be investigated safely
and presented with evidence before that decision.

## 6. Evidence and authority ladder

| Level | Evidence | What it can establish |
|---|---|---|
| E0 | Source reading, grep, design reasoning | Candidate mechanisms and questions; no execution claim |
| E1 | Unit tests, host models, property tests | Pure-logic behavior under the modeled assumptions |
| E2 | Fuzzing, mutation, formal/symbolic checks | Properties covered by the exact harness/model and bounds |
| E3 | Target link, binary inspection, FLASH/static-RAM/stack receipts | Properties of the exact build/profile measured |
| E4 | QEMU or emulator end-to-end | Integration behavior within the emulator model |
| E5 | Non-destructive target-silicon tests | Observed behavior on named hardware without irreversible mutation |
| E6 | Owner-authorized destructive/sacrificial tests | Observed irreversible behavior for the named parts, revisions, and procedure |
| E7 | Factory/release evidence | Production ceremony, custody, reproducibility, and shipment gates |

Higher levels do not automatically subsume different lower-level properties.
For example, a silicon smoke test does not replace a parser property test.
Reports must name the exact level actually reached.

## 7. Required fast adversarial-review wave

For security-sensitive architecture and implementation, launch exactly these
three reviewers **simultaneously in fresh contexts**:

- literal **`gpt-5.6-sol`** with `model_reasoning_effort="ultra"`;
- Claude Code **Opus 5** (`opus`) with `xhigh` effort; and
- Kimi Code **Kimi K3** (`kimi-code/k3`) with the highest supported thinking
  effort.

Use the local `codex`, `claude`, and `kimi` CLIs. Give all three the same short
prompt, frozen target, baseline, stage, and bounded focus. Start a new session
for each review. Do not give them prior reports, other reviewers' conclusions,
status prose, playbook catalogs, or a dossier of claimed defenses. Do not add
extra coordinator-launched reviewer swarms. The goal is three independent
source reviews, not three orchestrated research projects.

The CLI command/event log is the runtime receipt. Record only reviewer/model,
target commit and tree, command or session identifier, completion status, and
raw report path. Separate pre-launch and post-launch receipt files, report
digests, terminal transcripts, and packet manifests are unnecessary unless a
stricter task-specific gate explicitly requires them.

If a reviewer cannot launch, retry that same reviewer once for a mechanical
failure. Do not silently substitute a model or serialize the other reviews while
waiting. An explicit owner-selected replacement or waiver takes precedence for
its stated scope; record it and preserve it across turns. If the leg remains
unavailable, report it honestly and apply the focused completion rules below
only where they permit another run.

### Review runtime bounds and report length

The initial three reviews form one parallel wave. Each reviewer gets **15 minutes
total** and should aim for **about 800 words**. Owner decision, 2026-10-26:
report length is a suggestion, not an acceptance gate. An overrun alone must
not invalidate a review, trigger another model run, block landing, or require
owner approval. Record the length, preserve the full report, and assess its
substance against the required checks. Runtime and raw-artifact byte limits
remain hard bounds. Do not extend a running leg, cross-review reports, or
rewrite a report. Focused follow-ups after the wave
finishes are governed below. Already-running mandatory tests are separate and
run once. Reviewers must reserve the final stretch for
synthesis: a partial compact report at the deadline beats a timed-out leg
(the first 8-minute wave lost an entire reviewer to a mid-exploration
timeout — the bound exists to stop campaign creep, not to price out the
slowest model).

At the deadline, the reviewer returns what it has with an honest `GAP`, or the
coordinator records the leg as timed out. A timeout never causes the other two
reviews to restart. A stricter task-specific owner gate may require more, but it
must say so before the target freezes.

### Focused completion of mandatory gaps

Owner decisions, 2026-10-26 and 2026-10-27: a completed `GAP` or a substantive
timeout may receive focused follow-ups to finish explicitly unanswered mandatory
checks. Additional bounded runs within the authorized task may proceed
autonomously; completing one follow-up does not create a new approval requirement.
Keep these runs proportionate to the remaining work and apply the progress and
stopping rules below. Mechanical launch retries remain a separate case.

- First collect the initial reports and identify the missing checks. Keep the
  candidate commit/tree, stage, technical requirements, and acceptance gates
  fixed. A disagreement, optional assurance, or an undesired verdict is not a
  missing check.
- Start with one completion wave per frozen candidate, involving only
  the incomplete legs. Run independent legs concurrently. Each gets a fresh
  context, at most **15 minutes**, and a suggested **800-word** report. Do not restart
  successful legs or rerun unchanged tests merely to accompany the follow-up.
- Use the same reviewer unless the owner explicitly selects a replacement.
  Resolve the requested model exactly; do not silently substitute or enable
  fallback. A new model's scoped report does not make the original leg complete.
- Give the reviewer the frozen identity, the neutral unanswered checks, and
  the primary sources needed to answer them. Exclude prior reports and verdicts;
  do not ask it to agree with another model. Preserve the original report and
  record the follow-up's model, scope, result, and runtime separately.
- Reconcile the combined evidence against every original mandatory check.
  A scoped `GO` closes only its demonstrated coverage. Reproduce new concrete
  findings normally; material corrections still require Section-10 re-review.
  A gap never becomes a waiver merely because the follow-up ends.
- If mandatory checks remain unanswered, the coordinator may launch another
  focused run autonomously. Before each run, record the exact remaining check,
  what the previous attempt resolved, why this attempt can close the remainder,
  and its stopping point. Narrow the source set or correct the concrete context
  or tool problem; do not simply repeat an unchanged prompt.
- Authorize only the next useful run, not an open-ended series. Keep the same
  per-run time and artifact limits, reuse valid evidence, and run only incomplete
  legs. Stop autonomous reruns after two consecutive attempts leave the same
  mandatory gap unchanged, or when no concrete improvement to the next attempt
  is available. Report the remaining evidence and shortest decision path;
  do not seek a preferred verdict, waive the gap, or add optional reviewers.
  A run count alone is not a reason to request owner approval. Existing scope,
  reviewer-selection, risk-acceptance, and external-action boundaries still apply.

### One-wave execution

All three reviewers receive only:

- the exact target commit/tree and comparison baseline;
- the objective, requested stage, bounded product surface, and non-goals;
- a short list of the load-bearing invariants or remediation outcomes;
- a compact summary of tests/evidence already run; and
- the immutable-target instruction.

They inspect the exact diff and affected callers source-first. Prior reviews,
playbook/status claims, and other reviewer outputs are deliberately absent from
the initial context. Reviewers may run read-only commands and focused tests in
external build directories, but may not edit the canonical target, use
hardware, or perform external writes. Each raw response goes to a distinct path
outside the target.

### Coordinator triage; no cross-review

After the three parallel reports return, the coordinator:

1. deduplicates concrete findings;
2. reproduces every claimed blocker or high/major issue from source or a focused
   executable check;
3. treats unsupported suspicions as `NOTE`, not as blockers;
4. checks the task-relevant playbook and owner gates once; and
5. reports one compact decision and the shortest correction set.

There is no pairwise disclosure, cross-adjudication, second-opinion prompt, or
model-written matrix. Majority vote does not overrule a reproduced unsafe
trace. Conversely, one unsupported model assertion does not block landing. If
the coordinator cannot resolve a stage-impacting disagreement quickly from the
source/evidence, report it to the user as `UNRESOLVED` instead of launching more
reviewers.

## 7b. Deep review gear (owner-triggered only)

The fast wave above is the right instrument for bounded per-candidate diffs.
It is the wrong instrument where a shallow pass is itself the risk: actions
that cannot be undone, and large piles of un-adjudicated findings. For those,
run the **same three-reviewer pattern in deep gear** — identical discipline,
longer budget, whole-surface scope.

**Triggers (any one; the owner selects the surface):**

1. An irreversible or production-authority-bearing action, **before**
   execution: OTP/option-byte burns, SE lifecycle ratchets (the S-1/S-2
   class), factory-ceremony steps, rollback-floor writes, first-boot
   self-lock activation.
2. A backlog of un-adjudicated single-coordinator findings before bulk
   remediation: any unverified HIGH-severity candidate, or ten or more
   candidates on one surface (an SE-driver-style pile).
3. A pre-ship full-surface or full-project sweep.

**Shape (identical discipline to §7 unless stated otherwise):**

- The same three reviewers in fresh, mutually blind contexts with the same
  short prompt. A missing or timed-out leg is recorded, never substituted.
- Scope is a whole surface or artifact set, not one diff.
- Budget: up to one working session (~4 hours wall-clock) per leg; no
  response-word cap. Findings still lead with PoC-or-`suspicion,
  unverified` honesty.
- The coordinator reproduces every blocker/major claim from source or a
  focused executable check before it is accepted; unsupported suspicions
  remain `NOTE`s; disagreement that cannot be resolved from evidence is
  reported `UNRESOLVED`, never voted away.
- **No** pairwise disclosure, no cross-adjudication matrix, no digest
  ceremony, no standing use: deep gear fires on these triggers only.

**Output:** tracker issues created or updated (each candidate carrying its
PoC-or-suspicion label), one compact coordinator decision, and the usual
runtime receipt (reviewer/model, target identity, session identifier,
completion status, raw report path). A deep-gear verdict on an irreversible
action is a recommendation; the owner authorizes the action itself.

## 8. Minimal review context and output

Do not build a review packet. The shared prompt contains the target and baseline
identities, objective/stage, bounded focus, at most seven short invariants or
acceptance checks, and a one-paragraph evidence summary. Link source-of-truth
documents only when the reviewer must read them to decide the requested stage.
Production/hardware residuals are named once; they do not trigger work for a
merge-only review.

Every reviewer returns this exact compact shape:

```text
VERDICT: GO | FIX | GAP
TARGET: <commit> / <tree>
FINDINGS:
- <BLOCKER|HIGH|MEDIUM> <file:line> — <mechanism>; <evidence>; <smallest fix>
GAPS: none | <one line>
```

Use at most three findings. Optional hardening is omitted or placed in at most
two `NOTE` lines after `GAPS`; it never changes `GO` without a concrete unsafe
trace. `FIX` requires a source anchor, mechanism, consequence, and falsifiable
evidence. `GAP` means the reviewer could not answer a mandatory question within
the bound. The coordinator, not the models, records the CLI/runtime facts and
the final synthesized decision.

Formal-verification work still follows any stricter mandatory command or
evidence requirement in
[`verification/fv-adversarial-review-playbook.md`](verification/fv-adversarial-review-playbook.md),
but its catalogs are not pasted into the three reviewer prompts.

A reviewer may recommend risk acceptance but may not set a finding to
`☑️ ACCEPTED`. That status is owner-only and requires a recorded owner decision
naming the owner, date, exact finding and target/report digests, accepted
consequence, and scope. Ordinary implementation/merge authority delegated to a
maintainer does not include security-risk acceptance. Model consensus is not
acceptance authority.

## 9. Reviewer recommendation meanings

The prompt names exactly one stage—normally architecture, merge, or shipment.
The compact verdict applies only to that stage and exact target:

- **`GO`:** no concrete stage-blocking defect was found and no mandatory answer
  is missing.
- **`FIX`:** one or more concrete findings require correction before that stage.
- **`GAP`:** identity, evidence, or a mandatory question could not be resolved
  within the time bound.

A model never authorizes implementation, merge, shipment, hardware mutation,
risk acceptance, or an external write. An authorized owner/maintainer acts on
the synthesized evidence. A merge `GO` is never a production-shipment verdict.

## 10. Convergence and stopping discipline

The default convergence loop is:

1. implement and test the bounded Phase-C slices;
2. freeze one exact candidate;
3. run the one parallel three-reviewer wave;
4. reproduce and fix only concrete blockers or mandatory gaps as one batch;
   use Section 7's focused completion path for an unanswered check on an
   unchanged candidate;
5. re-freeze and, if code/behavior changed, run the same short wave once more;
6. land when gates are green and coordinator triage has no reproduced blocker
   or unresolved mandatory gap.

A change is **material** when it affects an authority rule, state transition,
byte/schema format, trust boundary, failure response, resource envelope,
security claim, or the substance of a blocker. A material change invalidates the
old verdict and receives a fresh three-reviewer wave on the combined corrected
snapshot. It does not require review after each intermediate commit.

That re-review rule applies once a snapshot has entered Phase D or carries a
review recommendation. It does not require a full review after every material
commit made inside the initial authorized Phase C batch. Likewise, when a Phase
D review produces several material corrections, implement and test the related
corrections as one bounded remediation batch, then freeze and review their
combined result once. No prior recommendation transfers to the changed digest
during that interval, and no merge/production claim is available until the
next Phase D review converges.

For a remediation snapshot that stays inside the original authority, trust
boundaries, compatibility envelope, and product surface, the prompt may include
a short acceptance list for the prior blockers and changed callers. It still
does not include prior reports or catalog prose. A new authority, fallback,
persistent state, incompatible wire change, or Section-5 trigger returns to
Phase B before review.

A **non-material** change is limited to editorial correction, link/receipt
repair, or a mechanically equivalent test/document update that changes no
authority, behavior, evidence claim, or acceptance gate. The coordinator may
classify it directly; if uncertain, include it in the next combined freeze.

Do not start cross-review or recursively ask models to debate. If the second
wave still has a reproduced blocker, fix it in the active product scope. Apply
Section 7's bounded completion path to an unanswered mandatory check. For an
unresolved disagreement, unavailable leg without authorized replacement, or a
gap that reaches Section 7's progress-based stopping condition, give the user
the exact evidence and shortest decision path. Otherwise continue the focused
completion autonomously under Section 7; do not introduce a per-run approval
step merely because an earlier completion has already run.
Bank editorial preferences, duplicate defenses, and optional hardening.

Do not declare convergence merely because review is expensive. Conversely, do
not reopen an accepted architecture merely because a reviewer can imagine an
additional defense. The deciding question is whether new evidence changes a
requirement, invalidates an assumption, or makes the selected design unsafe or
unimplementable.

No recommendation transfers across a changed artifact. Every wave binds its
conclusion to the exact reviewed commit and tree.

## 11. Irreversible and external actions

No plan or model review authorizes destructive hardware or an external
deployment. Before OTP, option-byte, RDP/WRP, SE lifecycle, credential, factory,
or production-release mutation, obtain an explicit owner instruction naming:

- the exact board/part and revision or external target;
- the cells, objects, keys, lifecycle states, or deployment affected;
- the exact artifact, source, toolchain, ceremony/procedure, and three-reviewer
  wave result being authorized;
- the named operator, authorization window, and exact single attempt covered;
- the pre-state capture and recovery limits;
- the expected irreversible result and stop conditions;
- the evidence that the non-destructive prerequisites passed.

Absence of authorization is a hard stop, not an assumption to fill in. The
authorization is consumed when the first irreversible command may have
launched, including a timeout, reset, error, or partial execution. It cannot be
replayed for a retry, replacement part, broader cell/object range, changed
artifact, changed procedure, or later window; each requires fresh owner
authorization.

## 12. Reusable quick reviewer prompt

Use this same short prompt for all three fresh sessions. Replace only the model,
paths, identities, stage, and bounded focus.

```text
Review PQSigner OS for <STAGE>.
Target: <PATH>, commit <COMMIT>, tree <TREE>.
Compare: <BASE>..<COMMIT>.
Focus only on <PRODUCT SURFACE>: <AT MOST SEVEN SHORT CHECKS>.
Evidence already green: <ONE SHORT PARAGRAPH>.

Inspect the diff and affected callers source-first for concrete security or
correctness blockers. Keep the target immutable. Use read-only commands only;
no edits, hardware, external writes, prior reports, status prose, or playbook
catalogs. Ignore style and optional hardening. You have 15 minutes. Aim for
about 800 words; report length is advisory.

Return exactly:
VERDICT: GO | FIX | GAP
TARGET: <commit> / <tree>
FINDINGS:
- <BLOCKER|HIGH|MEDIUM> <file:line> — <mechanism>; <evidence>; <smallest fix>
GAPS: none | <one line>
```
