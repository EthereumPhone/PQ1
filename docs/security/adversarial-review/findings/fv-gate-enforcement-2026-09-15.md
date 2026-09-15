# FV CI gate enforcement — #663 / #664

Active surface: formal-verification CI gate enforcement. Phase B/C resumes the
existing working-tree fixes under the current fail-closed assurance contract.
Base is `9762ea7c41de15b86191184bb2c2baa0caf68e58`, branch
`feat/pq1-board-target`; the isolated candidate preserves all 113 earlier work
items. Sources of truth are CLAUDE.md, STATUS.md's FV owner links, the planning
workflow, the FV playbook's G1 gate, and issues #663/#664 (including their
2026-08-20 working-tree receipts). The source wiring check is not a hosted
branch-protection or actual proof-execution receipt.

Three bounded slices: (1) retain the current invocation/nightly checks and add
exact parsed step/runner/context contracts for every blocking gate; (2) retain
the existing 30 registrations and EasyCrypt pin workflow wiring, pin gate
identities/enforcement levels independently in the checker, and register the
checker itself instead of waiving it; (3) executable controls for skipped,
printed, masked, similarly named, removed and demoted invocations, followed by
one combined review boundary. The two production quarantine steps retain their
existing expected-failure semantics under exact step pins. Proof and firmware
behavior, other uncommitted workflow jobs, Kani repair, hosted settings and the
broader #509 assurance pass remain outside this batch.

Coordinator controls found that the current uncommitted checker accepts
`echo make miri`, `make miri-extra`, and `if false; then make miri; fi` as
blocking invocation evidence. Its dated-text demotion rule does not pin the
registration or enforcement level, and its self-registration waiver leaves
that check outside the manifest. These are concrete instances of #663/#664,
not a new product surface. Reusing existing exact-step contracts is selected
over expanding a partial shell parser: it also covers the existing deliberate
failure wrappers without pretending to interpret arbitrary shell programs.
The independent policy catches manifest-only deletion/demotion; changes to
checker policy and workflow contracts remain reviewed source changes.

Mandatory evidence: checker self-test, focused executable workflow/manifest
regressions, `make verify-gate-enforcement`, the newly wired toolchain-free
`verify-easycrypt-pins` target, and actionlint on the affected workflow.
The resource envelope is host Python/YAML plus the existing pin checker; no
firmware bytes, persistent schema, toolchain upgrade or external runtime action
changes. Landing is a scoped commit/push and tracker closure after convergence;
no hardware/deployment action is authorized. Failed experiments live only in
the isolated candidate; unrelated bytes and overlapping manifest edits are
preserved during integration.

Phase D checklist: finish those three slices and mandatory checks, freeze one
combined commit/tree, run the required simultaneous 15-minute/800-word
SOL/Opus/Kimi wave, reproduce concrete blocker claims locally, remediate and
re-freeze/re-review if material, then land the reviewed source and compact
receipts. Existing #509 retains the single deferred combined FV / production
configuration / build-provenance assurance pass. No extra review campaign or
proof discharge is added.

## Combined implementation and evidence

All 37 blocking gates now carry complete parsed invocation-step contracts,
including runner and job-control exclusions plus the existing workflow-level
environment (or its absence). All 64 registrations have independent identity/
enforcement pins in the checker, including its own CI step. The 30 existing
working-tree registrations and EasyCrypt pin-check wiring are included; the
unrelated Kani mutation update and other CI jobs are not included. Exact target
boundaries also distinguish `kani` from `verify-kani-mutation` and similarly
named targets. Local reason references are documented as metadata hygiene, not
review authorization.

`make verify-gate-enforcement` passes its existing self-test, ten new executable
regression groups (213 real checker invocations on disposable workflow/manifest
copies), and the complete 64-gate source wiring check. The controls include every
registration deletion, every blocking demotion/context removal/printed command,
both blocking tiers' shell suppression forms, workflow/job/step controls, and
the checker's own CI step. `verify-easycrypt-pins` passes its negative controls
and exact eight-axiom pin ledger; its two existing admitted orphan-file pins
remain and no EasyCrypt proof compilation is claimed. `actionlint` passes on
the affected Lean workflow. A subsequent comment/error-text correction changes
no test or enforcement behavior.

The next boundary is Phase D on this combined candidate. These are local
source-wiring and control results, not proof-engine, hosted CI, hardware or
shipment evidence. The checker, reviewed manifest contracts and prior setup
steps remain trusted source; exact invocation pins do not interpret arbitrary
shell code or validate third-party action implementations.

## First review and combined correction

The first wave reviewed commit `711080e35f13ef7d764d377eba7951be5c51d3ec`,
tree `9d224a17e50da55d26e3723d5794b7b08d220854`, against the base above.
Opus returned GO (611.668 seconds), Kimi GO (419.410 seconds), and SOL FIX
(556.857 seconds). SOL required its one mechanical retry after every source
command failed at nested Bubblewrap namespace creation; the outer immutable
mounts remained in force. Raw reports and launcher receipts are adjacent.
There was no provider policy refusal or target drift.

Coordinator reproduction confirmed three corrections: a push-only or
closed-only workflow could pass as per-PR enforcement; the protocol nightly
row claimed CryptoVerif although CI selects only ProVerif/Tamarin; and the
EasyCrypt pin row omitted both Python helpers. The combined remedy requires
pull_request with the default opened/synchronize/reopened activity coverage,
splits CryptoVerif into an explicit local-only wrapper/registration, and
independently checks the EasyCrypt helper/control path closure. Removing the
false CryptoVerif claim alone would lose completeness, so the small wrapper
preserves explicit local coverage without claiming a computational proof run.
The additions are static policy metadata, one Make wrapper and focused fixture
controls; they add no firmware state, protocol change, new runtime authority
or tool dependency. These changes invalidate first-wave recommendations and
require a fresh wave on their combined snapshot. The original path-coverage
self-test now retains the actual invocation context and requires the intended
coverage diagnostic, avoiding an unrelated early failure.

All 65 registrations (37 blocking, 28 local) now pass. Final validation:
`make verify-gate-enforcement` passed the self-test, 13 regression groups in
55.727 seconds and the full manifest check; EasyCrypt pin negative controls and
the eight-axiom pin ledger passed; actionlint and diff whitespace checks passed.
The CryptoVerif wrapper was checked with make -n, not a fresh tool execution.
Opus's separate observation about future kani-*/miri-* target-family discovery
is optional scope expansion: existing registrations are independently pinned.
It remains deferred with #509, alongside setup/action/tool custody and hosted
settings assurance; no broader sweep is activated here. The next boundary is
the mandatory corrected-snapshot review, then scoped landing if it converges.

## Second review and coverage correction

The second wave reviewed `5f4b68de3b4dca96b9c7e6244cf576a009a3c916`, tree
`82387d2164e82217aeb9152e4b7ced427e79d583`, against the same base. Opus returned
FIX (421.029 seconds), Kimi GO (549.791 seconds), and SOL FIX (695.700 seconds).
All reports were within 800 words with matching identity and no target drift.
SOL again required its single mechanical nested-namespace retry (first attempt
56.625 seconds); its read-only source checks ran, but temporary-write-dependent
tests were unavailable inside that sandbox. The coordinator and Kimi had run
the full suite. Kimi added supporting prose around the requested verdict fields;
its complete raw response is retained without rewriting.

Two findings were reproduced locally. Removing the EasyCrypt model directory
from both manifest and workflow left the whole checker green. The reported Miri
child ignore for nsc/mod.rs fooled its individual check but was caught by the
two production rows; the neighboring existing nsc/ns_ptr.rs file reproduced the
whole-checker false green. Both corrected YAML fixtures pass actionlint. During
this reproduction the fixture serializer was corrected to retain the literal
GitHub `on` key instead of emitting PyYAML's internal boolean key.

The related allowlist control also accepted replacing easycrypt/** with either
a literal directory or easycrypt/*, with actionlint and the whole checker green.
GitHub's documented whole-path and slash semantics make these inadequate for
recursive coverage. This is a concrete correction to the same coverage
invariant, not an optional new campaign. The matcher now proves only equal
patterns, the catch-all, recursive literal roots, and literal suffixes beneath
**/; other inclusions fail conservatively. The Kani reverse check uses that
same matcher for its existing crate inventory. EasyCrypt's required reverse
closure now includes the model directory itself. All nonempty paths-ignore
filters are rejected for per-PR blocking gates; current blocking workflows use
none. Removing denylist support avoids adding an arbitrary glob-intersection
engine and leaves no new dependency or runtime authority. The cost is rejecting
future disjoint denylists until separately designed and reviewed. The broader
#509 assurance scope remains deferred.

These behavior corrections invalidate the second-wave recommendations. They
form one combined remediation inside #663/#664, followed by the required
fresh review boundary. Raw reports, focused reproductions and gate output are
adjacent. The authoritative GitHub pattern reference is
https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#filter-pattern-cheat-sheet.

The corrected coverage batch passes all 15 regression groups in 73.792 seconds,
the checker self-test and all 65 registrations. Actionlint and diff whitespace
checks pass. The previously green EasyCrypt pin result still applies to its
unchanged checker/model inputs; no proof execution is claimed.

## Third review and trigger correction

The third wave reviewed `31a219f71b28f3f39b83715931d9fb2c4c93e332`, tree
`f50fda40b8a39f68a302022beb1a5df4b7b36cb1`, against the same base. Opus returned
GO (408.504 seconds), Kimi GO (185.359 seconds), and SOL FIX (743.689 seconds).
Identity, immutability and output bounds passed; SOL used its one documented
mechanical namespace retry. Raw responses are preserved despite extra supporting
prose from Opus/Kimi. The coordinator treats Opus's explicitly nonblocking
future-family discovery observation as NOTE even though it was placed in
FINDINGS. SOL's first-goal-only discovery observation was reproduced too, but
identifies no missing live registration; all 65 present identities are pinned.
Both future-discovery limitations belong to the already-deferred #509 pass.

Two enforcement defects remain blockers. A changed annual cron passes both the
whole checker and actionlint; an empty schedule passes the checker but actionlint
rejects it. Per-PR branches-ignore master+ and branches maste? pass both tools
while GitHub's repetition/optional-character semantics suppress master coverage.
The branch-pattern discrepancy is supported by GitHub's filter reference above.
These are reproduced failures of the existing trigger invariant within #663,
so they cannot be banked with the optional discovery work.

The smallest combined correction pins the existing parsed schedules by workflow
and restricts branch patterns to the supported literal/star subset. Exact pins
retain the two daily schedules and the explicitly documented weekly advisory
proxy observation; they do not silently promote that observation to daily or
blocking drift detection. Rejecting unsupported branch operators and requiring
reviewed cadence edits avoids a cron evaluator or full GitHub glob engine.
No dependency, new source inventory, persistent state or runtime authority is
added. The previous recommendations are invalidated by this correction; the
next boundary is the same required short three-reviewer wave on the combined
snapshot after its focused gates pass.

Final trigger-correction evidence: all 17 executable regression groups pass in
69.742 seconds, plus the self-test and complete 65-gate source check. The branch
subset is explicitly ASCII letters/digits, underscore, dot, slash, hyphen and
star; unfamiliar syntax fails rather than receiving guessed semantics. These
changes affect only the checker and its tests. Actionlint and diff whitespace
checks pass; unchanged EasyCrypt pin inputs retain their prior green receipt.

## Fourth review and event-shape correction

The fourth wave reviewed `9200e83d199dfa6a43423de67cbd0cc33326a693`, tree
`38ceabb2dff6ce00b115c900d91222834c2b642b`, against the same base. Opus returned
FIX (318.818 seconds), Kimi GO (517.159 seconds), and SOL FIX (644.790 seconds).
All reports passed the identity/output/runtime bounds with no target drift.
The initial SOL launch (130.083 seconds) could obtain Git status metadata, but
all source-reading commands failed at nested namespace creation. This distinction
is recorded in the mechanical retry receipt; its single retry retained the same
reviewer/prompt and immutable mounts. No policy refusal occurred.

The remaining branch case is the zero-directory **/ form. Local full-checker
fixtures with branches-ignore **/master and **/** pass, as does actionlint.
Their applicability to branch matching is inferred from GitHub's shared filter
reference and documented zero-directory path behavior; no hosted trigger
experiment was run. The safe bounded correction removes slash from the supported
branch-pattern subset. All actual branch filters are literal master, so this
removes uncertain syntax without changing the workflows or adding a glob engine.

SOL also found that present scalar/list push or pull_request values were coerced
to empty mappings. The coordinator reproduced false, true, empty-list and list
payloads leaving the entire checker green while actionlint rejects them. Those
known event payloads now require null or a mapping, and event-name lists require
nonempty strings. Regression fixtures normalize PyYAML's on key before applying
mutations so whole-event changes are not overwritten by serialization cleanup.
This is validation of the supported trigger shapes, not a complete replacement
for GitHub's workflow schema validator. Both corrections remain within #663's
trigger-enforcement invariant and invalidate the prior recommendations; they
require the same combined review boundary after their focused gates pass.

Final guard-correction evidence: all 18 regression groups pass in 76.303
seconds, plus the checker self-test and all 65 registrations. Actionlint and
diff whitespace checks pass. The source edit is limited to the checker and
its tests; unchanged EasyCrypt pin inputs retain their prior green receipt.

## Convergence and landing boundary

Final reviewed commit: `c6c9f004a911049eb11fd50ce3f06b92a24d4536`; tree
`c4d7d801797a806607f77280dac5c8a81166a6f1`; comparison base remains
`9762ea7c41de15b86191184bb2c2baa0caf68e58`. SOL, Opus and Kimi all returned
GO with no findings or mandatory gaps. Durations were 699.543, 421.119 and
433.138 seconds; report lengths were 10, 386 and 399 words respectively.
The single mechanical SOL attempt consumed 88.167 seconds before its retry;
all identities, raw artifact hashes and immutability receipts validate.

Coordinator decision: GO for the scoped merge. All 18 executable regression
groups, the self-test, 65-gate source check, EasyCrypt pin controls and actionlint
are green. SOL could not create temporary test fixtures in its read-only sandbox;
the coordinator and Kimi completed those tests. SOL also read baseline STATUS
prose despite the prompt exclusion. Runtime inspection found no archived
candidate verdicts or other-reviewer report contents in its command outputs;
this procedural deviation is retained honestly, not described as perfect
context isolation. The shared initial prompts were byte-identical.

The optional discovery/setup/tool/hosted-settings observations remain deferred
under [#509](https://github.com/EthereumPhone/PQ1/issues/509#issuecomment-5683426902).
No further campaign or proof discharge is activated. These checks did not leave
a reproduced blocker on the selected source wiring; they did not validate all
GitHub schema forms, arbitrary shell/setup semantics, hosted branch protection,
proof execution, hardware or shipment.

The accepted receipt records the six reviewed source blobs. Landing may add
these final raw reports and integration receipts as nonmaterial evidence only;
source blobs must match the reviewed candidate exactly. The canonical manifest
keeps unrelated Kani/bytecode work unstaged, while the reviewed manifest blob
is staged for the scoped commit. All other original work must retain its bytes.

The canonical integration passes all 18 groups in 81.152 seconds, the self-test
and all 65 registrations with the pre-existing working-tree changes present.
All six staged source blobs match the reviewed candidate. All 110 unrelated
original items retain their exact bytes; the overlapping manifest keeps the
unrelated Kani and bytecode edits unstaged. Source and report-prose whitespace
checks pass. An unfiltered whitespace check flags 91 formatting instances only
inside byte-preserved raw evidence (terminal output and diff excerpts); those
records are intentionally retained without rewriting their contents/hashes.
