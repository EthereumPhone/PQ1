# Master integration — FV evidence fixes

Active surface: formal-verification evidence tooling. Phase C integration of
already-reviewed fixes onto master ab9e9049a5a8c8d088966d02b7ff9a5714ae678a.
Canonical dirty/untracked hashes are preserved in baseline.json. User explicitly
authorizes publishing these fixes to master, then research-limitation assessment.

Slices: prior FV/Verity/gate-contract prerequisites (ebb590d0,9762ea7c,43cf6208),
Kani mutation corrections, EasyCrypt gate reconciliation with master's 53-file
closure, and CI/context/count integration. Exclude all board/boot changes.
Preserve master's proof sources, statements, 49 polarity controls, six-headline
scope-probe bijection, exact margin/taint-control counts and assumption census.
No new crypto claim or production authority. #509's broad sweep stays deferred.

Mandatory checks: unchanged-prerequisite source/receipt comparison; relevant
FV script regression/drift checks; Kani census and runner controls; CI registration
and its regression controls; complete current 53-file split fast gate plus pinned
image controls/full replay. The full proof gate and one new simultaneous 900s /
800-word SOL ultra, Opus xhigh, Kimi max wave may run independently on the frozen
combined target. Reproduce only stage blockers, re-review material corrections.
Landing requires both green executable gates and reconciled review, fresh remote
master check, no force-push, preserved unrelated workspace, and a compact receipt.

Next boundary: combined Phase D after integration tests. Then publish to master
and stop this phase before examining the research frontier in Phase A. Research
assessment will use current master, not the older feature-branch limits. Any new
proof experiment stays disposable until independently tested/reviewed for promotion.

## Integration evidence before freeze

All earlier Lean, extracted, Verity, TLA and protocol proof project bytes match
the reviewed fix branch d168122e. Their recorded complete proof results remain
dated evidence; the integration also runs fresh relevant checker controls.
Every existing master EasyCrypt .ec/.eca source is unchanged. The combined
gate retains 53 files, 1,166 unique pins, 1,082 statements, 49 polarity controls,
15 taint controls, four taint-count controls, exact margin counts and six-file
headline/scope-probe linkage. The new helper also rejects noncanonical pin aliases.

Kani census and runner controls pass: 173/27 source census, 164/22 enrolled and
nine/five outside, 43 mutation groups. All 67 gate registrations pass. Static
EasyCrypt contract checks pass. New split input identity:
`e64e9594831f9b2df2ccdaeaf5f8c213`. A complete fresh pinned-image replay and the
combined bounded source review are still required before master publication.
The old 45-file green receipt is not a receipt for this newer proof artifact.

## Combined review correction

The first integration wave identified the absent documented heavy Kani mutation
entrypoint and the missing nightly protocol negative-control invocation. Both
are corrected, with an explicit local-only heavy registration and regression
controls. The EasyCrypt control helper also uses explicit failures so Python
optimization cannot remove result checks; this was not reachable through the
currently pinned container environment but is corrected in this same batch.
The proof sources and assumptions remain unchanged. Split identity is now
`ec0cec4a59a4eef2b6862c56f8475f09`; the interrupted `e64e9594831f9b2df2ccdaeaf5f8c213` replay is superseded, not green evidence.
The updated candidate requires the combined review and complete replay again.

## Earlier completion receipt — 2026-09-17 (superseded below)

Source commit `6bc23f2223aa820595be3bd6b04391bd7e5b6121`, tree
`4a5ec55d432c2f4d46a041c3d231c85502a7fca6`, compared with master
`ab9e9049a5a8c8d088966d02b7ff9a5714ae678a`. Source remained clean.

The [full pinned-image replay](fv-master-integration-2026-09-16/full-replay-v2.json)
exited 0: 53/53 direct compiles, 53/53 CLI runs, zero disagreements; all files
requirable; 1,166 unique pins and 1,082 statements; unchanged assumption census;
49 polarity/reason controls; 15 taint controls and four count controls; margin
guards 4/4 and negative controls 3/3. Final input identity stayed
`ec0cec4a59a4eef2b6862c56f8475f09`. The raw log ends GREEN. The run spans an
overnight host-clock advance, reported as wall time rather than active runtime.
The earlier interrupted replay is explicitly superseded and is not green evidence.

Fresh checker evidence: 22 gate regression groups and 68 registrations; seven
split-contract groups; 11 Kani census and eight runner groups; Verity CI with
fresh compiler/kernel replay (213 exported declarations, 208 kernel-rechecked,
one explicitly admitted declaration); TLC/protocol/proof-mutation checker
controls. No new full Kani campaign, heavy Kani BMC, full independent Lean
kernel campaign, hardware test or hosted-CI execution is claimed. Earlier full
proof-project receipts are reused only for the recorded identical source inputs.

The [corrected source review](fv-master-integration-2026-09-16/review-triage-v2.md)
returned Opus GO and Kimi GO. SOL's one permitted mechanical retry timed out
at 900 seconds without a report; its raw visible messages contain progress
updates, not a final verdict. This remains a mandatory missing leg. All legs
ended before the overnight host interruption. Opus's runtime identifies
`claude-opus-5` and also reports an auxiliary Haiku usage entry; no additional
coordinator reviewer was launched. Requested models, efforts, commands and
runtime/report hashes remain in the unchanged launcher manifests.

**Disposition: all required executable gates green; master publication pending
an explicit owner decision on the missing SOL review.** No owner risk acceptance
is inferred from the two GO reports. The workflow's second-wave stopping rule
applies; no extra review round is launched. The two non-blocking source notes
are banked in #688; integration closure is tracked in #687. The broader #509
assurance pass stays deferred. This receipt adds no source, proof assumption,
acceptance gate, firmware-equivalence claim or numerical security bound.

## Owner-selected Astra and final correction review — 2026-09-17

The owner explicitly selected **Astra instead of SOL**; this authorizes the
reviewer substitution, not acceptance of a missing review. Astra found two
checker defects, both reproduced: a Tamarin comment/attributed-lemma decoy and
an EasyCrypt declaration-name alias that hid a missing pin. Later required
reviews reproduced additional Tamarin lexical discrepancies. The final correction
pins complete model source bytes before formula extraction or prover invocation,
retains the separate formula/verdict inventories, and rejects noncanonical or
aliased EasyCrypt declaration identities. The general Tamarin lexical scanner
was removed. Models, EasyCrypt proof sources and assumptions remain unchanged.

Final reviewed source: `816db25c4d161544d2ba74b988efd50942167d0d`, tree
`050cafedbcb138388636551687710f67c69a9368`, on the same master base. The
[final review triage](fv-master-integration-2026-09-16/review-triage-v6.md) records
**Astra GO, Opus GO, Kimi GO**, no findings, no target drift, and all three
reports within the simultaneous 900-second / 800-word bounds. Each material
correction received a fresh blind review; historical FIX and timeout receipts
remain intact. No missing mandatory reviewer or unresolved source blocker remains.

The frozen final Tamarin checker passed all three models/eight lemmas. Its
self-tests pass with Python optimization 0, 1 and 2; nine negative assertion
controls fail for the intended reason. The EasyCrypt contract has nine passing
test groups, 53 files, 1,166 canonical unique pins and 1,082 statements. Gate
registration controls pass all 22 groups/68 registrations. Other unchanged
prerequisite evidence retains the scope and limits stated above.

The [source mapping](fv-master-integration-2026-09-16/final-source-mapping.json)
binds the full EasyCrypt replay at `eb18115e` to the final candidate: the only
subsequent changed file is `scripts/check_protocol_models.py`. All EasyCrypt
inputs, wrapper, Makefile and CI callers are byte-identical. The new split input
identity is `623ad0710d73000a1c693049b8933813`; the earlier `ec0cec4a…` replay is
historical and is not used to certify this identity.

The [full replay](fv-master-integration-2026-09-16/full-replay-v3.json) completed
**GREEN**, exit 0, at 2026-09-17 16:09:47 UTC (5,901.029 seconds wall time):
53 direct compiles, 53 CLI replays, zero disagreements, all files requirable,
1,166 unique pins, 1,082 statements, unchanged census, 49 proof controls,
15 taint controls, four taint-count controls, four margin guardrails and three
margin negative controls. Final input identity remained `623ad0710d73000a1c693049b8933813`.
Raw log SHA-256: `80efa33d6756f5bdc26e3c5ae00447686d2dd4fed36e09c572d1b7bcd2c7ed39`.

**Final disposition: GO for master integration.** All stage-required executable
gates and the three owner-selected reviews are complete; no reproduced blocker
or mandatory review gap remains. The existing owner instruction authorizes the
normal fast-forward push. The receipt-only publication delta changes no source,
proof assumption or acceptance gate. Remote master is rechecked before pushing;
the unrelated canonical workspace is preserved. #687 closes on verified landing.
#688, #509 and the separate research frontier #100 remain open. No full Kani/heavy
campaign, hosted-CI execution, hardware evidence or production authority is implied.
