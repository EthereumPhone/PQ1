# Returned-coordinate forgery partition

Source-merge receipt for `d03db3d99bf1eb34b6e27ed32fa60c43bed66fed`, tree `703275ba24d5b610d494df3f9fbad928904d3d05`, based on
`75d7bdaaf3840edc8570b685ecd21591ababcff3`. The later receipt commit changes no proof or gate input.
The normal merge targets master `13769cfbdf30654a9b81aeafea4e6eca5ddad695`, whose intervening
contract-test and Foundry-version changes are outside this proof surface.
[Merge-input comparison](landing-base.json) verifies that all other files,
including all 402 bindings and every local replay input, remain byte-identical.
The raw reviews remain scoped to the frozen source identity above.

The existing initialized byte game's new-message forgery residual is refined
into new top/bottom WOTS component messages, a private FORS value at an
unreturned ordinary coordinate, or coverage assembled from prior responses.
All returned signatures retain their widths; covered ordinary values match
their exact private coordinates, and the thirteenth root-as-secret is treated
separately. Different trees may be covered by different previous responses.

The [proof boundary](../../../../../contracts/verification/easycrypt/c10-port/RAW-FORGERY-PARTITION.md)
keeps general information exposure and numerical private/chain/encoding charges
open under #100/#295. Unreturned coordinates do not imply unknown values. The
probability hop retains successful forgery and its unchanged existing charges.

## Validation

- [Full cold replay](full-gate.log): 438 direct targets,
  438 default-CLI targets and 411 controls pass. Pinned
  r2026.02 image, network disabled, read-only source and disposable cold copy.
  Exit 0 in 11843.59 active elapsed seconds, within the
  local 18,000-second active execution watchdog.
- Started 2026-09-29T13:36:09.331514+00:00; finished 2026-09-29T16:53:32.916993+00:00.
  Input identity `06793da6caf1b7efe0ff7b7691927981` stayed unchanged throughout.
  Wall elapsed: 11843.59 seconds; host suspension:
  0.00 seconds. Linux CLOCK_MONOTONIC excludes suspension;
  CLOCK_BOOTTIME records it separately. The [timing correction](timing-correction.json)
  replaces the coordinator's mistaken wall-time acceptance check on the local
  proof replay. The project's 900-second reviewer wall bounds remain unchanged.
  Two incomplete attempts were stopped after laptop pauses and are not counted
  as complete evidence. Their [first log](paused-q21-full-gate.log),
  [first result](paused-q21-full-gate-result.json), [overnight log](overnight-q21-full-gate.log)
  and [overnight result](overnight-q21-full-gate-result.json) are retained.
  The user confirmed overnight sleep; the [journal](overnight-suspend-journal.log)
  independently records it. These incomplete runs used the previous source.
  Their partial evidence and reviews do not authorize this
  combined candidate; it has its own fresh replay and bounded review wave.
- A subsequent [pre-integration replay](pre-integration-q21-full-gate.log)
  completed green on the previous source. During that run a Codex server restart
  interrupted only the outer result recorder; the original proof process
  continued. Its [recovery](pre-integration-q21-daemon-recovery.json) records
  the actual container exit through [docker wait](pre-integration-q21-recovered-container-wait.json);
  its host make exit was not directly observed. This is historical evidence,
  separate from the combined-source replay above.
- 3000 pins, 2599 statements, 181 roots,
  2155 census rows and 402 source bindings.
  All old statements and assumption rows are preserved; no new project axiom,
  admit or unrealized clone assumption.
- Eight modules passed 16 source-matched whole-file checks. All 25 new controls,
  eleven checker regression groups, static contract and source binding pass.
- The arithmetic correction in the existing `XmssmtCC_All.ec` also passed
  [both whole-file drivers](arithmetic-remediation-checks.json).
- Master advanced during the pre-integration full replay. The [integration correction](q21-integration-remediation.json)
  refreshes three Rust source hashes after upstream signing-progress callbacks.
  The stale binding was rejected before the deliberate refresh. Four transcript
  tests and two progress-correspondence tests pass, along with binding, identity,
  static contract and eleven checker regressions. All EasyCrypt proof and control
  bytes are unchanged. Callback side effects, panics, reentrancy and timing are
  outside this manual functional correspondence; finite fixtures are not refinement.
  The new source identity received the complete replay and fresh review above.
- Opus returned GO; Astra reported GAP solely for the then-pending combined-source full cold replay. Both found no source-level blocker across all seven focus areas, including the three refreshed Rust bindings. The coordinator resolved the exact pending-replay gap with the matching completed green replay; raw reviewer verdicts are preserved. Standing owner instructions replace SOL with Astra and omit
  Kimi. Raw [Astra](astra-report.txt), [Opus](opus-report.txt) and
  [coordinator](review-summary.json) records retain the exact findings and gaps.
- [Hosted CI](hosted-ci-triage.json) is separate from the local proof replay.
  A passing local gate does not imply overall green hosted CI.

## Controls and limits

Ten positive consumers/examples, eight scope probes and seven exact-statement
mismatches exercise the new surface. The mixed-coverage consumer is conditional;
it is not a constructed concrete counterexample. Rejected applications establish
their declared diagnostics, not premise necessity, theorem falsity, bound
necessity or complete-game nonvacuity. Scope checks remain name-level checks.

The deliberate enrollment changed the input identity. Preflight checker,
source-binding and static stages passed; the old identity was rejected, then
explicitly updated and verified before the frozen full replay. Two early
external controls lacked a direct import, were corrected and rechecked, and
their initial failures are preserved externally but not counted as evidence.

The initial full replay passed 438 direct targets but failed the default CLI
at `XmssmtCC_All.ec:3655`, proving a product nonnegative with an automatic
nonlinear step; that file reported 1,944 diagnostics in total. The
already-failed disposable run was stopped; its [log](initial-q21-full-gate.log)
and [result](initial-q21-full-gate-result.json) are retained. The correction
applies `mulr_ge0` explicitly and discharges each factor's nonnegativity,
preserving the theorem and assumptions. It received whole-file checks, a fresh
frozen review wave and the new complete replay above. Proof checks and solver
timeouts are unchanged. The local replay watchdog timing correction is recorded
above; the earlier review verdicts do not authorize the corrected tree.

Manual classical ideal-oracle model only. No Rust-extraction, concrete SHA-256,
QROM, closed numerical EUF or production/hardware authority. #509 stays deferred.
