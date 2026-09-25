# Accumulated adaptive signing-response accounting

Source-merge receipt for `5e477d33a3f335c339dae8b27d5fab40a08874a5`, tree `0d6504167c8d8c80ea1f1e95de7770c507047909`, based on
`09eaa56b9609b7d2031a575d361e25e22b51fbd2`. The later receipt commit changes no proof or gate input.

The passive private observer records every successful returned signature,
including repeats. Exact projection preserves the original initialized byte
game and its successful-forgery probability. All entries retain their actual
forest/subtree references through adaptive calls and final verification. The
message projection equals the original session list, and the response count
is at most the nonnegative signing cap. The existing final-new-message
extraction is connected to that exact list.

The [result boundary](../../../../../contracts/verification/easycrypt/c10-port/RAW-ADAPTIVE-EXPOSURES.md)
keeps general information exposure and numerical private/encoding charges open
under #100/#295. Literal returned values do not characterize all attacker
knowledge, and missing one reference does not imply secrecy.

## Validation

- [Full cold replay](full-gate.log): 430 direct targets, 430 default-CLI targets
  and 386 controls pass. Pinned r2026.02 image, network disabled, read-only source
  and disposable cold proof copy. Exit 0 in 10754.96 seconds,
  within the original 18,000-second bound.
- Started 2026-09-25T07:00:05.234517+00:00; finished 2026-09-25T09:59:20.197621+00:00.
  Input identity `ea9deb7a9681913681f0bc4a1ee80df4` stayed unchanged throughout.
- 2953 pins, 2564 statements, 173 roots, 2143 census rows and 394 source bindings.
  All old statements and assumption rows are preserved; no new project axiom,
  admit or unrealized clone assumption.
- Nine selected modules passed 18 whole-file checks; their bytes match the
  enrolled source, also covered by the full cold replay. All 27 new controls,
  eleven checker regression groups, static contract and source binding pass.
- Opus returned GO; Astra reported GAP solely for the then-pending full cold replay, with no source-level finding. The coordinator resolved that exact evidence gap with the matching completed green replay while preserving both raw verdicts.
  Standing owner instructions replace SOL with Astra and omit Kimi. The raw
  [Astra](astra-report.txt) and [Opus](opus-report.txt) reports and
  [coordinator record](review-summary.json) preserve their exact scope.
- [Hosted CI](hosted-ci-triage.json) is recorded separately. A local proof-gate
  result is not an overall green-CI claim.

## Controls and identity

The new controls comprise eleven positive applications/examples, nine scope
probes, six exact-statement mismatches and one unfinished nonnegative-cap
obligation. The positive examples preserve repeated messages, separate the
special tree-12 component and prove that failed/capped/invalid-message refusals
retain the log and count. Rejected applications establish only their declared
diagnostics, not premise necessity, theorem falsity, tightness or complete-game
nonvacuity.

The deliberate enrollment changed the input identity. All preflight checker,
source-binding and static stages passed; the old identity was rejected, then
explicitly updated and verified before the frozen full replay. Early external
control attempts with missing imports or inferred-type errors were corrected
and rechecked; their failures are preserved externally and not counted as
valid rejection evidence.

Manual classical ideal-oracle model only. Fixture agreement is tested
correspondence, not Rust extraction. No concrete SHA-256, QROM, closed numerical
EUF or production/hardware authority. #509 remains deferred.
