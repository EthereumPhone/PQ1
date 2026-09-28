# Actual FORS extraction in the C10 byte game

Source-merge receipt for `4d3cb40d39604c910fb9a3d01e30d68ebf224412`, tree `19cda620e56604ee0c656633ab89905ac542f664`, based on
`bb44efb9d0f15123b0ba9ab0b9251cff6037d293`. The later receipt commit changes no proof or gate input.

The actual recovered forest is now tied to both verifier layers. With complete
references in the retained histories, conditional extraction identifies twelve
ordinary private leaf values and preserves the thirteenth tree-root-as-secret.
Actual successful signing creates those references and later permitted calls
preserve each reference. Missing-reference branches and the same initialized
byte game's successful-forgery residual remain explicit, with unchanged
probability charges. The [result boundary](../../../../../contracts/verification/easycrypt/c10-port/RAW-FOREST-EXTRACTION.md)
keeps adaptive exposures and numerical forgery charges open under #100/#295.

## Validation

- [Full cold replay](full-gate.log): 421 direct targets, 421 default-CLI targets
  and 359 controls pass. Pinned r2026.02 image, network disabled, read-only source
  and disposable cold proof copy. Exit 0 in 10252.58 seconds,
  within the original 18,000-second bound.
- Started 2026-09-24T22:11:45.719545+00:00; finished 2026-09-25T01:02:38.304382+00:00.
  Input identity `51b87d9274a86dbae3222f883482d61a` stayed unchanged throughout.
- 2911 pins, 2528 statements, 164 roots, 2132 census rows and 385 source bindings.
  All old statements and assumption rows are preserved; no new project axiom,
  admit or unrealized clone assumption.
- All 36 prototype whole-file proof checks passed; their bytes match the
  enrolled source, which also passed the full cold replay. The 34 new controls
  match their declared outcomes. Eleven checker regression groups, static
  contract and source binding pass.
- Opus returned GO; Astra reported GAP solely for the then-pending required cold replay. Both reported no source-level findings. The coordinator resolves that exact gap using the matching completed replay, preserving the raw verdicts.
  Standing owner instructions replace SOL with Astra and omit Kimi. The raw
  [Astra](astra-report.txt) and [Opus](opus-report.txt) reports and
  [coordinator record](review-summary.json) retain the exact evidence boundary.
- [Hosted CI](hosted-ci-triage.json) is recorded separately. A local proof-gate
  result is not an overall green-CI claim.

## Controls and identity

The 34 new controls comprise thirteen positives, eleven scope probes, nine
exact-statement mismatches and one unfinished width obligation. One positive
proves that fixed row count alone does not make forest compression injective;
another checks the special root's tree-12 semantics. Rejected proof attempts
establish only their declared diagnostics, not falsity, premise necessity or
tightness. These are not complete-game nonvacuity checks.

The preflight rejected the old input identity after deliberate enrollment;
its checker, source-binding and static stages passed. The identity was
explicitly updated, then passed its separate check and the full frozen replay.

These are manual classical ideal-oracle model statements. Fixture agreement
is tested correspondence, not Rust extraction. No concrete SHA-256 theorem,
QROM, numerical EUF guarantee or production/hardware authority is claimed.
The combined owner-triggered playbook pass #509 remains deferred.
