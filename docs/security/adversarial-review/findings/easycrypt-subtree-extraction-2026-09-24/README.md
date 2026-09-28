# Linked subtree extraction in the actual C10 byte game

Source-merge receipt for `7e099a632794c633ed14a9dc7a6e1bb0a3274f29`, tree `ff6778bb8f7adb6b42ef78766b19c62640d735c5`, based on
`451594d4dda89054cb38ab87e6c2d504c8bcefd2`. The later receipt commit changes no proof or gate input.

Successful complete byte-game verification now records linked actual WOTS/Merkle recovery layers. Outside the existing public collision/zero events it yields either an unrecorded top-message root or paired WOTS openings in both layers. Actual successful signing records the lower root used as its top message. The byte-game theorem binds the message hash, supplied signature components, original public seed/root and final new-message guard. The same initialized-game hop retains its successful-forgery residual and unchanged charges. The forest value remains existential; neither case receives a numerical charge, and FORS/adaptive/private/encoding obligations remain open.

## Validation

- [Full cold replay](full-gate.log): `403` direct targets,
  `403` default-CLI targets and `325` controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget change. Exit 0 in 17260.11 seconds.
- Started 2026-09-24T16:37:01.344886+00:00; finished 2026-09-24T21:24:41.459200+00:00.
  Input identity `7d32af4a46730ea4aa82d37d99387b52` stayed unchanged across the run.
- `2835` pins, `2467` statements, `153` roots,
  `2117` census rows and `367` manual source bindings.
  No new project axiom, admit or unrealized clone assumption.
- All `20` repository-only focused proof-driver checks and
  `21` new controls match the enrolled sources and expected reasons.
  Eleven checker regression groups, static contract and source binding pass.
- [Opus](opus-report.txt) returned GO. [Astra](astra-report.txt) reported GAP
  solely because the required cold replay was still pending; both reported no
  source-level findings. The [coordinator record](review-summary.json) resolves
  that exact evidence gap with this unchanged-source replay and preserves both
  raw verdicts and runtime/model evidence. Standing owner instructions replace
  SOL with Astra and omit Kimi. No source change or additional reviewer turn
  was required.
- The [hosted CI record](hosted-ci-triage.json) separately identifies any
  unchanged baseline failures. A local proof-gate result is not an overall
  green-CI claim.

These are classical manual-model statements. Rust/model fixture agreement
is tested correspondence, not extraction. No concrete SHA-256 theorem, QROM,
96-bit deployed security or hardware/production authority is claimed.
Adaptive opening coverage and component forgery reduction remain under
#100/#295; #509 stays an owner-triggered deferred combined playbook pass.

## Control and identity evidence

The 21 new controls comprise seven positives, six scope probes and eight
rejected exact theorem applications. All matched their original declared
outcomes and reasons. Rejection establishes no falsity, necessity or tightness.
The additional positive proves root persistence under history extension; these
checks are not complete-game nonvacuity evidence.

The preflight command rejected the old input identity after deliberate
enrollment. Its checker, source-binding and static stages passed. The identity
was explicitly updated in the candidate; the separate identity check and
full frozen cold replay pass at the new value.

Observed host timing gaps are retained in [the timing record](host-clock-gaps.json). Both bounded reviews completed before those gaps. The completed replay duration above includes wall-clock elapsed time and stayed within its original 18,000-second limit; no review was restarted and no budget was extended.
