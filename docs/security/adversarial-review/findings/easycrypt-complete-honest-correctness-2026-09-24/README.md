# Complete actual honest-signature correctness

Source-merge receipt for `e405562e14fa3d656a3334b5c2959623ff5356ad`, tree `f26a20e6d71bc2e6254c7e649db0d278d8f691c2`, based on
`2bc048a29315ef2a72300a0717f7305511e9caae`. The later receipt commit changes no proof or gate input.

Actual WOTS, forest, hypertree layers, full signer and exact codec connect separate key generation to signing and later verification. Every returned encoding is 4008 valid bytes and verifies against the earlier top root. Termination is proved; bounded signing failure and the invalid-sum sentinel stay explicit. Physical-prefix transfer is outside this batch.

## Validation

- [Full cold replay](full-gate.log): `356` direct targets,
  `356` default-CLI targets and `225` controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget change. Exit 0 in 8735.98 seconds.
- Started 2026-09-24T00:22:42.866334+00:00; finished 2026-09-24T02:48:18.850160+00:00.
  Input identity `8094018baa5245a04bd5ab8bbc9fcc16` stayed unchanged across the run.
- `2672` pins, `2329` statements, `122` roots,
  `2079` census rows and `320` manual source bindings.
  No new project axiom, admit or unrealized clone assumption.
- All `180` repository-only focused proof-driver checks and
  `57` new controls match the enrolled sources and expected reasons.
  Eleven checker regression groups, static contract and source binding pass.
- [Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
  findings in one simultaneous bounded wave. The [coordinator record](review-summary.json)
  retains exact runtime/model evidence. Standing owner instructions replace
  SOL with Astra and omit Kimi. The cold-replay requirement is now resolved.
- The [hosted CI record](hosted-ci-triage.json) separately identifies any
  unchanged baseline failures. A local proof-gate result is not an overall
  green-CI claim.

These are classical manual-model statements. Rust/model fixture agreement
is tested correspondence, not extraction. No concrete SHA-256 theorem, QROM,
96-bit deployed security or hardware/production authority is claimed.
Adaptive opening coverage and component forgery reduction remain under
#100/#295; #509 stays an owner-triggered deferred combined playbook pass.
