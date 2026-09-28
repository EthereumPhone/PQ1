# Honest correctness transfer and public-node collision charges

Source-merge receipt for `a25c9122ac294bea966ac9ac7b909dc3dfb39514`, tree `d6b72bea2152c135c0de37e9d78c2e0b535c7e77`, based on
`e4687547e2b194c397b8a43f0ddaf15134bf7119`. The later receipt commit changes no proof or gate input.

The physical honest-byte error is charged through the existing shared-secret prefix hop. Public retained-node collisions receive their 128-bit birthday charge, including cached-call accounting and a same-client complete byte-game application. Public zero nodes receive a separate charge; invalid-sum WOTS recovery matching a reference leaf implies that event. The remaining forgery residual stays explicit.

## Validation

- [Full cold replay](full-gate.log): `371` direct targets,
  `371` default-CLI targets and `263` controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget change. Exit 0 in 8996.59 seconds.
- Started 2026-09-24T03:15:59.055838+00:00; finished 2026-09-24T05:45:55.645864+00:00.
  Input identity `45a497ff6ac7dfb7869ed3b84a51469f` stayed unchanged across the run.
- `2727` pins, `2378` statements, `134` roots,
  `2096` census rows and `335` manual source bindings.
  No new project axiom, admit or unrealized clone assumption.
- All `30` repository-only focused proof-driver checks and
  `38` new controls match the enrolled sources and expected reasons.
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

## Control-evidence correction

The initial wave returned Astra GO and Opus FIX for overstating what the
negative controls establish. The coordinator reproduced that finding and
cancelled the initial gate; it supplies no passing gate evidence. The fresh
wave above reviews the corrected source. The initial reports and reconciliation
are retained in [initial-review](initial-review/coordinator-triage.json).

The 38 new controls comprise six positive checks, twelve scope rejections,
nineteen exact-statement mismatches and one unfinished obligation. The initial
report overstated the count of exact mismatches; these are the reconciled counts.
Rejected proof attempts do not establish logical falsity, necessity or tightness.
The [reproduction](control-reproduction/receipts.json) shows the same true weaker
bound rejected by exact application and accepted using a valid consequence proof,
through both drivers. The interactive CLI process may exit zero with proof errors;
diagnostics are therefore essential. Proof/control bodies are unchanged.
