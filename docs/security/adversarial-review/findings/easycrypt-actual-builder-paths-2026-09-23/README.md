# Actual tree construction and FORS signing — September 23, 2026

Source-merge receipt for dd99b605c6f670e0cb7af3d25cd89c3b3409e3df, tree 10e463060b9d75d041e4d5da121ff323dd428167,
based on 78c6ad337a7109a4296d734cb2f971ec89392a35. The later receipt commit changes no proof or gate input.

Actual Merkle/FORS stack construction supplies complete catalogs, retained
parent hashes, authentication paths, widths and returned-root witnesses.
Actual FORS private derivations and initial leaf hashes supply the reference
secret. Build/recover matching roots imply reference equality or explicit
retained node collisions. Actual FORS signing/recovery agrees with the tree
root computed during signing, including termination.

## Evidence

- Full cold make -C contracts/verification verify-easycrypt-split:
  266 direct targets, 266 default-CLI targets and 168 controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget changes. [Replay](full-gate.log).
- Run 2026-09-23T21:57:34.873951+00:00 to 2026-09-24T00:07:42.367170+00:00,
  7807.49 seconds, exit 0. Input identity
  0ffc0d10b386ad36420dc7f39df774dc is unchanged across the run.
- 2393 pins, 2086 statements, 103 roots, 2020 census rows, 230 manually bound
  source inputs. No new project axiom, admit or clone assumption.
- All 53 new modules pass source-matched direct/default-CLI checks with
  repository-only imports. All 24 new semantic/scope controls pass or fail
  for their declared reasons. Eleven checker regression groups and the
  static contract pass. Existing Python ResourceWarnings remain visible.
- The full gate retains the Rust/model fixture and transcript comparisons.
  This is tested manual correspondence, not extraction.

## Review and boundary

[Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
findings on the frozen source. Both ran simultaneously within 900 seconds
and 800 words. Their explicit cold-replay gap is now resolved.
Standing owner instructions replace SOL with Astra and omit Kimi.
The [coordinator summary](review-summary.json) records model evidence.
The native readonly preflight and launcher regression suite passed; observed
CLI versions and their version-contract boundary are in the wave manifest.

Hosted CI remains red on unchanged baseline failures #660, #711 and #717;
[triage](hosted-ci-triage.json) binds those findings to this source.
This is not an overall green-CI claim.

The milestone supplies the earlier reference-path premises, but does not
prove WOTS or complete forest/layer/signer composition. FORS sign/recover
correctness refers to the root computed during that call, not a separately
generated external root. Accumulated adaptive opening coverage, collision
probability charges and a numerical end-to-end forgery bound remain open
under #100/#295. Later checked component research is outside this candidate.
Zero-valued nodes remain allowed. #509 remains deferred to an owner-triggered
combined playbook pass.

The statements concern the independent-table intermediate game; the
whole-game prefix hop does not transfer private predicates literally to
physical Rust. No extraction, concrete SHA-256, QROM, deployed 96-bit bound,
hardware or production authority follows.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind the receipt.
