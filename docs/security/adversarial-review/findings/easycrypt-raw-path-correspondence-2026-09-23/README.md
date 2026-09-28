# Raw authentication-path correspondence — September 23, 2026

Source-merge receipt for 6e8994150edf2e45e7915d4056888e7e0e6fad2f, tree 4f46dd1801fbf19473179ddd8c84b7c1e93336d7,
based on b89a1b66647bd7498af9b4b9362984a328a2186c. The later receipt commit changes no proof or gate input.

Actual Merkle and FORS recovery records the complete path in the memoized
public oracle table. FORS includes its initial secret-to-leaf hash. Matching
a recorded reference root implies the reference leaf/secret or distinct
same-position raw inputs with equal 16-byte node projections. Reference
entries, path lengths and width premises remain explicit.

## Evidence

- Full cold make -C contracts/verification verify-easycrypt-split:
  213 direct targets, 213 default-CLI targets and 144 controls pass.
  Pinned r2026.02 image, network disabled, read-only source and disposable
  cold proof copy; no budget changes. [Replay](full-gate.log).
- Run 2026-09-23T19:45:34.190712+00:00 to 2026-09-23T21:46:24.183808+00:00,
  7249.99 seconds, exit 0. Input identity
  f91c239ef8a20e3e58a40b7478d333a3 is unchanged across the run.
- 2166 pins, 1890 statements, 95 roots, 1976 census rows, 177 manually bound
  source inputs. No new project axiom, admit or clone assumption.
- All ten new modules pass source-matched direct/default-CLI checks.
  Eleven new controls cover repeated actual recovery, a width countermodel,
  missing reference/leaf entries, widths, privacy and scope.
  Eleven checker regression groups and the static contract pass.
  Existing Python ResourceWarnings remain visible in the raw regression log.
- The full gate retains the complete Rust/model fixture and transcript
  comparisons. This is tested manual correspondence, not extraction.

## Review and boundary

[Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
findings on the frozen source. Both ran simultaneously within 900 seconds
and 800 words. The separate required replay is now complete.
Standing owner instructions replace SOL with Astra and omit Kimi.
The [coordinator summary](review-summary.json) records model evidence.

Hosted CI remains red on unchanged baseline failures #660, #711 and #717;
[triage](hosted-ci-triage.json) binds those findings to this source.
This is not an overall green-CI claim.

The reference-path premises are not supplied by this milestone. Actual
honest-tree construction is separate research, excluded from this candidate.
WOTS/FORS composition, adaptive accumulated opening coverage, collision
probability charges and a numerical end-to-end forgery bound remain open
under #100/#295. Zero-valued nodes and the WOTS invalid-sum sentinel are not
excluded by an artificial nonzero premise. #509 remains deferred to an
owner-triggered combined playbook pass.

The statements concern the independent-table intermediate game; the
whole-game prefix hop does not transfer private predicates literally to
physical Rust. No extraction, concrete SHA-256, QROM, deployed 96-bit bound,
hardware or production authority follows.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind the receipt.
