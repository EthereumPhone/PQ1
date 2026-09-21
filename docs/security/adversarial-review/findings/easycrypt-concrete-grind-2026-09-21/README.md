# C10 counter, byte adapter and bounded-search review

Source review is complete. The original 56-file replay passed; the combined
60-file replay is **GREEN**, exit code 0. [PR #710](https://github.com/EthereumPhone/PQ1/pull/710)
advances #100 while leaving the broader refinement obligations open.

On 2026-09-21, the owner explicitly removed Kimi from review while subscription
access is unavailable and requested modest compensation. Both permitted Kimi
attempts had failed before inference with subscription-access HTTP 403. One
fresh Astra review on `27307116`, capped at eight minutes / 500 words, returned
GO in 145.415 seconds. This adds an independent reading, not a third provider
or model family. The subsequent integration uses Astra and Opus only.

| Evidence | Exact source | Input identity / result |
|---|---|---|
| Original full replay | `dc0ab780` | `0019348b947cefe5055e32f4be9c91c3`; GREEN, exit 0; 56 files, both drivers, 52 controls |
| Original review | `0bd9f94d`, tree `909763a6` | Astra GO; Opus historical-comment finding corrected |
| Additional focused review | `27307116`, tree `9cd28923` | Astra GO, no findings |
| Integration review/replay | `7b7e64bb`, tree `57b2ffdb` | Astra GO (240.001 s), Opus GO (424.483 s); replay `25a44da326139fa04dedb005f3ff58cf` GREEN |
| Editorial correction | `276d3c23`, tree `f8245899` | Fast gate GREEN at `2e65303618452c3b2117ec8dcdf0f877` |

The original replay preceded the independent CI required-path floor fix; all
proof/Rust replay inputs were identical at `0bd9f94d`. That floor's 22 regression
groups passed separately. Original Astra needed one permitted mechanical retry
for nested Bubblewrap failure; legacy Landlock retained read-only candidate/Git
mounts. All completed reviews stayed within their caps, with no candidate drift.
Exact commands, identities, hashes and timing are in `receipt.json`. Raw provider
runtimes remain in a private local archive. Opus reported writing its own plan
artifact outside the target; the launcher does not enforce host-wide immutability.

Master advanced to `e6ac316e` during the original replay, promoting four separate
surface-count proofs and six controls. The integration preserves both branches:
60 files, 51 roots, 1,276 declaration pins, 1,154 statements, 58 controls and
1,715 census rows. All 60 proof files at `7b7e64bb` match one parent byte for byte
(`integration-source-mapping.json`). Shared gate inventories and counts were
reconciled, then a fresh full replay and simultaneous Astra/Opus review began.

The coordinator reproduced and corrected these findings:

- Original Opus: stale historical comments, including the now-vacuous r256
  premise. `R256Vacuous.ec` proves its negation; dated corrections preserve the
  conditional statement for compatibility and label its limited meaning.
- Integration Opus: stale 56-file metadata and four statement-adjacent comments
  describing the former abstract counter/encoder. The census header and text
  now describe the concrete model and combined perimeter.

These corrections are editorial under workflow section 10. All 60 formal files
retain identical code after comment removal; active census rows and gate logic
are unchanged (`integration-editorial-mapping.json`). The final fast gate passed
with the refreshed identity. The review/replay receipts still bind `7b7e64bb`;
they are not relabelled as exact-byte receipts for `276d3c23`.

Completed validation: real Rust helpers over 210 transcript cases; three new
semantic rejection controls; 10 split regressions; 22 gate-enforcement regression
groups; final source-binding, static/identity and gate-enforcement checks; and
the original full replay. **Combined full replay: GREEN**, exit code 0: both drivers passed all 60 files,
all 58 controls passed, and the input identity was unchanged. The complete log
is `full-split-integrated.log`.

The Rust host test uses the repository's nightly toolchain separately from the
pinned EasyCrypt container. Hosted execution of that nightly step has not been
observed; the review identified no concrete source blocker there. Dedicated FV, gate-enforcement, workflow lint and census CI passed on
editorial commit `276d3c23`. Broader unrelated CI
failures are tracked in #660, #661 and #711; no blanket CI-green claim.

Four standard-library Subtype construction obligations remain trusted. Generic
Grind retains its enumeration obligation, discharged in the actual WOTS clone.
Full Rust/hash/predicate refinement, abort-aware game composition, fresh-R oracle
coupling and numerical security remain open under #100/#295. Source binding and
finite tests are not extraction. The combined playbook sweep remains deferred
under #509. These results cover source merge, not production or hardware authority.
