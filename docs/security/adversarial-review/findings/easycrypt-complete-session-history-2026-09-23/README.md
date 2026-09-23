# Complete-session history and repeat accounting — September 23, 2026

Source-merge receipt for d0c2999c92932d46806322af96a637e186d9b170, tree e7fd222a409acf077c2a44914d230b064982caf3, based on 38976ea50b0f79e083759feb33f43876504d2738.
The later receipt commit changes no proof or gate input.

The actual live structured and byte-session models account for private R
derivations by signed messages and classify every 32-byte context as fresh
or previously completed. Repeats retain the first accepted randomizer and
digest. The novel-event bound explicitly excludes that retained output
from its entry-fixed predicate and retains the cached-query charge.

## Evidence

- Complete cold make -C contracts/verification verify-easycrypt-split:
  203 direct targets, 203 default-CLI targets and 133 controls pass.
  Pinned r2026.02 image, network disabled, source read-only, disposable cold
  proof copy; no budget changes. [Raw replay](full-gate.log).
- Run 2026-09-23T16:39:53.460544+00:00 to 2026-09-23T19:34:39.958021+00:00,
  10486.5 seconds, exit 0.
  Input identity fa1c76ddce3555c0565a9dfdbbe429ac is unchanged across the run.
  The elapsed time includes a [coordinator clock gap](clock-gap.json);
  both reviewers had already completed, and the original 18000-second
  full-gate wall-clock bound is enforced without an extension.
- 2128 unique pins, 1863 statements, 91 roots, 1962 raw census rows and
  167 manually bound source inputs. No new project axiom, admit or clone
  assumption. The broader cone's legacy admit remains outside headline
  environments.
- All 19 enrolled modules have source-matched direct/default-CLI
  [focused receipts](focused-receipts.json). Eleven new controls cover
  history, failure handling, private state, repeated outputs and scope.
  The 11 checker regression groups and static contract pass. The raw
  regression log preserves the existing Python ResourceWarnings.
- The complete gate retains 20 complete Rust/model signature comparisons,
  160 negative cases and four Rust transcript tests. This remains tested
  manual correspondence, not extraction.

## Review and boundary

[Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
findings on the exact source above. Both ran simultaneously within
900 seconds and 800 words. The required unchanged-source replay is now
complete; no further model wave was needed.
Standing owner instructions replace SOL with Astra and omit Kimi.
The [coordinator summary](review-summary.json) distinguishes the requested
Astra configuration from the observed Opus runtime model.

Hosted CI remains separately red on the unchanged baseline failures
#660, #711 and #717; [triage](hosted-ci-triage.json) records them.
This receipt does not claim overall CI is green.

These are history statements for the independent-table intermediate game.
The whole-game secret-prefix hop does not transfer its private predicates
literally to physical Rust state. The accumulated adaptive opening argument,
complete byte-model component reduction and numerical end-to-end forgery
bound remain open under #100/#295. The separate path-correspondence research
is excluded. Owner-triggered combined playbook pass #509 stays deferred.
No deployed 96-bit bound, Rust extraction, concrete SHA-256 theorem, QROM,
hardware or production authority follows from this source merge.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind this receipt.
