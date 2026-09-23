# Quantitative C10 foundations — September 23, 2026

Source-merge receipt for 589c650000f9d443723201ce5333aba5f6a6d4b4, tree dd9581383dcd0d587d01c1663c84eadf7109af8e, based on 1abfc31158e232f1a7f09b972a03176e53a5785f.
The later receipt commit changes no proof or gate input.

The milestone checks conditional accepted-output laws for the actual memoized
grinder and complete signer, fixed prior FORS opening sets, fixed hypertree
targets and an exact-coordinate replay reduction in the complete byte game.
The residual adaptive forgery probability remains unbounded.

## Evidence

- Complete cold make -C contracts/verification verify-easycrypt-split:
  184 direct targets, 184 default-CLI targets and 122 controls pass.
  Pinned r2026.02 image, network disabled, source read-only, disposable cold
  proof copy; no budget changes. [Raw replay](full-gate.log).
- Run 2026-09-23T14:39:53.725794+00:00 to 2026-09-23T16:30:59.386431+00:00,
  6665.66 seconds, exit 0.
  Input identity a7a6c66a5d9630e834ef2de251877aa4 is unchanged across the run.
- 2003 unique pins, 1750 statements, 87 roots, 1945 raw census rows and 148
  manually bound source inputs. No new project axiom, admit or clone assumption.
  The broader cone's legacy admit remains outside headline environments.
- All 21 new modules have source-matched direct/default-CLI
  [focused receipts](focused-receipts.json). Nine new controls distinguish
  freshness, cached-query charges, adaptive opening timing and scope.
  The 11 checker regression groups pass.
- The unchanged manual byte model retains the full gate's 20 complete
  Rust/model signature comparisons, 160 negative cases and four Rust
  transcript checks. This is tested manual correspondence, not extraction.

## Review

[Astra](astra-report.txt) and [Opus](opus-report.txt) returned GO without
findings on the exact source above. Their pending replay gaps are resolved
by this unchanged-source gate. Both ran simultaneously within 900 seconds
and 800 words. Standing owner instructions replace SOL with Astra and omit Kimi.
Raw reports remain verbatim; [coordinator notes](review-summary.json) clarify
three imprecise descriptions in Opus's prose. The source and checked theorem
statements define the actual claims. No further model wave was needed.
The [manifest](review-wave-manifest.json) captures requested model configuration
and runtime bounds; the summary distinguishes observed Opus model identity
from the requested Astra configuration.

Hosted CI remains separately red on the unchanged #660, #711 and #717
baseline failures; [triage](hosted-ci-triage.json) records them.
This receipt does not claim overall CI is green.

The remaining component reduction and accumulated adaptive opening argument
stay open under #100/#295. The entry freshness premise is explicit in this
milestone; later external Q2 history/repeat-context proofs are excluded.
The combined owner-triggered playbook pass #509 stays deferred.
No deployed 96-bit bound, Rust extraction, concrete SHA-256 theorem, QROM,
hardware or production authority follows from this source merge.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind this receipt.
