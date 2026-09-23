# Shared-byte-session C10 milestone — September 23, 2026

Source-merge receipt for `1fc27470fc083e84eb844bf06e4aaf4551a7a079`, tree `dab22c3bfae2e7535c662c9553f148ab167a9f53`, based on
`1be79a0a653b90bf93071b0b83129b8654fff618`. The later receipt commit changes no proof or gate input.

The manual model represents adaptive C10 key generation, full signing and
verification, and the 4008-byte interface over one persistent classical oracle.
It checks physical/public query budgets, byte/structured game correspondence,
same-client secret-prefix coupling and sticky fail-stop behavior.
The independent-game forgery probability remains unbounded.

## Evidence

- Complete cold `make -C contracts/verification verify-easycrypt-split`:
  163 direct targets, 163 default-CLI targets and 113 semantic/mutation controls
  pass. Pinned r2026.02 image, network disabled, source read-only, disposable
  cold proof copy; no budget changes. [Raw replay](full-gate.log).
- Run 2026-09-23T12:20:26.310014+00:00 to 2026-09-23T14:09:50.082735+00:00,
  6563.77 seconds, exit 0. Input identity `820fb7e3a8d386a01b58981604b327e0`
  is unchanged across the run.
- 1902 unique pins, 1664 statements, 83 roots, 1918 raw census rows and 127
  manually bound source inputs. No new project axiom, admit or clone assumption.
  The broader cone's legacy admit remains outside the headline environments.
- 20 complete byte-identical Rust/model signatures, 160 matching negative
  cases and hash-call counts; four Rust transcript checks.
  [Focused receipts](focused-receipts.json) cover all 73 new proof modules.
  This is tested manual correspondence, not extraction.

## Review and corrections

[Astra ultra](astra-report.txt) and [Opus xhigh](opus-report.txt) returned GO on
the exact source above. Their pending replay gaps are resolved by this complete
unchanged-source gate; raw reports are preserved. Both ran simultaneously within
900 seconds and 800 words. Kimi is omitted under the owner's standing instruction.
[Coordinator disposition](review-summary.json).

The original cold run stopped before proof replay at the policy-cap tripwire:
RawShuffle needs the 16-bit scaling denominator 65536. The correction permits
only its exact source hash, path and single occurrence; regression cases keep
other files, edits and spellings rejected. Opus's earlier missing Rust bindings
were reproduced and corrected by binding hypertree.rs and merkle.rs.
The original gate failure, reports and manifests remain in this receipt.

The original Astra launch and sole retry could not execute source reads because
of local sandbox setup. The corrected wave used the current Codex native
read-only sandbox after mount preflight; Opus kept outer read-only mounts.
No host policy or credentials changed. Runtime identities and bounds are in the
[manifest](review-wave-manifest.json).

Hosted CI is separately red on the existing #660, #711 and #717 failures;
[triage](hosted-ci-triage.json) records those unchanged baseline inputs.
This is not an overall CI-green claim.

The component reduction and meaningful quantitative ITSR/EUF-CMA bound remain
open under #100/#295. Later external Q experiments are outside this receipt.
The combined owner-triggered playbook pass #509 stays deferred.
No hardware, firmware-release, production, extraction, SHA-256-independence or
QROM claim follows from this source merge.

[Evidence identity](evidence.json) and [SHA256SUMS](SHA256SUMS) bind this receipt.
