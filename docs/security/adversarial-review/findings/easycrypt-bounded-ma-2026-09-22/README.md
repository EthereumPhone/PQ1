# Bounded member-aware WOTS reduction — September 22, 2026

Source merge evidence for [PR #726](https://github.com/EthereumPhone/PQ1/pull/726).
Reviewed and proof-replayed source: `532c4b7a2b945566ce4e3b3247a9f50224883788`, tree `2a32fd7af778c80c551a42fb2c4fce844a6317e0`;
comparison base: `8f739990d691a5b62b043b2fb6357e5500dabbae`. Any following receipt/link commit changes no proof
or gate input. The canonical dirty board worktree was preserved.

`C10BoundedMA.bounded_interactive_D1_MA` bounds `BoundedGame(A)` wins by the
existing WOTS-TW and member-aware S-TCR challenge probabilities. Accepted-query
reachability and a preserved transcript event remove universal N2 and the
charged grind-failure summand for this bounded experiment. Target cap, address
separation, encoder bridge, member-aware collection separation, private oracle
globals and adversary termination remain explicit. No project axiom or admit
was added; the broader cone's legacy `FORS_C_TreePort.extract_op` admit remains.

## Executed evidence

- `make -C contracts/verification verify-easycrypt-split`: cold disposable copy,
  pinned image, network disabled, source read-only, all 69 files checked as
  direct targets and all 69 through CLI iteration; all 70 controls pass.
- Full run: 2026-09-22T12:30:49.309935+00:00 to 2026-09-22T14:11:28.208241+00:00,
  6038.9 seconds, exit 0. Raw output: [full-gate.log](full-gate.log).
- Identity `c8559f353fcd973902a9f5ad466b6f58`; 57 roots, 1,347 unique declaration pins,
  1,216 statements, unchanged 1,730-row raw assumption/module census.
- Focused compile/CLI, exact final-theorem positive control and intended proof
  rejection of erased history and a failed-query record. Source-bound Rust
  transcript checks and all static gate checks run in the full wrapper.

## Review

[Astra](astra-report.txt) and [Opus](opus-report.txt) return GO on the exact
source above; neither reports a finding. Full replay was pending during their
source reviews and is now discharged by the separate receipt. The initial Astra
leg had no source access because nested Bubblewrap commands failed before
execution. Its one same-model mechanical retry used legacy Landlock under the
unchanged outer read-only candidate/Git mounts and the identical prompt.
Aggregate review time including retry: 360.025 seconds,
within the original 900-second bound; reports are within 800 words. Kimi was
omitted and Astra replaced SOL under explicit standing owner instructions.
Runtime manifests and the initial honest GAP report are retained.

## Limits and handoff

This is a bounded WOTS result. Bounded hypertree composition, a concrete shared-
hash/adaptive-history proof, FORS truncated-R accounting, useful reduction
runtime and numerical challenge bounds remain open in #100/#295. The model is
manually linked to Rust, not extracted. No firmware or deployment changes, and
no hardware/shipment authority, are part of this batch. #509 remains deferred.

Hosted CI is not all green: seven failures reproduce unchanged TRNG-ledger,
curation-manifest, fuzz-lockfile and Foundry-installer inputs, tracked by
#660/#711/#717. [CI disposition](ci-disposition.json) records source comparisons
and decisive job output. G1, Lean FV, secure host tests, firmware link, QEMU,
Miri, cargo-vet and hosted Claude review passed on the source candidate.

[Evidence identities](evidence.json) and [SHA256SUMS](SHA256SUMS) bind these receipts.
