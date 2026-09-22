# Bounded hypertree and leaf interfaces — September 22, 2026

Source merge evidence for [PR #727](https://github.com/EthereumPhone/PQ1/pull/727).
Reviewed and replayed source: `5c1770105acb81700d99eea8e917b1156b96e0db`, tree `0f0990e1f83a5f0133da3e8633b741a8a1db45ef`;
comparison base: `044b3d200194687cb61b6d59984739169d451f67`. A later receipt/link commit changes no proof
or gate input. The canonical dirty board worktree was preserved.

The bounded NPRF hypertree signer terminates, emits exactly d layers on success,
agrees with the total signer on successful results, and returns no signature on
exhaustion. Its failure-rejecting nonadaptive game is bounded by the existing
total game. Separately, the actual precomputed leaf wrapper's termination and
member separation instantiate the N2-free WOTS theorem. Target cap, address,
encoder, collection separation and adversary termination remain explicit.

**The two inequalities are not joined.** A common failure-aware experiment
through the full precomputed cube and collision branches remains necessary;
exhaustion at an unused cube entry must not erase an operational win. The old
total hypertree theorem still carries N2. This batch adds no project axiom or
admit; the broader cone's legacy `FORS_C_TreePort.extract_op` admit remains.

## Executed evidence

- `make -C contracts/verification verify-easycrypt-split`: cold disposable copy,
  pinned image, network disabled, source read-only; all 71 files checked directly
  and through CLI iteration, and all 75 controls pass.
- Run: 2026-09-22T14:47:46.876085+00:00 to 2026-09-22T16:29:34.929987+00:00,
  6108.05 seconds, exit 0. [Raw full gate](full-gate.log).
- Identity `bbdc6399fb6ea45a48ce169f8f2d7408`; 59 roots, 1,359 declaration pins,
  1,228 statements, 1,732 raw assumption/module rows. Only two concrete module
  rows were added; existing assumptions are unchanged.
- Focused direct/CLI proofs and positive theorem clients pass. Negative controls
  reject removal of successful-output conditioning, an empty-signature release
  after failure, and missing PK-compression member separation. The full wrapper
  also runs the source-bound Rust transcript check and static gate regressions.

## Review and boundaries

[Opus](opus-report.txt) returned GO. [Astra](astra-report.txt) returned GAP
solely because full replay was pending, with no findings. The unchanged source
has now completed that replay; the coordinator discharges this mandatory gap
from the execution receipt above. The Astra report remains unmodified.
The initial Astra leg could not execute source-reading commands because nested
Bubblewrap failed; its one same-model mechanical retry used legacy Landlock
inside unchanged read-only candidate/Git mounts, with the identical prompt.
Opus also noted that the failure flag is local: no observable exhaustion
probability or reverse total-to-bounded inequality is exported. This is a
non-blocking future interface limitation, banked with #100/#295; the bounded
operational claim does not require the reverse inequality. See the
[coordinator note](coordinator-note.json).
Aggregate review time: 441.842 seconds within the
original 900-second cap; both reports meet the 800-word cap. Astra replaces SOL
and Kimi is omitted under standing owner instructions. Runtime manifests retain
that distinction; the mechanical gap is not counted as completed source review.

The remaining cube/collision composition, real shared-hash/adaptive-history,
FORS truncated-R, useful reduction runtime and numerical bounds remain open in
#100/#295. This is a manually linked sampled-key model, not a Rust extraction.
There are no firmware/deployment changes or hardware/shipment claims. #509 stays
deferred. [Hosted CI disposition](ci-disposition.json) records the actual
hosted-check results and any unchanged baseline failures.

[Evidence identities](evidence.json) and [SHA256SUMS](SHA256SUMS) bind the receipts.
