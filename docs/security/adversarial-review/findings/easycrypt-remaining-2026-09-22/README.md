# Remaining C10 research — September 22, 2026

Source merge evidence for [PR #731](https://github.com/EthereumPhone/PQ1/pull/731). Reviewed/replayed
source `8d388d66123068b995827f76840b129d4491f4a9`, tree `3e1801909df0d61c481dac1bbc7a3754d2e0cb8d`, base `bd9b8a889da225238a52ca896b8fa1735262b9b4`.
The later receipt/link commit changes no proof or gate input. The canonical dirty
board worktree was preserved.

The bounded hypertree now has an N2-free five-term bound with the existing
failure charge retained. The same-adversary leaf and collision reductions and
all remaining premises are explicit. The deployed all-leaf paths cover the full
cube; earlier descriptions of unused entries did not apply to this experiment.
Coverage alone does not remove the charge or preserve an event through game hops.

The classical memoizing search bounds exhaustion using initially fresh inputs
from arbitrary entry history. Its C10 instance uses actual distinct counter-byte
inputs and the actual digit predicate; at least 9,994,240 fresh trials suffice
for a checked `2^-305` exhaustion bound. Physical length/tag lemmas, uniform
high-half R truncation, a whole-experiment adaptive birthday bound, and the
existing FORS consumer's finite IID-R/conditioned mixture preserve repeated R.
These are not numerical forgery or quantum-security bounds.

## Executed evidence

- Full cold `make -C contracts/verification verify-easycrypt-split`: pinned image,
  disposable copy, network disabled, source read-only; all 78 files
  pass direct compilation and CLI iteration, all 90 controls pass.
- Run: 2026-09-22T20:28:52.742517+00:00 to 2026-09-22T22:06:14.258187+00:00;
  5841.52 seconds, exit 0. [Raw replay](full-gate.log).
- Identity `5f6df9c16534c5d85745b7a6f406075d`; 66 roots, 1422 unique
  declaration pins, 1271 statements, 1751 raw census
  rows. The 19 new census rows are defined operators, the fully instantiated
  Birthday clone/operands, and one SMT-export annotation. The existing recursive
  operator body has the same normalized census hash. No existing assumption changed; no new project axiom
  or admit. The broader cone's legacy `FORS_C_TreePort.extract_op` admit remains.
- Focused proofs/CLI and all 15 new controls pass their expected outcomes. They
  reject cached/duplicate-input freshness, wrong H_msg length, single-path cube
  coverage, low-half R truncation and erased FORS exhaustion. Positive clients
  consume the new contracts and show a duplicate input supplies one trial.
- Four source-bound Rust helper tests pass, including H_msg/pair layouts and
  FORS/hypertree digest fields. These remain finite manual correspondence checks.
- The corrected recursive sampler is opaque only to SMT export; its definition
  and theorem statements remain available to checked EasyCrypt proofs. The new
  cloned-consumer SMT regression reproduces the original export error and passes
  with this annotation. The first full replay and first source-review wave were
  superseded after this integration failure, and are preserved separately.
- The first static gate detected a forbidden import of the quarantined policy-
  cap file. The corrected coverage proof derives geometry directly from the
  base model; the unchanged quarantine fence now passes. Failed exploration and
  superseded preflight attempts are not counted as proof evidence.

## Review and boundaries

[Review disposition](review-summary.json) retains each raw verdict and the
coordinator's finding/gap reconciliation. Both fresh reviewers returned GO with
no findings. Opus noted the documented lack of a link from the theorem's whole-
experiment draw budget to production per-key usage. That remains open under
#100/#295; an expected number of draws does not supply a worst-case signing
allowance. The coordinator also inspected `Birthday.eca` in the pinned image
and printed its instantiated statement, confirming explicit termination and
call-budget premises. The completed unchanged-source replay discharges the
outstanding execution gate. Opus alias resolved to `claude-opus-5-5`.
The original Astra leg could not read
source because nested Bubblewrap failed. Its sole same-model retry used the
legacy Landlock backend inside the unchanged read-only candidate/Git mounts,
with the byte-identical prompt and original 900-second wall-clock bound.
Astra ultra replaces SOL and Kimi is omitted under the user's standing decisions;
Opus uses xhigh. Runtime manifests bind the exact versions, times and report
hashes. This is source-merge review, not hardware or shipment approval.

The remaining statements are charge-free accepted-history composition, the
common stateful shared-SHA simulation (including keyed R derivation), and costed
reductions with quantitative ITSR/EUF-CMA bounds. Existing pure hash operators do
not provide that cost model. #100/#295 stay open; #509 stays deferred. No Rust
extraction, SHA-256 independence or deployment authority is claimed.

[Hosted CI](ci-disposition.json) records actual results and unchanged baseline
failures rather than asserting all CI is green. [Numerical illustration](numerical-illustration.json)
is reproducible arithmetic, separate from the checked conservative theorem.
[Evidence identities](evidence.json) and [SHA256SUMS](SHA256SUMS) bind this receipt.
