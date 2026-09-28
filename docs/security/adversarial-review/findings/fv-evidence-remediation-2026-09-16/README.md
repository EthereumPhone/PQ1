# FV remediation evidence — 2026-09-16

The parent receipt owns the coordinator decision and current limitations.
The six review directories retain original prompts, reports, runtime streams,
stderr and launcher manifests. Absolute paths in those original files refer to
the isolated review worktree and external scratch directories used at execution.
The three *-accepted.json receipts identify the accepted reviewers and hashes;
each separate Codex directory is the one permitted mechanical launch retry.
Original outputs are not edited or normalized.

reviewed-fv.patch reconstructs the reviewed tree from d52679ac; frozen-commit.txt
records the exact final review commit. The patch does not include later receipt
closure text. The integration preflights identify unrelated concurrent changes.

easycrypt-full.log is a superseded partial run, deliberately stopped after the
abstract-theory import issue was reproduced. Only easycrypt-full-v2.log and its
completion receipt can establish the final complete proof replay.
Focused Kani logs cover three original/mutant pairs and exact selection; they do
not claim a complete Kani nightly campaign. Historical target controls do not
claim fresh complete replay of the historical proof tree. The clean-runner logs
exercise bootstrap and Make invocation in a disposable container, not hosted CI.
SHA256SUMS binds every other file in this directory after completion.
