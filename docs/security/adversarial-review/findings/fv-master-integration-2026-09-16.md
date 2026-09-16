# Master integration — FV evidence fixes

Active surface: formal-verification evidence tooling. Phase C integration of
already-reviewed fixes onto master ab9e9049a5a8c8d088966d02b7ff9a5714ae678a.
Canonical dirty/untracked hashes are preserved in baseline.json. User explicitly
authorizes publishing these fixes to master, then research-limitation assessment.

Slices: prior FV/Verity/gate-contract prerequisites (ebb590d0,9762ea7c,43cf6208),
Kani mutation corrections, EasyCrypt gate reconciliation with master's 53-file
closure, and CI/context/count integration. Exclude all board/boot changes.
Preserve master's proof sources, statements, 49 polarity controls, six-headline
scope-probe bijection, exact margin/taint-control counts and assumption census.
No new crypto claim or production authority. #509's broad sweep stays deferred.

Mandatory checks: unchanged-prerequisite source/receipt comparison; relevant
FV script regression/drift checks; Kani census and runner controls; CI registration
and its regression controls; complete current 53-file split fast gate plus pinned
image controls/full replay. The full proof gate and one new simultaneous 900s /
800-word SOL ultra, Opus xhigh, Kimi max wave may run independently on the frozen
combined target. Reproduce only stage blockers, re-review material corrections.
Landing requires both green executable gates and reconciled review, fresh remote
master check, no force-push, preserved unrelated workspace, and a compact receipt.

Next boundary: combined Phase D after integration tests. Then publish to master
and stop this phase before examining the research frontier in Phase A. Research
assessment will use current master, not the older feature-branch limits. Any new
proof experiment stays disposable until independently tested/reviewed for promotion.

## Integration evidence before freeze

All earlier Lean, extracted, Verity, TLA and protocol proof project bytes match
the reviewed fix branch d168122e. Their recorded complete proof results remain
dated evidence; the integration also runs fresh relevant checker controls.
Every existing master EasyCrypt .ec/.eca source is unchanged. The combined
gate retains 53 files, 1,166 unique pins, 1,082 statements, 49 polarity controls,
15 taint controls, four taint-count controls, exact margin counts and six-file
headline/scope-probe linkage. The new helper also rejects noncanonical pin aliases.

Kani census and runner controls pass: 173/27 source census, 164/22 enrolled and
nine/five outside, 43 mutation groups. All 67 gate registrations pass. Static
EasyCrypt contract checks pass. New split input identity:
`e64e9594831f9b2df2ccdaeaf5f8c213`. A complete fresh pinned-image replay and the
combined bounded source review are still required before master publication.
The old 45-file green receipt is not a receipt for this newer proof artifact.
