# PR-to-master control evidence reuse (#1002)

Status: implementation contract; issue #1002 owns the required review, actual
CI and measured acceptance receipts. Owner: issue #1002; #789 retains ownership
of EasyCrypt proof/Rust correspondence separation. This is a Lean control
execution optimization, with no new mathematical or correspondence claim.

## Contract and trust boundary

A master push may consume one complete successful same-repository PR control
run for its landed candidate. The push still freshly rebuilds every project
proof, checks every source/statement/manual binding, audits the exact closure
inventory, and executes both closure canaries. All 15 existing identity fields
must match the original producer, including actual loaded libraries and judging
policy; the entire Git tree must also match. Nothing restores executable code
or compiler libraries from evidence. `authenticate_shards` keeps its current
same-run/attempt context rule unchanged.

GitHub's authenticated API, workflow service, hosted runners, pinned actions,
repository maintainer control of the landed workflow, the upstream pinned
mathlib artifact service and installed toolchain remain explicit trusted
boundaries. Remove Actions dependency-cache restore/save from this workflow
for all jobs, including probe, PR producers and push consumer. Every hosted
job starts from absent `.lake/packages`, resolves pinned dependency source and
uses the existing upstream mathlib fetch command. Earlier PR revisions and
other workflows cannot supply a branch-scoped executable cache to an eligible
producer. Same workflow-byte equality and admission of the exact required step
set enforce this policy; no cache step is permitted in an eligible producer. A compromised trusted
runner/API is outside this mechanism's claim. No new privileged event, write
permission, trust in a digest supplied inside a receipt, or attestation service
is introduced. Artifact digests obtained from the authenticated API are
submitted by the pinned upload action, not independently computed by GitHub;
the trusted runner/uploader boundary is necessary.

## Producer admission

Use authenticated read-only GitHub metadata; bound pagination, request time,
archive sizes and expanded members. Treat a partial listing as ineligible.

1. Consumer must be the real EthereumPhone/PQ1 master push, clean at its event
   SHA, not a fork/manual/PR/local invocation. Discover exactly one merged PR
   associated with that target commit, with base master and same-repository
   head, whose API merge_commit_sha is the target. No ambiguous selection.
2. Select exactly one completed successful pull_request run of
   `.github/workflows/lean-probability.yml` at that PR's exact head SHA. Verify
   repository ID/name, workflow ID/path and run/attempt using separate API
   reads. Initially only attempt 1 is eligible; any rerun selects cold execution.
3. Require the exact expected producer job set: eight named control shards,
   the aggregate, and the new eligibility probe. Every required job and
   required execution/upload step must have completed successfully; on PR the
   probe is a successful ineligible/no-op. Reject missing/duplicate/extra jobs,
   skipped required steps, cancelled jobs and failed conclusions.
4. Obtain the original checkout SHA from the GitHub-served producer checkout
   log and require agreement across producer/aggregate jobs and receipt
   contexts. Validate that Git object via the API: its tree equals the target,
   its synthetic merge's second parent is the PR head and first parent is an
   ancestor of the target. Require workflow source bytes at that checkout and
   the PR head to equal the current consumer's reviewed workflow. The original
   context must name the exact repository, run, attempt, event, checkout,
   workflow SHA and `refs/pull/<number>/merge` workflow ref.
5. Require exactly the eight shard artifacts and original aggregate for that
   attempt. Pin IDs, GitHub SHA-256 digests, source repository/head/run and
   non-expiry. Download by ID and explicitly check archive bytes against the
   API-recorded uploader digest before strict extraction. Reject symlinks, traversal,
   duplicate members and resource-limit excess. Re-read metadata after
   download; changed run/artifact identity or conclusion refuses reuse.

## Original evidence and target link

Authenticate the original aggregate's fresh-build, closure/canary logs,
identity, exact closure inventory and original context. Reconstruct and compare
its complete aggregate summary by invoking the unchanged `authenticate_shards`
on all original raw sources/logs under the original context, with freshly
generated target fixtures. All 1,655 cases / 4,965 stages at the baseline must
be covered; future census growth remains exact. A `passed` field is insufficient.

Only after the consumer's own fresh proof checks and complete identity match
may it emit a separate successful target receipt. That receipt names target
context and identity, origin PR/head/checkout/run/attempt/workflow, artifact
IDs/digests and original result hashes, authenticated coverage and fresh checks.
It never edits original contexts. Repeat input/context drift checks at exit.

## Workflow and cold fallback

A probe job attempts metadata/aggregate admission on push. It installs the
pinned toolchain and fetches dependencies from absent packages, then compares
every existing identity field except `project_libraries_sha256` against the
origin. It does not build project proofs. Any such mismatch selects sharding
early. The probe, shards and final job fetch the same explicit set covering
every direct Mathlib import in the pinned proof inventory, then prepare the
`proofwidgets/widgetJsAll` dependency target. This creates the same dependency
sidecar hashes as the full build without compiling project proofs or excluding
any identity input. A regression guard checks this wiring. Hosted feasibility compares the fourteen fields before
and after building, as well as both complete fifteen-field identities. The
probe outputs only a candidate run ID, not a verification pass. PR/manual/forced-cold runs
select the existing eight fresh shards immediately. Probe error, skip or
failure also selects those shards, using explicit `always()` dependency logic.

The required final `PMF proofs and semantic controls (8)` job always runs.
Add one explicit reuse mode to `check_probability.py`: its single process owns
fresh build, identity, origin fetch/authentication, reuse or
`run_controls(..., shard_index=0, shard_count=1)`, then exit drift checks. It
does not invoke full mode recursively or start another build.
It requires either a successful complete cold matrix or a successful probe
with a candidate and an intentionally skipped matrix. All other dependency
states fail. With a candidate, it freshly builds/audits the target then fetches
and authenticates the origin independently; probe data cannot grant acceptance.
If any origin, artifact, target-identity or eligibility check fails, record the
reason and execute the existing complete cold control runner locally in this
job, without repeating the already-successful project build. Only successful
fresh controls can then pass. Set its timeout to 180 minutes for the fresh
build, network/identity checks and complete single-runner cold controls, and
measure the cold path before declaring the issue complete. Fresh build/axiom/binding failures remain failures.

This avoids a second fresh target build on the successful reuse path. A late
rejection runs the full controls on one hosted runner and can be slower than
normal sharding; measure this cost explicitly. Earlier ineligibility retains
the eight-shard path. No probe output or skipped/failed job can green the final
check. Repository variable `PROBABILITY_FORCE_COLD=true` and a manual dispatch
which always runs cold retain explicit cold routes; local full replay is
unchanged. Only the probe and final jobs receive actions:read and
pull-requests:read alongside contents:read. Tokens enter the probe/gate parent
processes that call the API. A short-lived worker running the same trusted
transport module receives each request through stdin; credentials and signed
URLs never enter its command line. Remove GH_TOKEN and GITHUB_TOKEN from
every child environment, including this transport worker and every
proof/tool/control subprocess. The parent enforces the remaining shared
five-minute network budget with a subprocess timeout that kills and reaps
the worker, covering connection establishment, headers and body reads even
when a peer keeps making slow progress. Ordinary host process creation and
cleanup still rely on the OS scheduler. Downloaded evidence remains data only.

## Bounded delivery and acceptance

Base: `4bca0e86c67d1a86acda7783bb05ea97216246a7`. Preserve all 422 Lean source
files, 2,824 theorem statements/closures, 52 manual bindings, 1,655 existing
fixtures, compiler limits and negative-control classification. Removing branch-scoped
Actions caches narrows dependency trust; upstream mathlib artifacts remain the
existing tool TCB. No changes to
EasyCrypt, Rust sources or theorem assumptions.

Before enabling reuse, compare all 15 fields from two independent cache-free
hosted builds; mismatches keep reuse disabled and require diagnosis without
narrowing identities. Draft experiment #1003 supplies this feasibility evidence.

- R1: pure producer/receipt admission plus bounded GitHub transport and target
  linking. Negative tests cover repository/run/attempt/PR source/workflow/tree,
  ambiguous lookup, expiry/replacement/digest and raw evidence failures.
- R2: push orchestration and cold fallback. Test dependency state truth table,
  failed/skipped probes/producers, final-job dispatch, forced cold and late
  identity rejection. Enroll paths and gate-enforcement contract.
- R3: fresh full local gate; support/workflow checks; actual PR/cold and push
  reuse runs, complete raw artifact audit, measured elapsed/runner cost and
  cold fallback overhead. Preserve unchanged proof/fixture/binding bytes.

Architecture review precedes implementation. Required simultaneous reviewers
are Astra ultra and Opus 5.5 xhigh under the owner's persistent override, 900s /
800 words /16MiB each. After a recorded coordinator architecture decision, one
combined Phase D freeze follows R1-R3 implementation and local evidence. Ordered
closure checklist: exact frozen identity; mandatory full/support gates;
required implementation review and concrete blocker repair/re-review; actual
PR checks; guarded normal master landing; actual push reuse/cold measurement
and raw evidence audit; minimal issue/README receipt and independent readback.
A missing required review remains an honest gap. No optional reviewers or
#509 campaign. The deferred combined assurance remains under #509.

Use an isolated worktree, preserve canonical work and the paused CG proof
batch. Normal branch/master pushes and issue updates are within the user's
existing authorization. No hardware, shipment or irreversible action.

Rejected shortcuts: commit/tree-only matching, accepting artifact filenames or
passed flags, deleting same-run validation, suppressing push CI, and trusting
producer-supplied library archives. Signed attestations are not required for
this first API-authenticated boundary; adding them would need a separate policy.

API assumptions are checked against GitHub's official
[workflow runs](https://docs.github.com/en/rest/actions/workflow-runs),
[artifact IDs/digests](https://docs.github.com/en/rest/actions/artifacts), and
[secure-use guidance](https://docs.github.com/en/actions/reference/security/secure-use).

Dependency scope follows the documented [GitHub cache isolation](https://docs.github.com/en/actions/reference/workflows-and-actions/dependency-caching#restrictions-for-accessing-a-cache).
