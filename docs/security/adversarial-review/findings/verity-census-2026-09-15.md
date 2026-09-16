# Verity assurance census remediation — 2026-09-15

## Verity follow-up selected — 2026-09-15 (#673)

Active surface: Verity assurance census. Phase B/C is limited to three slices:
(1) compile all eight Part B modules in fresh isolated output and inspect every
exported declaration's transitive axiom closure, with exact axiom identities and
an identity/type/body pin for the one existing admitted declaration;
(2) bind all five unbuildable Part A source files by exact path and bytes,
including the factory assumption and eleven existing source holes, reporting
this quarantine as unverified rather than as a semantic proof result;
(3) wire the complete gate into blocking CI, preserve the raw census as a
conservative backstop, and correct the contradictory Verity build/trust claims.
No proof body, parameter, firmware or contract behavior is in scope.

Acceptance requires actual gate controls for named/private/metaprogrammed and
transitively consumed admissions (including `stop`), added/changed axioms,
relocated or enlarged baseline holes, unbuilt/orphan files, stale outputs,
source/environment/manifest drift, and positive closed proofs. The fresh build
uses only the pinned Lean distribution plus copied Part B source; project Lake
caches and the unavailable Part A dependency cannot grant evidence. Part A
remains frozen until its separate port is explicitly selected.

The next boundary is one combined candidate freeze after the focused controls,
Verity ci and relevant FV/CI wiring checks pass, followed by the mandatory
bounded SOL/Opus/Kimi wave. No per-slice review or broader assurance campaign is
added. The existing combined owner-triggered playbook remains deferred in #509.

## Implementation boundary

`make -C contracts/verity verify-verity-census` now uses a temporary source copy,
the installed Lean 4.22.0 compiler at revision
`ba2cbbf09d4978f416e0ebd1fceeebc2c4138c05`, and fresh output for every Part B
module. It inventories 213 exported declarations, including private/generated
ones, and all 15 environment axioms. Every project declaration's full transitive
closure is checked. The two Hash axioms have exact identity/type pins. The sole
admitted Part B helper has identity/type/body pins and cannot lend its allowance
to a new dependent. Five compiler-generated partial helper identities are also
fixed. The 12 raw source mentions remain a conservative backstop.

Part A's five source hashes cover its eleven holes and the source-only CREATE2
axiom without claiming elaboration. Unlisted Lean sources, links, changed inputs,
changed axiom signatures and changed admitted obligations fail the gate. The
installed compiler/stdlib, gate and reviewed baseline remain trusted. This is
not an independent kernel check or an audit of transient anonymous examples.
No existing Lean proof source changes in this remediation.

The dedicated `verity-fv.yml` workflow invokes both the census and executable
controls on changes to their full source/tooling surface. The new target is
enrolled in the gate-enforcement manifest. `verify-stats` delegates to this same
census; the previous multiline grep statistics are removed. Trust documentation
now explicitly says that the Part A obligations are not verified.

## Phase C evidence / Phase D closure checklist

Green on the combined candidate: `make -C contracts/verity ci` (fresh census,
six existing raw-inventory regression groups, nine semantic-census groups with
compiler-backed negative controls); `python3 scripts/check_gate_enforcement.py`
(all 33 enrolled gates); its `--self-test`; and
`actionlint .github/workflows/verity-fv.yml`. The semantic groups took 170.900 s.
These are local E1/E2 results, not a hosted CI or deployment receipt.

Closure now consists only of freezing this combined candidate, the mandatory
simultaneous 900-second/800-word SOL/Opus/Kimi merge wave, coordinator reproduction
of concrete blockers, and atomic landing after convergence. Source remediation
would require a new frozen wave. No full playbook sweep or proof discharge is
added; #509 remains owner-triggered and deferred.

## First wave and reproduced correction

The first frozen candidate was `789b8e1ff35110590a0cc5c9177de9869e3464f6`,
tree `4f07e82949f7a6f5962807736db637727211f011`, compared with
`ebb590d0ffd2b84b2b07939c85fd31af8e0b8412`. Opus returned FIX (256.601 s,
325 words), Kimi GO (429.833 s, 345 words). SOL's first leg could not execute
any source command because nested Bubblewrap namespace creation failed; it was
stopped after eight identical mechanical failures. Its one documented Landlock
retry executed source commands but timed out at 900.172 s without a report.
There is no completed SOL verdict for that candidate. Both launcher receipts
report no target drift. Kimi's ordinary statement-pinning limitation is outside
the census claim. Opus's branch-protection observation is a hosted-settings gap,
not evidence that the source workflow can pass after gate failure.

Coordinator reproduction confirmed Opus's blocker: adding
`census_unchecked_false : False := True.intro` through `addDecl` with
`debug.skipKernelTC true`, then a derived False theorem, compiled and passed the
first census with 217 declarations and an empty axiom closure on both invalid
claims. A trust-level-zero import is not a kernel replay.

The smallest complete correction adds the version-matched upstream
lean4checker replay before the census, seeded solely from trusted Lean stdlib
constants. Existing stdlib names must retain their full constant metadata;
all other names enter replay/census regardless of claimed module origin.
The 208 safe, non-partial Part B constants are kernel-rechecked. Five existing
partial compiler helpers remain explicitly census-only and unsafe declarations
are rejected. The unmodified 176-line upstream replay and its license are
vendored at a pinned commit; no network dependency is added. This increases the
checker TCB and adds one executable kernel-bypass regression. Banning a literal
option or import was rejected as an incomplete source-token workaround.

This reproduced unsafe trace is the workflow Section-5 trigger and changes the
proof-evidence boundary within #673's existing scope. It invalidates the first
candidate's recommendations. No additional owner authority is needed. The
corrected candidate receives the same bounded three-reviewer wave after the
focused gates pass. No broader campaign is added.

The corrected combined `make -C contracts/verity ci` is green: the fresh census
reports 213 exported / 208 kernel-rechecked declarations, the existing six raw
regression groups pass, and all ten semantic groups pass (207.677 s), including
the exact unchecked-False injection. Gate enforcement remains green for all 33
entries. The upstream replay bytes match SHA-256
`0c17b9b3f3bd225167b5c04abe820ca9231eaee33eba4ae163aec9cc67cfdd63`.

## Second wave and module-union correction

Candidate `6096de0b6620a55a52da98298d155620dc5d51db`, tree
`47b7c15cc76d12eb474ceef69520d08867822575`, compared with the same base, received
Opus GO (462.687 s / 491 words), Kimi GO (304.353 s / 341 words), and SOL FIX
(741.192 s / 106 words). SOL again required one mechanical Landlock retry after
two source commands failed before execution under nested Bubblewrap. All final
reports named the frozen identity; neither launcher recorded target drift.
The reviewers' test-execution gaps are covered by the coordinator's complete
local regression run. Opus's unprobed compiler-time filesystem-authority note
is a deferred build-assurance question, not a reproduced stage blocker; the
trust document now explicitly states that this gate does not sandbox Lean IO.

Coordinator reproduction confirmed SOL's declaration-coalescing finding:
`Wots.lean` can declare an axiom named
`PQSigner.Verifier.Merkle.auth_path_depth_eq_SUBTREE_H`, with the same type as
Merkle's theorem. Both modules compile, but Lean's aggregate import subsumes the
axiom with the theorem. The old census then passes with 213 declarations and 15
environment axioms, losing the sibling module's axiom provenance.

The smallest correction inspects the original private `ModuleData` retained in
the imported environment header. All eight modules' name/info arrays must agree;
project names cannot duplicate one another or redeclare stdlib names; and the
aggregate non-stdlib constants must match this complete union. Module ownership
comes from those original arrays. Rejecting duplicates also covers identical
cross-module declarations; callers should reference the existing declaration.
A per-module repeated full compiler/replay pipeline was considered unnecessary:
retained original data already supplies the lost information without extra
builds. This adds 29 collector lines and one executable sibling-module regression,
with no extra dependency or owner authority. The unchanged baseline and the
focused new regression are green. The reproduced census mismatch is the
Section-5 trigger; it invalidates the second candidate's recommendations and
requires the same bounded wave on the corrected combined snapshot.

The combined module-union correction passes `make -C contracts/verity ci`:
six raw regression groups plus eleven semantic groups (235.454 s), including
both the sibling declaration case and the kernel-replay case. The baseline
remains 213 exported / 208 kernel-rechecked declarations, 15 environment axioms,
one admitted Part B declaration, and five unverified Part A sources. Gate
enforcement remains green for all 33 entries. This is the next combined freeze.

## Final wave and landing boundary

The corrected source candidate `fdabe5eb9b953706681b1276eba3d3c48db12c2e`, tree
`839e6bf8d646c34048ff90b1c5211c8b68ad764e`, compared with
`ebb590d0ffd2b84b2b07939c85fd31af8e0b8412`, received GO from all three required
reviewers: Opus 406.775 s / 58 words, Kimi 543.565 s / 330 words, and SOL
715.519 s / 10 words. Their prompts were identical. SOL's first attempt stopped
after two pre-execution nested-Bubblewrap namespace failures (61.450 s); the
one documented mechanical retry used the same model and read-only candidate/Git
mounts with the Landlock backend. Runtime receipts include the explicit CLI
model/effort requests. Neither launcher recorded target drift. The suspend-aware
clock was retained, and every completed report was within 900 seconds/800 words
and named the exact target. Raw reports and receipts are retained under
`verity-census-2026-09-15/review3*`.

SOL reported no gaps. Kimi did not rerun the complete CI suite; the coordinator's
executed 17-group run covers that evidence gap. Its stated runtime concern is
not a measurement: the recorded eleven semantic groups took 235.454 seconds.
Kimi included supporting source notes beyond the compact verdict fields; those
raw bytes are preserved, and its verdict, target and limitations are unambiguous.

Opus reported an unproven raw-`quotInfo` lead: replay calls `quotDecl` without
checking that supplied metadata, but its attempted exported-module fixture
failed and it found no dependent accepted by replay. Coordinator source
inspection confirms that replay branch; no successful exported counterexample
is available. This is banked in the existing deferred #509 pass, alongside the
compiler-time IO/custody, ordinary statement-claim coverage and hosted-settings
questions. It is not a reproduced blocker or owner risk acceptance. There are
no coordinator-confirmed outstanding merge blockers or mandatory review gaps.

The working-tree integration preserves all 113 earlier work items; the shared
gate manifest receives only the new Verity entry. Its combined 63-entry gate
check and the fresh integrated Verity census pass. The committed manifest stages
only the reviewed 33-entry base-plus-Verity version, leaving the user's other
manifest changes unstaged. Source bytes match the final reviewed candidate;
only this coordinator receipt and raw evidence are added after the freeze.
Those evidence additions are non-material under workflow Section 10.

This closes #673's census/enforcement defect, not the twelve existing proof
holes. Part A remains uncompiled/unverified, and the existing partial helpers
remain census-only. No proof body changed. The source review and local E1/E2
checks supply no hardware, hosted-CI execution, implementation-equivalence,
shipment or irreversible-action evidence. The combined assurance pass in #509
remains deferred until an owner selects it.
