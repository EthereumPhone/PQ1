# Adversarial-review findings — the catalogue

This folder is the **single repository home for adversarial-review finding
records** produced under the playbooks in the parent directory and the
[FV playbook](../../../verification/fv-adversarial-review-playbook.md). Under
the **current** workflow
([`docs/planning-and-review-workflow.md`](../../../planning-and-review-workflow.md)
§7/§7b), review evidence comes from ONE simultaneous three-reviewer wave
(gpt-5.6-sol `ultra` / Claude Opus 5 `xhigh` / Kimi K3) plus coordinator triage —
there is **no** Partner-A/Partner-B cross-adjudication step — and kept
findings are filed as GitHub issues on `EthereumPhone/PQ1`. The older
canonical-post-cross-adjudication lifecycle (raw first passes and cross
passes freezing outside the reviewed target, their digests and disposition
matrix cited here afterward) is **historical / specially-authorized-only**;
see the note at the top of [TEMPLATE.md](./TEMPLATE.md). Consistent headers
and per-finding status make it obvious which adjudicated findings have been
worked through and which remain open.

> **Sibling — confirmed-vuln writeups.** Individual *confirmed-and-fixed* vulnerability reports live in [`../../vulns/`](../../vulns/) (their own established folder, each with a fix). Those are a distinct flavor from adversarial-review *pass* reports; this folder catalogues the passes. (Consolidating `vulns/` into here is a possible future cleanup — it is heavily cross-referenced, so left separate for now.)

Reports explicitly labelled **historical**, **imported**, **pre-workflow**, or
**supplemental** in the catalogue are preserved byte-for-byte evidence from
before this canonical workflow. Their older frontmatter/status vocabulary does
not grant exact-pair completion or a current recommendation; do not rewrite
their frozen bytes merely to resemble the current template.

## How reviewed findings become repository state

> **Current workflow:** steps 1–5 below are the old exact-pair lifecycle —
> historical / specially-authorized-only under
> [`docs/planning-and-review-workflow.md`](../../../planning-and-review-workflow.md)
> §7/§7b. The current path is: one simultaneous three-reviewer wave →
> coordinator triage → one GitHub issue per kept finding. Run steps 1–5 only
> when a task-specific owner gate explicitly requires the old canonical-record
> lifecycle.

1. Both required partners write and digest independent first-pass reports
   **outside the reviewed target**. Preserve every candidate, raw origin ID,
   diagnostic, and honest residual.
2. Each partner receives the other's complete first-pass report and writes a
   separate cross-review. Freeze and digest both cross-reviews.
3. Record all four reports in
   [`CROSS_ADJUDICATION_TEMPLATE.md`](./CROSS_ADJUDICATION_TEMPLATE.md). Every
   candidate gets exactly one of `CONFIRMED`, `REFUTED`, `NARROWED`, or
   `UNRESOLVED`; disagreement is preserved, never majority-voted away.
4. Only after that matrix freezes, copy [`TEMPLATE.md`](./TEMPLATE.md) to
   `docs/security/adversarial-review/findings/<surface>-<YYYY-MM-DD>[-<run>].md`
   for the canonical post-cross record. Cite the exact first-pass, cross-pass,
   matrix, and target digests. Because cross-adjudication is already complete,
   every canonical item starts with `Status: 🔬 REVIEWED`; later resolution
   marks confirmed/narrowed items fixed, accepted, or deferred and refuted
   items invalid with evidence.
5. An authorized maintainer files the byte-identical evidence/canonical report
   in a separate reporting commit and adds a row to the catalogue. End with the
   mandatory honest residual and cross-link actionable work to the GitHub
   issue tracker (`EthereumPhone/PQ1`; the retired `docs/work-todo.md`'s
   successor — labels `source:work-todo`, `priority:*`, `surface:*`).

The report is self-describing (frontmatter + per-finding status). From this
directory,
`grep -rlE --exclude='*TEMPLATE.md' '^status: (open|in-review)([[:space:]]|$)' .`
lists filed reports with unhandled work, and
`grep -rnE --exclude='*TEMPLATE.md' '^[-*] \*\*Status:\*\* (🔲 OPEN|🔬 REVIEWED)' .`
lists their individual findings that are not closed out.

## Status lifecycle — so "handled" is unmistakable

**Per finding** (the `Status:` line on each `Fn`):

| Status | Meaning |
|---|---|
| `🔲 OPEN` | surfaced in a pre-cross/imported record, not yet cross-adjudicated |
| `🔬 REVIEWED` | cross-adjudicated — `CONFIRMED` / `REFUTED` / `NARROWED` / `UNRESOLVED` is recorded with both partners' evidence, but the item is not yet closed out |
| `✅ FIXED` | a fix landed — the **Resolution** line names the commit + date |
| `☑️ ACCEPTED` | explicit owner-only risk acceptance — the **Resolution** records owner, date, exact finding, target + frozen-report digests, accepted consequence, and scope; a reviewer, model, or ordinarily authorized maintainer cannot set this status |
| `🚫 INVALID` | false positive on re-review — the **Resolution** line says why |
| `⏸ DEFERRED` | real, but blocked (needs hardware / a design decision / another dependency) — Resolution names the blocker + the tracking item |

**Per report** (the frontmatter `status:`):

| Status | Meaning |
|---|---|
| `open` | one or more findings are still `🔲 OPEN` |
| `in-review` | all findings triaged (`🔬`/beyond), some not yet closed |
| `resolved` | **every** finding is `✅ FIXED` / `☑️ ACCEPTED` / `🚫 INVALID` / `⏸ DEFERRED` (with a tracking link) |
| `fixes-landed-production-blocked` | every code finding is handled, but a named deferred ship blocker still forbids production authority |

**When you work through a report:** for each finding you handle, change its `Status:` line, append a one-line **Resolution** (what you did / a commit SHA + date, or why invalid/deferred), and — when nothing is left `🔲 OPEN` / `🔬 REVIEWED` — flip the report frontmatter `status:` to `resolved` (or `fixes-landed-production-blocked` when a named deferred finding still forbids shipping). Only an explicit owner decision may set `☑️ ACCEPTED`; record the owner, date, exact finding, target and frozen-report digests, accepted consequence, and scope. Ordinary maintainer authority does not include risk acceptance. Reviewer consensus is recommendation evidence, never acceptance authority. Cross-link the real work to the `EthereumPhone/PQ1` GitHub issue tracker (labels `source:work-todo` / `source:production-todo`, plus `priority:*`, `surface:*`, `ship-blocker` — the retired owner-TODO files' successor); this folder is the *review record*, the issue tracker is the *action list*.

The raw first-pass reports, lossless union (if used), cross-reviews, and
cross-adjudication matrix are distinct artifacts. A union is an evidence
envelope, not a consensus engine. The reporting commit is not the reviewed
target and does not inherit its recommendation. Later resolution edits must
preserve all frozen input and matrix digests.

## Catalogue

Newest first. Add a row when you file a report; update the Status/Findings cells as you work through it.

> **2026-07-19 — actionable state lives on the tracker.** Every open finding from the reports below (and the 54 pre-cross candidates in the 2026-07-18 discovery report) is filed as a GitHub issue under [`label:finding`](https://github.com/EthereumPhone/PQ1/issues?q=label%3Afinding); the reports here remain the frozen evidence. Close items on the tracker, not by editing old report status lines — new resolutions reference issue numbers.

| Report | Surface | Date | Report status | Findings (open / handled) |
|---|---|---|---|---|
| [fv-remediation-2026-09-14](./fv-remediation-2026-09-14.md) | fv evidence acceptance | 2026-09-14–15 | `reviewed` — fresh SOL/Opus/Kimi GO; isolated landing gates pass | 8 implemented; fixes and FV prerequisites recorded for authorized branch publication; raw-counting limits remain |
| [fv-adversarial-review-2026-09-14](./fv-adversarial-review-2026-09-14.md) | fv (one bounded SOL/Opus/Kimi wave + coordinator Lean/TLC and checker reproductions) | 2026-09-14 | `in-review` | 8 retained: 6 medium / 2 low; no reproduced HIGH; [fixes implemented and reviewed](./fv-remediation-2026-09-14.md) |
| [fv-deep-review-2026-07-19-coordinator](./fv-deep-review-2026-07-19-coordinator.md) | fv (post-remediation follow-up: F1–F11 status, gate/CI enforcement, claim-vs-theorem, Kani census, doc/tracker sync; plus external SOTA research) | 2026-07-19 | `resolved` (coordinator-led deep review with executed controls + mutually withheld Opus/GPT-5.6 refutation passes; all 13 findings fixed same-day; F1's billing residual deferred to #456, Kontrol live-run to #197, research follow-ups #466/#467) | 0 open / 13 handled |
| [full-project-sweep-2026-07-19-discovery](./full-project-sweep-2026-07-19-discovery.md) | multi (second sweep; 7 lanes over the erc7730-campaign diff, 2026-07-19 fix batches, and sweep-1 blind spots) | 2026-07-19 | `open` (supplemental pre-cross discovery evidence — not cross-adjudicated, not workflow completion) | 26 open / 0 handled (tracked as issues #430–#455) |
| [full-project-sweep-2026-07-18-discovery](./full-project-sweep-2026-07-18-discovery.md) | multi (full PQSigner_OS sweep; 15 first-principles lanes over all 16 playbook surfaces) | 2026-07-18 | `open` (supplemental pre-cross discovery evidence — not cross-adjudicated, not workflow completion) | 54 open / 0 handled |
| [clear-signing-pq1-forced-blind-architecture-2026-07-16](./clear-signing-pq1-forced-blind-architecture-2026-07-16.md) | multi (clear signing, hostile companion, trusted UI/FI, lifecycle, resources, prodconfig, provenance) | 2026-07-16 | `in-review` — frozen candidate NO-GO | 20 reviewed canonical groups / 0 handled; raw matrix = 13 confirmed, 10 narrowed, 3 unresolved, 1 refuted |
| [PQ1 forced-blind architecture cross matrix](./clear-signing-pq1-forced-blind-architecture-2026-07-16-cross-matrix.md) | multi (complete symmetric cross-adjudication worksheet) | 2026-07-16 | `complete` review artifact | all 24 first-pass IDs + 3 new cross IDs; includes both bounded counterpart responses |
| [PQ1 forced-blind Partner A bounded response](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-bounded.md) / [Partner B bounded response](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-bounded.md) | multi (one-turn new-cross-candidate responses) | 2026-07-16 | frozen review artifacts | B-origin `XB-001`; A-origin raw `XB-1`/`XB-2`; no recursive exchange |
| [PQ1 forced-blind Partner A cross](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-cross.md) / [Partner B cross](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-cross.md) | multi (symmetric architecture cross-adjudication) | 2026-07-16 | frozen review artifacts | each maps all 24 first-pass IDs; both return NO-GO |
| [PQ1 forced-blind Partner A first pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-a-first.md) / [Partner B first pass](./clear-signing-pq1-forced-blind-architecture-2026-07-16-partner-b-first.md) | multi (mutually withheld exact architecture reviews) | 2026-07-16 | frozen first-pass artifacts | accepted A V5 + B V4; three discovery lanes each plus personal adjudication |
| [fv-full-stack-2026-07-15-cataloguing-receipt](./fv-full-stack-2026-07-15-cataloguing-receipt.md) | fv (post-freeze report/provenance catalogue mutation) | 2026-07-15 | `resolved` receipt | 0 findings; records immutable bytes/digests and drift |
| [fv-full-stack-2026-07-15-coordinator](./fv-full-stack-2026-07-15-coordinator.md) | fv (nine-surface executing/sourced synthesis + EasyCrypt/research roadmap) | 2026-07-15 | `open` | 11 open / 0 handled; no implementation performed |
| [fv-full-stack-2026-07-15-partner-b-cross](./fv-full-stack-2026-07-15-partner-b-cross.md) | fv (GPT-5.6 SOL `ultra` symmetric cross-adjudication; immutable raw bytes) | 2026-07-15 | `open` review artifact | maps all 21 first-pass IDs; no current-assurance promotion |
| [fv-full-stack-2026-07-15-partner-a-cross](./fv-full-stack-2026-07-15-partner-a-cross.md) | fv (Opus 4.8 `max` symmetric cross-adjudication; immutable raw bytes) | 2026-07-15 | `open` review artifact | maps all 21 first-pass IDs; axis-split verdict |
| [fv-full-stack-2026-07-15-partner-b-first-pass](./fv-full-stack-2026-07-15-partner-b-first-pass.md) | fv (GPT-5.6 SOL `ultra` mutually withheld first pass; immutable raw bytes) | 2026-07-15 | `open` first-pass artifact | 14 raised before cross; see coordinator dispositions |
| [fv-full-stack-2026-07-15-partner-a-first-pass](./fv-full-stack-2026-07-15-partner-a-first-pass.md) | fv (Opus 4.8 `max` mutually withheld first pass; immutable raw bytes) | 2026-07-15 | `open` first-pass artifact | 7 raised before cross; see coordinator dispositions |
| [multi-2026-07-15-deterministic-second-round](./multi-2026-07-15-deterministic-second-round.md) | multi (deterministic second-round validation; source-review legs discarded after visibility guard) | 2026-07-15 | `resolved` (0 new findings; does not resolve earlier reports or satisfy the required exact-pair workflow) | 0 open / 0 handled |
| [multi-2026-07-14-local-closure-review](./multi-2026-07-14-local-closure-review.md) | multi (supplemental local all-playbook closure review; no external first pass accepted) | 2026-07-14 | `open` (pre-workflow evidence; not canonical cross-adjudication or workflow completion) | 4 open / 0 handled (1 novel, 3 materially new closure paths) |
| [full-project-sweep-2026-07-14](./full-project-sweep-2026-07-14.md) | multi (full PQSigner_OS sweep; supplemental pre-workflow evidence—the required identified partner pair was not completed) | 2026-07-14 | `fixes-landed-production-blocked` (historical/imported; not workflow completion) | 0 open / 18 handled (10 fixed, 8 deferred) |
| [clear-signing-2026-07-10](./clear-signing-2026-07-10.md) | clear-signing (ERC-7730 compiler, renderer, dispatch + FI; validation continued 2026-07-12) | 2026-07-10 | `in-review` | 1 reviewed / 29 handled (28 fixed, 1 deferred; F11 awaits an owner decision) |
| [2026-07-adversarial-review-engagement](./2026-07-adversarial-review-engagement.md) | multi (playbook family build-out) | 2026-07-02..04 | `in-review` | 1 reviewed / 10 handled (7 fixed, 3 deferred; F5 awaits an owner decision) |
| [clear-signing-2026-07-02](./clear-signing-2026-07-02.md) | clear-signing (ERC-7730 + render ladder) | 2026-07-02 | `resolved` | historical pass — live bugs fixed, tracked in the clear-signing playbook + work-todo |
