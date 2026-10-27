# PQSigner OS agent entry point

This file is a router, not a duplicate project specification.

Before non-trivial work:

1. Read [`CLAUDE.md`](CLAUDE.md) for the project invariants, security contract,
   platform constraints, and code conventions.
2. Read [`docs/STATUS.md`](docs/STATUS.md) for the current evidence and ship
   frontier; follow its owner links rather than trusting duplicated status.
3. Track work on **GitHub Issues** (`EthereumPhone/PQ1`): open items carry
   `source:work-todo` / `source:production-todo` labels (both TODO files were
   retired 2026-07-19; originals are archived under `docs/archive/`), plus
   `priority:*`, `surface:*`, and `ship-blocker`. "The TODO" anywhere in
   project docs means that tracker; banking an item means filing an issue.
4. Follow
   [`docs/planning-and-review-workflow.md`](docs/planning-and-review-workflow.md)
   for planning, scope changes, convergence, and adversarial review.
5. For security-sensitive work, use the existing playbook index at
   [`docs/security/adversarial-review/README.md`](docs/security/adversarial-review/README.md)
   to identify stricter mandatory gates and the later assurance surface. Do not
   turn intersecting playbooks into separate merge-review campaigns or paste
   their catalogs into reviewer prompts. Unless a task-specific gate requires
   the full playbook now, add one combined owner-triggered playbook pass to the
   TODO before landing and leave it for a future owner-triggered session. New
   sessions must not promote that deferred sweep into the active phase merely
   because its playbooks intersect the code. Concrete unsafe traces and required
   commands cannot be deferred by relabelling them. Unrelated playbooks need not
   run.
6. **User-side firmware verification, factory SE provisioning, first-boot
   rotation, WRP staging, option-byte handling, or the FSBL:** read
   [`docs/security/user-device-verification.md` § USB path](docs/security/user-device-verification.md#usb-path-proof-of-secure-erasure-with-a-power-cycle)
   first. Owner direction 2026-10-27 (proof of secure erasure over USB with a
   power cycle, done by ST's ROM bootloader on a device shipped with empty
   flash; final SE keys installed at the factory from the per-die DHUK)
   changes several documented assumptions and is not implemented yet.

## Focus and review-cadence routing

Before implementation, name one active product surface, the current workflow
phase, the bounded slice set, and the next review boundary. Treat an explicit
user focus instruction as a scope cap: bank unrelated discoveries as GitHub
issues (the retired owner-TODO files' successor — see the routing list above)
and do not let review/process cleanup displace the
active product work unless it is a concrete blocker for that work.

The workflow linked above solely owns phase-boundary review batching, batch
bounds, per-slice evidence, and early-stop triggers. Follow those rules rather
than initiating adversarial review after every slice. Do not start a second
product surface before the active phase reaches its recorded stopping point.

Once Phase D starts, enter the workflow's **closure mode**. Treat its recorded
completion checklist as closed: run the stage-relevant mandatory gates, freeze,
review, remediate stage-blocking findings, re-freeze/re-review when required,
and land. Do not add optional reviewers, broader assurance campaigns, process
rewrites, documentation polish, or unrelated hardening unless the user explicitly
requests it, a task-specific owner gate required it before the freeze, or a
concrete workflow expansion trigger makes it a blocker. If closure stalls, report the exact
blockers and shortest compliant path before starting more work.

Phase D uses one short, simultaneous three-reviewer wave under the workflow's
hard wall-clock and output bounds. The reviewers are GPT-5.6 SOL, Claude Opus
5, and Kimi K3. Give all three the same small, clear-context prompt. Do not
build a packet dossier or run pairwise/cross-adjudication. The workflow's
Section 7 governs focused completion of missing mandatory answers and explicit
owner-selected reviewer changes. Keep unresolved answers as honest gaps.

Multiple intersecting playbooks do not create more reviewer prompts, campaigns,
or phase boundaries. Reviewers derive threats from the source and invariants in
fresh contexts; catalogs and prior verdicts are not initial prompt material.
The coordinator reconciles the three compact reports against task-specific
gates, reproduces concrete blocker claims locally, and banks non-blocking
observations. Disagreement does not launch another model round.

## Security-review surface routing

Five cross-cutting playbooks complement the subsystem-specific and formal-
verification playbooks:

- [lifecycle, provisioning, persistent state, recovery, and RMA](docs/security/adversarial-review/lifecycle-persistent-state-adversarial-review.md)
- [entropy, key generation, derivation, nonce, and key lifecycle](docs/security/adversarial-review/entropy-key-lifecycle-adversarial-review.md)
- [secure runtime, resources, exceptions, concurrency, and unsafe code](docs/security/adversarial-review/secure-runtime-resource-adversarial-review.md)
- [production configuration, prodtest, and assurance fidelity](docs/security/adversarial-review/production-configuration-prodtest-adversarial-review.md)
- [build, release, provenance, signing-key custody, and distribution](docs/security/adversarial-review/build-release-provenance-adversarial-review.md)

These lenses are additive when the combined playbook pass runs. A fast
source-only merge review records that deferred assurance honestly and must not
imply hardware, shipment, or irreversible-action authority.

Task-specific normative specifications, authorization boundaries, and explicit
owner decisions take precedence over the generic workflow and may require
additional reviewers or evidence.

The workflow is the sole owner of the project's YAGNI/exploration balance,
scope-expansion triggers, evidence ladder, three-reviewer runtime configuration,
review-batching and convergence rules, and irreversible-action planning gates.
Do not restate or weaken those rules here. Before starting a security-sensitive
implementation or review, identify and follow the applicable workflow stage and
any stricter task-specific gate.

If this file conflicts with a more specific owner document, stop and surface
the conflict rather than choosing silently.
