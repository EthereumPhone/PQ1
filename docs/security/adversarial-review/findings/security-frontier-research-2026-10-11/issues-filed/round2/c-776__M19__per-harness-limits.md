COMMENT_ON: 776
---
**A structural suggestion from the 2026-10-11 security frontier research (item M19), on top of fixing the individual harnesses. Lines re-read at master `c2fab970`.**

The nightly still runs every Kani harness of every crate as one `make` recipe inside one job step: `.github/workflows/nightly.yml:88` runs `make kani` under a 300-minute job limit (`.github/workflows/nightly.yml:56`), and the recipe is a sequence of whole-crate runs (`Makefile:4603` for ERC-7730, then `Makefile:4605`, `Makefile:4608`, `Makefile:4610` and the pixel-UI crate last at `Makefile:4646`). One harness that does not terminate therefore takes the job, and every crate after it, with it. Reordering the crates and compiling out the known offenders fixed the instances found so far, but the next non-terminating harness will do the same thing. `erc7730_ir_parse_panic_free` (`pqsigner-erc7730/src/ir.rs:3398`) is the current one, per the comment of 2026-10-05.

The research's reviewer also reports that the 2026-10-10 Kani and Kani-mutation runs both ended with the runner being shut down inside a harness, which looks like memory exhaustion and not the job timeout. I did not read those run logs. The job already has a step that prints out-of-memory evidence afterwards (`.github/workflows/nightly.yml:89`), so the logs should settle it.

Suggested additions:

- [ ] Give each harness, or at least each crate step, its own wall-clock limit and memory limit, so a blow-up turns one harness red and the rest still report.
- [ ] Run the crates as separate jobs, so one crate cannot starve another of the job's time budget.
- [ ] Decide what a red nightly causes. Today nothing does: no workflow opens an issue or blocks a release on a failed scheduled run. That part is in {{M19}}, since it applies to every scheduled job and not only Kani.

Not checked: whether Kani can be given a per-harness limit directly or needs a wrapper, and how much the split costs in runner minutes.

<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M19, section 11). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading; the CI run logs were not re-read and nothing was run. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
