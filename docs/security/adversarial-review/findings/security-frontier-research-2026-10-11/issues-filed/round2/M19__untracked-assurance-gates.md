TITLE: Enrol the binary never-ship audit in CI with a two-sided control, give a red nightly a consequence, and add image-level FI and glyph-leak regression checks
LABELS: enhancement,priority:high,surface:release,surface:sca-fi,source:frontier-research-2026-10
---
## Summary

A check that exists in the tree but runs in no workflow protects nothing: a refactor can reopen the hole it was written for and still merge green. Most gates of that kind already have an issue (listed below). This issue collects the ones that do not. The largest is the binary never-ship audit, the only check that looks at a built firmware image and not at its build inputs. It was written, closed as done in #604, and is called by no workflow. The others: a scheduled job that fails changes nothing today, no tool checks that fault-injection (FI) countermeasures survive in the linked image, the glyph-rendering leakage test is manual and does not cover the pixel UI, and the real Bybit transaction is replayed only against hardware.

## What the code does today

- `Makefile:4469`: `prod-symbol-audit` is a local target. A search of `.github/workflows/` for `prod_symbol_audit` and `prod-symbol-audit` finds no caller, and `scripts/gate_enforcement.json` has no row for it.
- `scripts/prod_symbol_audit.sh:27`: the script's positive controls require the hardware random-number receipt and the complete STM32, OPTIGA and SE050 source-set receipt. The only firmware image CI links is `make build-hw` (`.github/workflows/ci.yml:477`), which is a mock secure-element test image (`Makefile:398`). The research's reviewer reports that this image fails those positive controls, so it cannot be the audited image. I did not run the script.
- `scripts/prod_symbol_audit.sh:36`: the script says itself that absence of a symbol is weak evidence, because link-time optimisation can inline a function out of the symbol table. Only the random-number backend has a marker that survives that: a byte string in its own linker section, tied to the same `cfg` as the code (`secure/src/rng.rs:20`).
- `.github/workflows/nightly.yml:34`: the nightly runs on a schedule. No workflow has a step that opens an issue or blocks anything when a scheduled job fails (a search of `.github/workflows/` for `gh issue`, `create-issue` and `if: failure()` finds nothing). #776 records that the nightly Kani job has not completed since at least early September.
- No script or workflow inspects a linked image for the FI primitives: a search of `scripts/`, `tools/*.sh`, `tools/*.py`, `.github/` and the `Makefile` for `check_true_into_sentinel`, `read_volatile_voted` and `FihBool` finds nothing.
- `tools/sca/Makefile:240`: `glyph-leak` is a manual target that tests the legacy 16x4 secret glyph path. No workflow runs it, and there is no equivalent for the pixel UI.
- `tools/demo_bybit_replay.py:2`: the byte-exact replay of the February 2025 Bybit Safe transaction is a script that drives a physical device. The behaviour it demonstrates (refusing a DELEGATECALL to a target that is not an allowlisted MultiSend contract) does have host tests under other names, for example `secure/src/tx/eip712/safe/extra_tests.rs:964`. The real transaction's bytes appear nowhere in the Rust sources.

## What is already tracked elsewhere

- #777 and #130 (with the comments of 2026-10-12): the `fi_min` fix and its missing gate script.
- #725: wiring the never-run-tests oracle into `make` and CI. #720, #721, #722, #724: the test suites that run nowhere, including running the bootloader geometry gate.
- #690 and #701: calling the gateway address check from the build recipes.
- #776: the nightly Kani job that never completes. #312: making the constant-time check a real gate.
- #456 and #558: CI results are advisory because `master` has no required checks.
- #865: the FI emulation harnesses that do not build, and a CI job that at least compiles them. #591, #633, #211, #232, #592, #296, #335: the FI sweeps themselves.
- #784 and #858: the glyph-path defects. #735: the feature denylist covers one of three firmware crates. #189, #635, #680: reproducibility and fuzz enrolment.

#648 mentions the audit script only as one lens of a deferred review pass; it does not ask for CI enrolment.

So this issue is only about the items below.

## Proposed work

- [ ] **Binary audit, absent leg.** In the firmware job, build a release-shaped dual secure-element image (no `mock-se`, no `e2e-test`) and run `scripts/prod_symbol_audit.sh` on it. It needs its own build; the `build-hw` image cannot serve.
- [ ] **Binary audit, present leg.** Add a mode that must find the forbidden content in the mock and end-to-end image. Without it, a green absent leg can mean "the names were inlined away".
- [ ] **Markers for the other never-ship features.** Extend the section-retained, `cfg`-coupled marker pattern that the random-number backend uses to `mock-se`, `e2e-test`, `otp-hardcoded-master-key` and `ui-capture`, so the audit does not depend on symbol names.
- [ ] **A consequence for a red scheduled job.** Choose one and write it down: an automatically opened issue on a failed scheduled run, or a release gate that requires the last nightly for that commit to be green. Today a scheduled failure is only visible to someone who goes looking.
- [ ] **FI primitives in the linked image.** On the linked dual secure-element image, check that each instance of the FI primitives keeps its redundant evaluation and the sentinel compare. #777 records why counting call sites is wrong at `opt-level = "z"` (the outliner merges identical call sequences), so the check must follow calls transitively. Give it a two-sided self-test. `fi_min` lives in the non-secure image and needs its own leg.
- [ ] **Glyph-leak in the nightly.** Run `make -C tools/sca glyph-leak` on a schedule, and add a pixel-UI harness with two subjects: the secret-run blit, and the entry-row path that draws the live PIN digit and seed letters. Gate on the memory-address model only and report the Hamming-weight result as a number. The entry-row subject is expected to fail until #784 and #858 are fixed; that is the point of having it.
- [ ] **Bybit transaction as a fixed vector.** Add the byte-exact SafeTx from `tools/demo_bybit_replay.py` as a named vector to the existing DELEGATECALL-refusal host tests, so the named real-world case is caught without a device. Small, and the lowest priority item here.
- [ ] Declare every gate added here in `scripts/gate_enforcement.json` in the same change.

## What it needs

CI and host tooling only. No hardware and no board change. The glyph-leak and image-level FI jobs need the emulation toolchain on the runner. If a self-hosted runner is used for long jobs, restrict it to scheduled and manual triggers, because the repository is public.

## Limits

- This adds no on-device defence. It keeps existing defences from regressing unnoticed.
- A true production image cannot be built today (the OPTIGA S-2 fence blocks it by design), so every image-level gate runs on the closest release-shaped image and must be re-run when S-2 closes. A green run means "this image is clean", not "production is clean".
- While `master` has no required checks (#456, #558), every per-push result is advisory. The research notes that required checks conflict with pushing directly to `master`: they force pull requests or a merge queue. That is an owner decision and is not part of this issue.
- Emulation does not model the hardware hash peripheral. Glyph-path leakage is unmeasured today; the gate would give the first number.
- The research also proposed five more named must-refuse vectors for the default test lane. I did not check which of them already have tests, so they are not listed.

## Related

#604 (closed: created the audit as a local target), #777, #130, #725, #720, #776, #456, #558, #865, #784, #858, #312. Precedent cited by the research: Trezor scans release binaries for a mock random-number marker in CI; Ledger runs emulated fault sweeps in CI ([rainbow](https://www.ledger.com/blog/fault-injection-simulation)); the [TF-M fault-injection hardening design](https://nrfconnectdocs.nordicsemi.com/ncs/latest/tfm/design_docs/tfm_physical_attack_mitigation.html) warns that optimisation removes redundant checks. I did not re-fetch those sources.

---
<sub>**Provenance.** Security frontier research, 2026-10-11 (report item M19, section 11). Report priority P1 is a research rating, not an owner decision. Code lines re-read at master `c2fab970` on 2026-10-12. Evidence: code reading and public sources; nothing was run on silicon. Report: `docs/security/adversarial-review/findings/security-frontier-research-2026-10-11.md`, committed on branch `docs/security-frontier-research-2026-10` and not yet on master when this was written, so this text is meant to stand alone.</sub>
