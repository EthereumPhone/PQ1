# Raw data for security-frontier-research-2026-10-11

Evidence behind `../security-frontier-research-2026-10-11.md`. Every file was produced by a research agent reading code, docs, issues or public sources. Nothing here was run on silicon. Line numbers refer to the working tree described in the report header.

| Path | Content |
|---|---|
| `final/master.json` | The 51 consolidated items with final status, priority, cost, kind and tracked issues |
| `final/surface_<surface>.json` | Which items each report section covers |
| `final/critic_round.json` | Completeness critic output, the 19 extra proposals and their skeptic verdicts |
| `round2/cluster_<key>.json` | One merged recommendation (`merge`) and its independent review (`skeptic`) per duplicate cluster |
| `imp/<ID>.json` | The 110 original proposals |
| `verify/<ID>.json` | Verification verdicts per proposal, keyed by lens |
| `inv_<surface>.json` | What pq1 has today, its gaps and claim-versus-code drift |
| `trezor_<surface>.json` | Trezor measures with `path:line` in trezor-firmware at `6ab39e95` |
| `gaps_<surface>.json` | Gap-analyst output per surface |
| `lit_all.json` | Sourced literature and vendor claims with URLs |
| `deep_research.json` | Fact-checked digest on hardware implants and display exfiltration |

Surfaces: implant, display, fi, sca, clearsign, boot, se, pin, fwupdate, usb, systemic.

## Added 2026-10-12 (focused pass and issue filing)

| Path | Contents |
|---|---|
| `focused/verify_se_pin_wipe_FINAL.md`, `focused/verify_boot_trustzone_FINAL.md`, `focused/verify_ui_fi_tooling_FINAL.md` | The three refute-briefed re-checks of defect rows at `c75b0d9c`, run before any issue was filed (45 rows: 32 confirmed, 12 partly, 1 refuted) |
| `focused/onchain_prior_art_report.txt`, `focused/onchain_prior_art_sources.txt`, `focused/onchain_prior_art_FINAL.md` | Prior-art survey behind report section 13 |
| `focused/onchain_design_review_gpt.md`, `focused/onchain_design_review_prompt.txt` | Independent adversarial review of the first draft of section 13 (GPT through the codex CLI) and the brief it was given |
| `focused/tamper_prior_art_report.txt`, `focused/tamper_prior_art_FINAL.md` | Survey of shipped tamper hardware and unpowered tamper detection behind section 14 |
| `issues-filed/NN-*.md` | The body of each issue as drafted (placeholders `{{NN}}` stand for sibling issues) |
| `issues-filed/c-NNN-*.md` | Each comment as posted on existing issue NNN |
| `issues-filed/filed.json` | Draft key to GitHub issue number and URL |

The issues cite master `0feea78a` line numbers. The report body cites `c75b0d9c`, an ancestor of that commit.

## Added 2026-10-12 (second pass: recommendations filed)

| Path | Contents |
|---|---|
| `issues-filed/round2/<KEY>__*.md` | The body of each of the 26 issues filed in the second pass, as filed (`{{KEY}}` stands for a sibling issue). `KEY` is the report item, or `H1` / `H2` for the two issues that came from the hardware asks and the open-question lists |
| `issues-filed/round2/c-<N>__<KEY>__*.md` | Each of the 50 comments, as posted on existing issue N |
| `issues-filed/round2/BRIEF.md` | The brief every reviewer was given |
| `issues-filed/round2/dispositions/<group>.json` | Per reviewer group: the outcome for every report item, the sub-actions and which existing issue covers each, the cited master lines with snippets, the untracked measurements and the new defects found |
| `issues-filed/round2/filing.log`, `ORDER.txt` | Filing order and the tool output |
| `issues-filed/round2/*.py` | The filing script and the two citation checkers |
| `issues-filed/filed.json` | Now also holds the second pass, under keys that start with `r2:` |

The second-pass issues and comments cite master `c2fab970`. Report section 16 has the item-to-issue map and the corrections this pass made to the report.

## Edits to the raw data (2026-10-12)

Two reviewer outputs were edited after they were first committed, because `make -C contracts/verification verify-hw-assumptions` treats every `HW-ASSUME-<ID>` string in the tree as a reference to a ledger row and failed CI on these two:

- `inv_se.json`: a wildcard over the three PUTKEY rows (the ledger prefix followed by `PUTKEY-*`, twice) now names them: `HW-ASSUME-PUTKEY-ATOMIC`, `HW-ASSUME-PUTKEY-KCV-RESP`, `HW-ASSUME-PUTKEY-REPUT-IDEMPOTENT`.
- `verify/FI-01.json`: an identifier that does not exist (the ledger prefix followed by `U585-REV`) now reads `HW-ASSUME-REV-U`, the ledger row for the die revision.

Nothing else in the raw data was changed.
