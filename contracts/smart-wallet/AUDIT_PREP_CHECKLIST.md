# PQSmartWallet — Audit Prep Checklist

Status against Trail of Bits' audit-preparation checklist, updated 2026-10-20
for the audit freeze. The 2026-05-22 version of this file is in git history.

## The package

| Document | What it is for |
|---|---|
| `AUDIT_SCOPE.md` | Start here: frozen revision and bytecode identity, files in scope, changes since the internal review, dependencies, build and expected results, interfaces, reading order |
| `AUDIT_REVIEW_GOALS.md` | Security objectives, areas of concern, worst cases, accepted residual risks, questions |
| `AUDIT_DIAGRAMS.md` | Flows, actors and privileges, invariants and where each is checked, glossary |
| `AUDIT_STATIC_ANALYSIS.md` | Slither triage, coverage, contract sizes, dead code |
| `TOB_INTAKE.md` | Answers to the intake questionnaire |
| `README.md` | System overview, build and test |
| `AUDIT_2026-05-18.md`, `AUDIT_2026-05-18_CROSS_CHECK.md` | The earlier internal review; a note at the top lists what has changed since |

## Step 1 — Review goals

- [x] Security objectives (`AUDIT_REVIEW_GOALS.md` §1)
- [x] Areas of concern, most worrying first (§2)
- [x] Worst cases (§3)
- [x] Accepted residual risks, so they are confirmed rather than re-reported (§4)
- [x] Specific questions (§5)

## Step 2 — Resolve the easy issues

- [x] Every open decision that would change the bytecode after the audit is
  taken and implemented:
  - owner removal deleted (#131, #213);
  - guard hook declined (#867);
  - legacy EIP-1271 entry added (#995);
  - raw-hash EIP-1271 workflows closed (#691);
  - ERC-721 / ERC-1155 receiver hooks added.
- [x] `forge test`: 149 passed, 0 failed, 2 skipped (both skips expected; `AUDIT_SCOPE.md` §6)
- [x] Deploy-profile pin tests: 7 passed. CI runs them on every PR, binding the production build to the firmware's CREATE2 constants (#672).
- [x] Slither 0.11.6: 28 results, no untriaged Medium or High; a hard CI gate (`AUDIT_STATIC_ANALYSIS.md` §1)
- [x] Coverage measured (`AUDIT_STATIC_ANALYSIS.md` §2)
- [x] Dead code: none, apart from the intentional `_erc1271Signer` tripwire
- [x] Halmos: 43/43 rules on both compiler profiles (`../verification/halmos/sessions/halmos-session-2026-10-20.txt`)
- [x] Kontrol: 31/31 proofs (`../verification/kontrol/sessions/kontrol-session-2026-10-20.txt`)
- [x] Lean models and proofs updated for the freeze; the FV gates pass
- [ ] 4naly3er, aderyn and Mythril were not run. Slither is the static-analysis gate.
- [ ] Certora: the specs under `certora/` are historical and were never run against the current code. They are not part of the package.

## Step 3 — Code accessibility

- [x] Files in scope, the out-of-scope tree, and dependencies with exact revisions (`AUDIT_SCOPE.md` §2, §4, §5)
- [x] Build instructions with the exact lib restore (`README.md`), checked on a workstation set up like CI (Foundry v1.8.3, the exact `foundry.lock` lib set)
- [x] Forked code identified: Coinbase Smart Wallet at `503363d7`, with what was removed and added (`TOB_INTAKE.md` §3)
- [x] Frozen version: annotated tag `tob-audit-freeze-2026-10`, commit hash in the tag message
- [x] Stale documents fixed or removed: `README.md` rewritten, `PQ_README.md` (an older design) deleted, the internal review marked

## Step 4 — Documentation

- [x] Sequence diagram of deploy, rotation and signing (`AUDIT_DIAGRAMS.md` §1)
- [x] Flowcharts of validation, execution, the factory and EIP-1271 (§2–§5)
- [x] Actors and privileges (§6)
- [x] System and function invariants, with the test or proof that checks each (§7)
- [x] Glossary (§8)
- [x] NatSpec on the public functions
- [x] The off-chain interfaces the contracts must match (`AUDIT_SCOPE.md` §7)

## Owner actions outside the audit package

1. **Deploy the freeze set**, Base first, with the deployer key:
   `FOUNDRY_PROFILE=deploy forge script script/DeployImplAndFactoryBaseMainnet.s.sol --rpc-url <rpc> --account <name> --broadcast`.
   The script refuses to broadcast unless the addresses match the firmware constants.
2. **Verify the sources on Basescan** and compare each on-chain codehash with `AUDIT_SCOPE.md` §1.
3. **Hold back firmware built from the freeze commit** from any device that has to transact on chain until step 1 is done. That firmware predicts wallet addresses from the freeze set, which has no code on any chain yet.
4. **Update the companion repositories'** factory constant: AmbireExtension, pq1-sdk and pq1-companion.
5. **Decide #638**, the inert upstream workflow files under `.github/`.
