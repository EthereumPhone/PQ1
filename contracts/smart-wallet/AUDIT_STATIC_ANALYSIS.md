# PQSmartWallet — Static Analysis, Coverage, Dead Code

Updated 2026-10-20 for the audit freeze (`AUDIT_SCOPE.md` §1). Tools:
Foundry v1.8.3 (the CI pin), slither-analyzer 0.11.6, solc 0.8.28. The
2026-05-22 version of this file is in git history.

---

## 1. Slither

Slither is a hard CI gate at Medium severity: the `Slither (contracts static
analysis)` job of the repository-root `.github/workflows/ci.yml`. The
configuration is `slither.config.json` (filter paths `lib/|reference/|test/|script/`,
`exclude_dependencies`, `fail_on: medium`), so `slither .` in this directory
reproduces CI. Workflow files under `contracts/smart-wallet/.github/` never
run: GitHub executes workflows only from the repository root.

Freeze run: **15 contracts, 102 detectors, 28 results, none of them an
untriaged Medium or High.**

### Triaged Medium findings

Three Medium findings are suppressed individually in `slither.db.json`, which
keys on the finding rather than the detector, so a new instance of the same
detector anywhere else still fails the build. Slither's finding IDs include
line ranges, so the two entries in `PQSmartWallet.sol` were re-keyed when the
freeze moved their lines; the reasoning is unchanged.

| Finding | Where | Why it is not a defect |
|---|---|---|
| `uninitialized-local` — `ok` | `PQSmartWalletFactory.createAccount` (line 106) | `bool ok;` is assigned in both arms of the `try`/`catch` that follows (`ok = v` / `ok = false`) before its only read. Slither does not model try/catch assignment. Even if it were right, the read is `if (!ok) revert InvalidFactorySignature()`, so the failure mode is refusing a valid deployment, never accepting an invalid one. |
| `divide-before-multiply` | `PQSmartWallet._validateSignature` and `_erc1271IsValidSignatureNowCalldata` | `((C10_SIG_LEN + 31) / 32) * 32` rounds a compile-time constant (`C10_SIG_LEN = 4008`) up to a 32-byte word (4032). The truncation is the intent and there is no runtime input. |

The suppressions live in `slither.db.json` rather than as
`// slither-disable` comments in the sources. Since the build sets
`bytecode_hash = "none"`, a comment would no longer move the codehash, but the
external file keeps the sources free of tool annotations.

### The remaining 28 results (Informational / Low / Optimization)

| Detector | Impact | Count | Where | Assessment |
|---|---|---:|---|---|
| `calls-loop` | Low | 1 | `executeBatchWithOffchainCount` | Calling each signed target in turn is the purpose of the batch. Any failing call reverts the whole batch, and nothing runs after the loop. |
| `reentrancy-events` | Low | 1 | `PQSmartWalletFactory.createAccount` | `AccountCreated` is emitted after `account.initialize(...)` on the proxy the factory just created, whose code is the wallet implementation. Only the event order is affected. |
| `assembly` | Informational | 14 | wallet, owner table, verifier | Deliberate: parsing the fixed-layout signature wrapper and calldata words, the transient credit slots, the ERC-7201 storage pointer, owner-key words, revert-data bubbling, and the Yul verifier. |
| `low-level-calls` | Informational | 3 | both execute paths, `validateUserOp` | The execute paths call the signed target and bubble its revert data. `validateUserOp` pays `missingAccountFunds` to the EntryPoint and ignores the result, as the v0.6 reference account does; the EntryPoint checks the deposit. |
| `too-many-digits` | Informational | 6 | verifier, wrapper parsing | 256-bit mask literals: the wrapper's 24-byte tail-pad mask (twice), the verifier's N-mask and two address-field masks, and the `Error(string)` selector word. |
| `cyclomatic-complexity` | Informational | 1 | `SPHINCsC10Asm.verify` | The whole verifier is one Yul function. |
| `dead-code` | Informational | 1 | `PQSmartWallet._erc1271Signer` | The intentional tripwire (L-2); see §6. |
| `missing-inheritance` | Informational | 1 | `SPHINCsC10Asm` | The verifier does not declare `ISPHINCSVerifier`. Its `verify(bytes32,bytes32,bytes32,bytes)` signature matches the interface, through which the wallet and factory call it. |

`4naly3er`, `aderyn` and Mythril were not run.

---

## 2. Coverage

`forge coverage --ir-minimum --report summary --no-match-path 'test/halmos/*'`,
with the default fuzz and invariant settings (256 runs; invariants at depth 500):

| Contract | Lines | Statements | Branches | Functions |
|---|---|---|---|---|
| `src/PQSmartWallet.sol` | 79.04% (132/167) | 76.92% (150/195) | 59.09% (26/44) | 92.59% (25/27) |
| `src/PQMultiOwnable.sol` | 93.85% (61/65) | 92.19% (59/64) | 45.45% (5/11) | 100.00% (14/14) |
| `src/PQSmartWalletFactory.sol` | 90.00% (27/30) | 91.18% (31/34) | 66.67% (4/6) | 100.00% (5/5) |
| `src/verifiers/SPHINCsC10Asm.sol` | not meaningful (Yul) | | | 100.00% (1/1) |

Two of the 27 functions in `PQSmartWallet.sol` are not reached; one is
`_erc1271Signer`, which is unreachable by design (§6). Among the uncovered
branches are the failure arms of the `require`s in `_bumpBootstrapUses` and
`_bumpSlotUses`, which validation makes unreachable by checking the caps
first (V-5 in `AUDIT_DIAGRAMS.md`).

Reading the numbers:

- **`SPHINCsC10Asm.sol` is a single function of Yul.** `forge coverage` does
  not instrument lines inside `assembly` blocks, so its line figure says
  nothing. The verifier is exercised by `test/SPHINCsC10Asm.t.sol` (KAT
  vectors from `test/c10_test_vectors.json` and primitive KATs),
  `test/SPHINCsC10AsmAdversarial.t.sol` (about 250 mutated signatures that must
  be rejected), `test/SPHINCsC10AsmMutantCorpus.t.sol`, the real-signature
  tests, and a byte-level comparison with the Rust reference `sphincs-c10/`.
- **The Halmos harnesses are excluded**: they are symbolic rules, run by
  `make -C ../verification verify-bytecode`, not Foundry tests.
- **Under `--ir-minimum` the codehash pin tests fail**, because coverage
  compiles without the production optimizer settings. That is expected: they
  pass under `forge test` and under the deploy profile.

---

## 3. Contract sizes (deploy profile, EIP-170 limit 24,576 bytes)

`FOUNDRY_PROFILE=deploy forge build --sizes`:

| Contract | Runtime (B) | Initcode (B) | Runtime margin (B) |
|---|---:|---:|---:|
| `PQSmartWallet` | 10,930 | 12,393 | 13,646 |
| `PQSmartWalletFactory` | 2,321 | 2,529 | 22,255 |
| `SPHINCsC10Asm` | 1,889 | 1,915 | 22,687 |

---

## 4. Tests

`forge test` (default profile): **149 passed, 0 failed, 2 skipped** in 20
suites. The skips are expected: `DeployedBytecodeReproCheck` runs only under
the deploy profile, and `EntryPointCodehashReceipt` needs `ENTRYPOINT_RPC_URL`.
Of note:

| Suite | What it covers |
|---|---|
| `PQSmartWallet.t.sol` | Unit and integration tests: role split, caps, credits, H-2/H-3, removed-selector rejection, key re-install refusal |
| `PQSmartWalletInvariants.t.sol` | Stateful invariants (256 runs × depth 500), including the append-only owner set with a re-install handler |
| `PQSmartWalletRealSig.t.sol` | Real C10 signatures from the host signer |
| `ERC7562ValidationRules.t.sol` | Storage and call-graph subset of the ERC-7562 validation rules |
| `ERC6492Replay.t.sol` | Counterfactual signatures and cross-chain/cross-wallet replay |
| `LegacyERC1271.t.sol` | The legacy `isValidSignature(bytes,bytes)` entry, a mock of Safe v1.4.1's contract-signature check, and the closed raw-hash workflows (#691) |
| `TokenReceiver.t.sol` | ERC-721 and ERC-1155 transfers into a wallet proxy, `supportsInterface`, no fallback |
| `SPHINCsC10Asm*.t.sol` | Verifier KATs, adversarial mutants, mutant corpus |
| `PinnedCodehashes.t.sol`, `PinnedBytecodeImmutableLemma.t.sol`, `DeployedBytecodeReproCheck.t.sol` | Codehash pins for both profiles; the production addresses and the firmware CREATE2 constants (deploy profile, CI) |
| `StorageSlotParity.t.sol`, `LeanSelectorParity.t.sol` | ERC-7201 slot and selector parity with the Lean model |

Deploy profile: `FOUNDRY_PROFILE=deploy forge test --match-contract 'PinnedCodehashesTest|PinnedBytecodeImmutableLemmaTest|DeployedBytecodeReproCheckTest'`
— **7 passed**.

---

## 5. Symbolic execution and proofs

| Tool | Result at the freeze | Receipt |
|---|---|---|
| Halmos (`make -C ../verification verify-bytecode`) | 43/43 rules on both profiles | `../verification/halmos/sessions/halmos-session-2026-10-20.txt` |
| Kontrol / KEVM (`make -C ../verification verify-kontrol`) | 31/31 proofs | `../verification/kontrol/sessions/kontrol-session-2026-10-20.txt` |
| Lean 4 models and proofs | builds; FV gates pass | `../verification/docs/THE_CLAIM.md` |

Certora specs in `certora/` are historical: they were never run against the
current code and are not part of the evidence.

---

## 6. Dead code

Internal helpers in `src/` and where they are used:

| Symbol | Used by |
|---|---|
| `PQSmartWalletFactory._salt` | `createAccount`, `getAddress` |
| `PQSmartWallet._validateSignature` | `validateUserOp` |
| `PQSmartWallet._selectorOf` | `_validateSignature` |
| `PQSmartWallet._calldataOwnerIndex` | `_validateSignature` (H-3 parity) |
| `PQSmartWallet._isSlotAllowedSelector` | `_validateSignature` |
| `PQSmartWallet._creditSlot` | `_stampValidatedCredit`, `_consumeValidatedCredit` |
| `PQSmartWallet._stampValidatedCredit` | `_validateSignature` |
| `PQSmartWallet._consumeValidatedCredit` | both execute paths |
| `PQSmartWallet._domainNameAndVersion` | Solady `EIP712` |
| `PQSmartWallet._erc1271IsValidSignature` | both `isValidSignature` entries |
| `PQSmartWallet._erc1271IsValidSignatureNowCalldata` | Solady's nested EIP-712 workflow |
| `PQSmartWallet._erc1271Signer` | **unreachable by design**: reverts, as a tripwire against a refactor that drops the override above (L-2). Slither reports it as dead code. |
| `PQMultiOwnable._initializeOwners` | constructor, `initialize` |
| `PQMultiOwnable._addOwner` | `addOwnerBytes` |
| `PQMultiOwnable._addOwnerAtIndex` | `_addOwner`, `_initializeOwners` |
| `PQMultiOwnable._bumpBootstrapUses`, `_bumpSlotUses` | `_validateSignature` |
| `PQMultiOwnable._setOffchainSigCount` | both execute paths |
| `PQMultiOwnable._getStorage` | every storage access |

Solady's `_erc1271IsValidSignatureViaSafeCaller` and
`_erc1271IsValidSignatureViaRPC` remain in the inherited library but are no
longer reachable: their only caller was the `_erc1271IsValidSignature`
override point (#691).

`removeOwnerAtIndex` and its helpers were deleted at the freeze. The struct
field `removedOwnersCount` is kept, always zero, so the counter fields stay at
their storage offsets.

---

## 7. Summary

| Item | Status |
|---|---|
| Slither | 28 results; no untriaged Medium or High; CI gate |
| `forge test` | 149 passed, 0 failed, 2 skipped (expected) |
| Deploy-profile pins and firmware constants | 7 passed; CI |
| Coverage | §2 |
| Halmos | 43/43, both profiles |
| Kontrol | 31/31 |
| Dead code | none, apart from the intentional tripwire |
| Contract sizes | wallet 10,930 B of 24,576 |
| 4naly3er / aderyn / Mythril | not run |
