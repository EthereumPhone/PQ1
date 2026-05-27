# PQSmartWallet — Static Analysis, Coverage, Dead Code

**Date:** 2026-05-22.
**Tool versions used:** forge 1.2.3-stable (a813a2c).
**Tool versions NOT used:** slither-analyzer — not installed locally;
recommended for the auditor to run in their environment.

---

## 1. Slither

Not installed on the prep workstation. Recommended invocation for the
auditor (or as a follow-up CI gate):

```bash
pip install slither-analyzer
cd contracts/smart-wallet
slither . --filter-paths "lib/|reference/|test/|script/" \
          --exclude-dependencies \
          --solc-remaps "$(cat remappings.txt | tr '\n' ' ')"
```

We do not currently gate CI on a clean slither run. Pre-launch action:
add slither + 4naly3er to `.github/workflows/test.yml`.

---

## 2. Forge coverage

`forge coverage --ir-minimum --no-match-path 'test/halmos/*'` (the
Halmos tests are not exercised by the Foundry runner; symbolic
discharge happens in CI via `halmos --contract Halmos...`).

In-scope contract coverage (lines / branches / functions):

| Contract | Lines | Branches | Functions |
|---|---|---|---|
| `src/PQSmartWallet.sol` | 74.83% (110/147) | 65.38% (17/26) | 83.33% (15/18) |
| `src/PQMultiOwnable.sol` | 74.68% (59/79) | 35.71% (5/14) | 81.25% (13/16) |
| `src/PQSmartWalletFactory.sol` | 90.00% (27/30) | 66.67% (4/6) | 100.00% (5/5) |
| `src/verifiers/SPHINCsC10Asm.sol` | 0.85% (1/118) | 0.00% (0/5) | 100.00% (1/1) |

Caveats:

- **`SPHINCsC10Asm.sol` is 99% Yul assembly inside one external
  `verify(...)` function.** `forge coverage` cannot instrument
  individual lines inside `assembly { ... }` blocks, so the 0.85% line
  number is meaningless. The verifier IS exercised by:
  - `test/SPHINCsC10Asm.t.sol` — 316 lines of unit tests including
    real C10 test vectors from `test/c10_test_vectors.json`.
  - `test/PQSmartWalletRealSig.t.sol` — 150 lines of end-to-end real
    signatures produced by the host signer.
  - Byte-level cross-check against `sphincs-c10/` Rust reference,
    documented in `AUDIT_2026-05-18.md` §1 "Verifier byte layout".
- **Uncovered branches in `PQMultiOwnable.sol`** are largely error
  paths that need fuzz / invariant runs to hit; the invariant suite
  (`PQSmartWalletInvariants.t.sol`, 256 runs × 128k calls) does
  exercise them but they don't show in `forge coverage`'s branch
  counter.
- The Halmos contracts and the deploy scripts pull the total down
  (they're 0% by construction — scripts are not unit-tested, Halmos
  contracts are not run by `forge test`). Filter them out to read the
  in-scope numbers.

Action items before audit handoff:

1. Add a branch-coverage push for `PQMultiOwnable` error paths
   (`AlreadyOwner`, `WrongOwnerAtIndex`, `NoOwnerAtIndex`,
   `InvalidNMaskLayout` already covered; `OffchainSigCountNotMonotonic`
   and `CombinedSlotCapExceeded` are covered via dedicated tests).
2. Document explicitly in the audit cover letter that
   `SPHINCsC10Asm.sol` line-coverage is misleading and direct the
   reviewer to the test vectors + Rust-reference diff.

---

## 3. Pinned-bytecode test failures during coverage run

`test/PinnedCodehashes.t.sol::test_codehash_pinned_or_print` and
`test/SPHINCsC10Asm.t.sol::test_verifierBytecodeFrozen` both fail
under `forge coverage --ir-minimum` because coverage disables the
production optimizer (`optimizer_runs=200`, `via_ir=true`,
`evm_version=prague`) so the deployed runtime bytecode hash differs
from the pinned production hash.

- Production pin (from `halmos.toml` + `test/PinnedCodehashes.t.sol`):
  - PQSmartWallet: `0xdc2aa6c4db5cc6ebec277d97ef6adada7c448d09a76749ddfa94edd4879a3680`
  - SPHINCsC10Asm: `0x919cf8ef4b028b50f51de2e71aba7d08900d0e59833d003eed68102c7e9289c0`
- `forge coverage --ir-minimum` codehashes (today):
  - PQSmartWallet: `0x9e88d1e2cb6339506e9fca0ebb6fc57a612e12906f7c74aeff2acc3f655b4d34`
  - SPHINCsC10Asm: `0x41f8482f017e7d34748c36dc3370a328834bcd364975996ab3230dad6bb2bdd4`

These tests pass under `forge test` (production profile). Documenting
here so the auditor knows the divergence is expected.

---

## 4. Foundry test suite (production profile)

```
forge test
```

92 tests; 92 pass under production profile. Subset:

- `PQSmartWallet.t.sol` — 56 unit + integration tests (1,320 lines).
- `PQSmartWalletInvariants.t.sol` — 7 stateful invariants (256 runs ×
  128k calls each, 0 reverts).
- `PQSmartWalletRealSig.t.sol` — end-to-end signing tests using real
  C10 signatures from the host signer.
- `SPHINCsC10Asm.t.sol` — verifier unit tests against
  `c10_test_vectors.json`.
- `StorageSlotParity.t.sol` — ERC-7201 slot derivation pinning.
- `PinnedCodehashes.t.sol` — deployed-bytecode codehash pinning.
- `LeanSelectorParity.t.sol` — selector consistency.

---

## 5. Symbolic execution (Halmos)

`halmos.toml` pins:
- halmos ≥ 0.2.0
- Z3 ≥ 4.13.0
- Bound `default_array_lengths = "0,1,2,4"`,
  `default_bytes_lengths = "0,32,4128"`.
- Loop unrolling `k <= 4`; larger k discharged by the Lean
  `executeBatch_runs_in_signed_order` theorem.
- `verify_bytecode = true` — fails if deployed codehash drifts from
  the production pin.

Contracts:
- `test/halmos/HalmosValidateUserOp.t.sol` — discharges
  `solidityWallet_compiles_correctly` (A3.2) for the validate path.
- `test/halmos/HalmosExecute.t.sol` — same for the execute path.

Not run in this prep pass; the auditor should run both with
`halmos --contract HalmosValidateUserOp` and
`halmos --contract HalmosExecute` against the audit-freeze commit.

---

## 6. Formal verification (Certora)

Four spec files in `certora/`:
- `PQMultiOwnable.spec`
- `PQSmartWalletExecute.spec`
- `PQSmartWalletFactory.spec`
- `PQSmartWallet.spec`

Configurations in `certora/confs/`. Not run in this prep pass — they
require an API key. Status of each rule (timeout / verified / known
issue) should be confirmed before audit handoff.

---

## 7. Dead-code scan

Manual review of internal helpers in `src/`:

| Symbol | File | Used? |
|---|---|---|
| `_salt` | Factory:145 | Yes — `createAccount`, `getAddress` |
| `_consumeValidatedOwnerIndex` | Wallet:275 | Yes — both execute paths |
| `_validateSignature` | Wallet:345 | Yes — `validateUserOp` |
| `_selectorOf` | Wallet:455 | Yes — `_validateSignature` |
| `_isSlotAllowedSelector` | Wallet:462 | Yes — `_validateSignature` |
| `_domainNameAndVersion` | Wallet:496 | Yes — Solady ERC1271 hook |
| `_erc1271Signer` | Wallet:513 | Tripwire revert (audit L-2 fix); intentionally unreachable; documented |
| `_erc1271IsValidSignatureNowCalldata` | Wallet:517 | Yes — Solady ERC1271 hook |
| `_initializeOwners` | MultiOwnable:162 | Yes — constructor + `initialize` |
| `_addOwner` | MultiOwnable:175 | Yes — `addOwnerBytes` |
| `_removeOwnerAtIndex` | MultiOwnable:184 | Yes — `removeOwnerAtIndex` |
| `_bumpBootstrapUses` | MultiOwnable:199 | Yes — `addOwnerBytes` |
| `_bumpSlotUses` | MultiOwnable:208 | Yes — `_validateSignature` |
| `_setOffchainSigCount` | MultiOwnable:220 | Yes — both execute paths |
| `_addOwnerAtIndex` | MultiOwnable:242 | Yes — `_addOwner`, `_initializeOwners` |
| `_getStorage` | MultiOwnable:261 | Yes — every state-touching method |

No dead internal symbols. Public/external surface is intentionally
minimal:
- Wallet: `initialize`, `entryPoint`, `masterPkSeed`, `masterPkRoot`,
  `validateUserOp`, `executeWithOffchainCount`,
  `executeBatchWithOffchainCount`, `addOwnerBytes`,
  `removeOwnerAtIndex`, `sphincsDigest`, `c10Verifier`,
  `_PQ_MULTI_OWNABLE_*` constants via inherited getters, `receive()`.
- Factory: `implementation`, `c10Verifier`, `createAccount`,
  `getAddress`, `addSlot0Digest`.

The bare `receive() external payable {}` is intentional (`fund the
wallet` UX); no other extension hooks.

---

## 8. Contract sizes (EIP-170 budget = 24,576 bytes)

| Contract | Runtime | Initcode | Runtime margin | Initcode margin |
|---|---:|---:|---:|---:|
| `PQSmartWallet` | 8,281 | 9,737 | 16,295 | 39,415 |
| `PQSmartWalletFactory` | 1,804 | 2,012 | 22,772 | 47,140 |
| `SPHINCsC10Asm` | 1,259 | 1,285 | 23,317 | 47,867 |
| `MockSPHINCSVerifier` (test only) | 274 | 357 | 24,302 | 48,795 |

All well within the EIP-170 24KB cap. The verifier in particular is
tiny because the heavy lifting is in calldata + memory + SHA-256
precompile calls, not in code.

---

## 9. Status summary

| Item | Status |
|---|---|
| Slither clean / triaged | ⚠ Not run locally; auditor to run |
| 4naly3er / mythril | ⚠ Not run |
| Forge tests pass (prod profile) | ✅ 92/92 |
| Forge coverage (in-scope contracts) | ⚠ 75-90% lines; verifier 99% Yul not measurable |
| Invariant suite | ✅ 7/7 over 256 × 128k calls |
| Halmos symbolic | ⚠ Not run this pass; configured |
| Certora formal | ⚠ Specs written, runs pending API key |
| Dead-code | ✅ None |
| Contract size budget | ✅ Comfortable |
