# PQSmartWallet — Audit Scope, Build, Freeze

Prepared 2026-10-20 for the Trail of Bits engagement. Start here; then read
`AUDIT_REVIEW_GOALS.md` (what we worry about) and `AUDIT_DIAGRAMS.md` (flows,
actors, invariants). `README.md` describes the system.

## 1. Frozen revision

| Item | Value |
|---|---|
| Repository | `EthereumPhone/PQ1` (PQSigner OS monorepo), directory `contracts/smart-wallet/` |
| Freeze tag | `tob-audit-freeze-2026-10` (annotated; the tag message carries the commit hash) |
| Compiler | solc 0.8.28, `via_ir = true`, `evm_version = "prague"`, `bytecode_hash = "none"` |
| Production profile | `FOUNDRY_PROFILE=deploy` (`optimizer_runs = 999999`); tests default to 200 runs |
| Foundry | v1.8.3 (the CI pin) |

Production bytecode identity at the freeze (deploy profile, from
`test/PinnedCodehashSelector.sol` and `test/DeployedBytecodeReproCheck.t.sol`):

| Contract | Deterministic address (Arachnid CREATE2, salt 0) | Runtime codehash |
|---|---|---|
| `SPHINCsC10Asm` | `0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4` | `0xfd55ec708737970f93a73cec1ce67de95391da4b673e24fa2516f9822bf92989` |
| `PQSmartWallet` | `0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011` | `0x4be66f1681776863f405c0bf6d5f412ffe7248873db7aa3ad6b38664f258b2b6` (on Base, chain 8453: the EIP-712 cache embeds the chain id) |
| `PQSmartWalletFactory` | `0xE3dbA404dCeC30093DE26764965a51689C1607BD` | `0x711dff4be17b368d25e5a24c35d12102f18209cd485392863f009e8a72712d5b` |

Proxy init-code hash (compiled into the device firmware):
`0x17ca674095afe9dc82aa6f396ee01bd837449a127b6be59a0d947329f29b2570`.

None of these is deployed yet. The set deployed on Base Mainnet on 2026-06-12
(impl `0x31e4…3590`, factory `0xe8CE…d452`) predates the changes below and is
superseded; see `deployments/`.

## 2. In scope

| File | Lines | SLOC |
|---|---:|---:|
| `src/PQSmartWallet.sol` | 725 | 342 |
| `src/PQMultiOwnable.sol` | 247 | 119 |
| `src/PQSmartWalletFactory.sol` | 148 | 71 |
| `src/verifiers/SPHINCsC10Asm.sol` (Yul) | 233 | 146 |
| `src/verifiers/ISPHINCSVerifier.sol` | 21 | 9 |
| `src/generated/PqsignerProto.sol` | 47 | 12 |
| **Total** | **1,421** | **699** |

SLOC excludes blank lines and comments, including NatSpec.
`generated/PqsignerProto.sol` is rendered from the firmware's `proto` crate by
`cargo run -p pqsigner-xtask -- gen-solidity-constants`. CI fails if it
drifts (`make check-solidity-constants`). Treat it as source.

Also of interest, as the inherited code the wallet relies on:
- Solady `accounts/ERC1271.sol` and `utils/EIP712.sol` (the nested EIP-712
  workflow and the ERC-6492 unwrap);
- Solady `utils/LibClone.sol` (the ERC-1967 proxy and its CREATE2 prediction);
- the EntryPoint v0.6 interfaces in `account-abstraction`.

## 3. What changed since the internal review of 2026-05-18

`AUDIT_2026-05-18.md` is an internal review, not a third-party audit. Since
then:

| Area | Change |
|---|---|
| Transient credits (H-3) | The single transient token became a per-`ownerIndex` counter (several ops for one wallet in one bundle); parity is checked in validation |
| Bootstrap budget (M-1) | Reversed. `bootstrapUses` is counted in the validation phase, because v0.6 swallows execution reverts and a deferred count could be driven to zero |
| Owner management | Gated on the EntryPoint (`msg.sender == entryPoint`), not `address(this)` |
| Verifier | FORS addresses bind the hypertree leaf index (closes a shared-forest forgery) |
| **Owner removal deleted** (freeze, #131 / #213) | `removeOwnerAtIndex` is gone. It was reachable only by a slot key used outside the device, let any slot remove any other, and allowed remove + re-add to reset a key's per-chain budget. The owner set is now append-only |
| **Legacy EIP-1271 entry** (freeze, #995) | `isValidSignature(bytes,bytes)` → `0x20c13b0b`, so Safe v1.3.0 / v1.4.1 accept PQ1 as a contract owner |
| **Raw-hash 1271 workflows closed** (freeze, #691) | `_erc1271IsValidSignature` keeps only Solady's nested EIP-712 workflow, dropping the MulticallerWithSigner "safe caller" path and the `tx.gasprice == 0` RPC path, both of which checked the bare hash |
| **Token receivers** (freeze) | ERC-721 / ERC-1155 receiver hooks and ERC-165; previously ERC-1155 transfers to the wallet always reverted, as did ERC-721 safe transfers |
| **Build metadata** (freeze) | `bytecode_hash = "none"`, so source comments and paths no longer change codehashes or addresses |

## 4. Out of scope (but relevant for reproduction)

```
contracts/smart-wallet/
├── lib/            pinned dependencies, restored from foundry.lock (not submodules)
├── test/           Foundry tests; test/halmos/ symbolic harnesses (compiled by forge)
├── script/         deploy scripts; ProductionDeploy.sol checks addresses against the firmware constants
├── certora/        historical Certora specs; never run against the current code; superseded by Halmos + Kontrol
├── .github/        upstream workflow files; GitHub never runs workflows from this directory (see its README)
├── broadcast/      deploy transaction records
├── deployments/    what is deployed where
└── reference/      (untracked) upstream fork base; use coinbase/smart-wallet@503363d7
```

The off-chain components that produce what the contracts verify (device
firmware, companion app) are out of scope. The interfaces they must match are
listed in §7.

## 5. Dependencies (`foundry.lock`)

| Dependency | Revision | Used by |
|---|---|---|
| `account-abstraction` | `f54584ed` (v0.9 release) | `src/` — only `contracts/legacy/v06/` (`IAccount06`, `IEntryPoint06`, `UserOperation06`) |
| `solady` | `90db92ce` (v0.1.26) | `src/` — `ERC1271` (+ `EIP712`, `SignatureCheckerLib`), `LibClone` |
| `openzeppelin-contracts` | `9cfdccd3` (5.6.1) | tests only (token receiver tests) |
| `forge-std` | `f494b0c2` | tests and scripts |
| `p256-verifier`, `safe-singleton-deployer-sol`, `webauthn-sol` | see `foundry.lock` | unused; restored only so the lib set matches CI exactly |

## 6. Build, test, reproduce

Follow `README.md` § "Build and test". Expected results at the freeze:

| Command | Result |
|---|---|
| `forge test` | 149 passed, 0 failed, 2 skipped. The skips are `DeployedBytecodeReproCheck`, which runs only under the deploy profile, and `EntryPointCodehashReceipt`, which needs an RPC URL |
| `FOUNDRY_PROFILE=deploy forge test --match-contract 'PinnedCodehashesTest\|PinnedBytecodeImmutableLemmaTest\|DeployedBytecodeReproCheckTest'` | 7 passed |
| `slither .` | 28 results, none of them an untriaged Medium or High (`slither.db.json`, reasoning in `AUDIT_STATIC_ANALYSIS.md`) |
| `make -C ../verification verify-bytecode` (Halmos, both profiles) | 43 rules; receipt in `../verification/halmos/sessions/` |
| `make -C ../verification verify-kontrol` | 31 proofs; receipt in `../verification/kontrol/` |

If a codehash pin fails, do not update it; something differs from the frozen
build.

## 7. Interfaces the contracts must match

| Interface | Producer | Where it is pinned |
|---|---|---|
| `sphincsDigest` preimage (12 fields) | device firmware (`aa/src/userop.rs`) | `make -C ../verification verify-transcription`, `test/SphincsDigestFieldBinding.t.sol` |
| Signature wrapper `abi.encode(uint256, bytes)`, 4128 bytes | firmware | `PqsignerProto.SIG_WRAPPER_LEN`, wrapper tests |
| Type-1 call data `addOwnerBytes(bytes)`; Type-2 `execute*WithOffchainCount(ownerIndex = slot + 1, …)` | firmware | `test/LeanSelectorParity.t.sol`, real-signature tests |
| Off-chain replay-safe hash (Solady PersonalSign under `("PQSmartWallet","1", chainId, wallet)`) | firmware (`aa/src/eip1271.rs`) | `test/ERC6492Replay.t.sol`, `test/LegacyERC1271.t.sol` |
| Factory slot-0 digest `sha256("pqwallet-factory-add-slot" ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)` | firmware | `PqsignerProto.FACTORY_ADD_SLOT_DOMAIN` |
| CREATE2 constants (factory address, proxy init-code hash) | firmware (`proto/src/lib.rs`) | `script/generated/PqsignerDeployment.sol` + `test/DeployedBytecodeReproCheck.t.sol` (CI, deploy profile) |

## 8. Reading order

1. `README.md`, then `AUDIT_REVIEW_GOALS.md`, then `AUDIT_DIAGRAMS.md`.
2. `src/generated/PqsignerProto.sol` (constants).
3. `src/PQMultiOwnable.sol` (storage, counters).
4. `src/PQSmartWallet.sol` (validation, execution, EIP-1271, receivers).
5. `src/PQSmartWalletFactory.sol` (CREATE2, squat defence).
6. `src/verifiers/SPHINCsC10Asm.sol`, alongside the Rust reference in `sphincs-c10/` and the C10 parameter set (`h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205`).
7. Tests, especially `PQSmartWalletInvariants.t.sol`, `ERC7562ValidationRules.t.sol`, `LegacyERC1271.t.sol`, `ERC6492Replay.t.sol`, `SPHINCsC10AsmAdversarial.t.sol`.
8. Formal-verification scope: `../verification/docs/THE_CLAIM.md`.

## 9. CI

The repository-root `.github/workflows/ci.yml` runs:
- **`contracts` job:** lib-exact restore, `forge test`, then the deploy-profile pin tests, which tie the production bytecode to the firmware's CREATE2 constants.
- **`slither` job:** hard gate at Medium.
- **`host-tests` job:** `make check-solidity-constants`.

`lean-fv.yml` and `a31-transcription.yml` run the Lean and transcription
gates. Halmos and Kontrol are run locally; their receipts are committed.
