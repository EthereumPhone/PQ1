# PQSmartWallet — Diagrams, Actors, Invariants, Glossary

Companion to `AUDIT_SCOPE.md` and `AUDIT_REVIEW_GOALS.md`. Updated
2026-10-20 for the audit freeze. The diagrams are Mermaid; GitHub renders
them, or paste them into `https://mermaid.live`.

Indexing used throughout: the device's slot `s` signs as
`ownerIndex = s + 1`. Index 0 is the bootstrap key.

---

## 1. Lifecycle: deploy, rotate, sign

```mermaid
sequenceDiagram
    actor U as User
    participant D as PQ1 device (secure world)
    participant A as Companion app
    participant B as Bundler
    participant EP as EntryPoint v0.6
    participant F as PQSmartWalletFactory
    participant W as Wallet proxy (ERC-1967)
    participant V as SPHINCsC10Asm
    participant T as Target

    Note over U,T: A. First UserOp on a chain deploys the wallet (slot 0, ownerIndex 1)
    A->>D: sign request (chainId, slot 0, INCLUDE_INIT_CODE)
    D->>U: transaction pages on the device screen
    U->>D: confirm
    D->>D: factorySig = bootstrap signature over addSlot0Digest(chainId, slot-0 key)
    D->>D: Type-2 signature = slot-0 key over sphincsDigest(userOp)
    D->>A: initCode (4280 B, carries factorySig) and Type-2 wrapper (4128 B)
    A->>B: UserOp with initCode and callData executeWithOffchainCount(1, count, ...)
    B->>EP: handleOps
    EP->>F: createAccount(master key, slot-0 key, chainId, factorySig), through SenderCreator
    F->>V: verify(master key, addSlot0Digest, factorySig)
    V-->>F: true
    F->>W: CREATE2 the proxy, then initialize(bootstrap key, slot-0 key)
    EP->>W: validateUserOp(userOp, userOpHash, missingAccountFunds)
    W->>V: verify(slot-0 key, sphincsDigest(userOp), signature)
    V-->>W: true
    W->>W: slotUses[1] += 1 and transient credit[1] += 1
    EP->>W: executeWithOffchainCount(1, count, target, value, data)
    W->>W: consume credit[1], record offchainSigCount[1] = count
    W->>T: call(value, data)

    Note over U,T: B. Rotation to slot s (ownerIndex s+1), two UserOps in separate bundles
    A->>W: read nextOwnerIndex, must equal s+1
    A->>D: sign request (chainId, slot s, REGISTER_SLOT)
    D->>U: rotation pages, then transaction pages
    U->>D: confirm
    D->>A: Type-1 wrapper (bootstrap, op 1), new key bytes, Type-2 wrapper (slot s, op 2)
    A->>B: op 1, nonce n, callData addOwnerBytes(new slot key)
    B->>EP: handleOps
    EP->>W: validateUserOp(op 1)
    W->>V: verify(bootstrap key, sphincsDigest(op 1), signature)
    W->>W: bootstrapUses += 1 in the validation phase, no credit
    EP->>W: addOwnerBytes(new slot key)
    W->>W: install at nextOwnerIndex, or revert AlreadyOwner if the key was ever installed
    A->>B: op 2, nonce n+1, callData executeWithOffchainCount(s+1, count, ...)
    Note over EP,T: op 2 follows the steady-state path (C)

    Note over U,T: C. Steady state, slot key at ownerIndex i
    A->>D: sign request (chainId, slot i-1)
    D->>U: transaction pages
    U->>D: confirm
    D->>A: Type-2 wrapper and the slot's new off-chain count
    A->>B: UserOp, callData executeWithOffchainCount(i, ...) or executeBatchWithOffchainCount(i, ...)
    B->>EP: handleOps
    EP->>W: validateUserOp
    W->>W: role split, H-3 parity, combined cap (section 2)
    W->>V: verify(slot key i, sphincsDigest(userOp), signature)
    W->>W: slotUses[i] += 1 and credit[i] += 1
    EP->>W: execute...WithOffchainCount(i, count, ...)
    W->>W: consume credit[i], offchainSigCount[i] = count (section 3)
    W->>T: call(s)
```

Notes:
- The factory signature is a bootstrap-key signature, once per chain. It is
  not counted in `bootstrapUses` (`AUDIT_REVIEW_GOALS.md` §4).
- In v0.6, `handleOps` validates every op of a bundle before executing any.
  The transient credit carries "this op was validated for index `i`" from
  one phase to the other (section 3).
- The device signs `sphincsDigest`, a SHA-256 hash, not the EntryPoint's
  keccak `userOpHash` (glossary).

---

## 2. `validateUserOp`

```mermaid
flowchart TD
    A["validateUserOp(userOp, userOpHash, missingAccountFunds)"] --> G0{"msg.sender is the EntryPoint?"}
    G0 -->|no| R0["revert NotFromEntryPoint"]
    G0 -->|yes| P{"signature is abi.encode(uint256 ownerIndex, bytes sig): 4128 bytes, offset 0x40, inner length 4008, zero tail pad?"}
    P -->|no| FAIL["validationData = 1 (SIG_VALIDATION_FAILED)"]
    P -->|yes| O{"ownerAtIndex(ownerIndex) holds a 64-byte key?"}
    O -->|no| FAIL
    O -->|yes| C{"ownerIndex == 0?"}
    C -->|"yes: bootstrap"| B1{"callData selector is addOwnerBytes?"}
    B1 -->|no| FAIL
    B1 -->|yes| B2{"bootstrapUses below 65,536?"}
    B2 -->|no| FAIL
    B2 -->|yes| VER
    C -->|"no: slot i"| S1{"selector is executeWithOffchainCount or executeBatchWithOffchainCount?"}
    S1 -->|no| FAIL
    S1 -->|yes| S2{"first calldata argument equals i? (H-3)"}
    S2 -->|no| FAIL
    S2 -->|yes| S3{"slotUses[i] + offchainSigCount[i] below 65,536?"}
    S3 -->|no| FAIL
    S3 -->|yes| VER["c10Verifier.verify(pkSeed, pkRoot, sphincsDigest(userOp), sig)"]
    VER -->|"false or revert"| FAIL
    VER -->|"true, index 0"| OK0["bootstrapUses += 1"]
    VER -->|"true, index i"| OKI["slotUses[i] += 1 and transient credit[i] += 1"]
    OK0 --> OK["validationData = 0"]
    OKI --> OK
    OK --> PAY["pay missingAccountFunds to the EntryPoint if non-zero"]
    FAIL --> PAY
```

`validationData` never encodes a time range or an aggregator. The counters
are written only after a successful verify, one counter per accepted op.

---

## 3. Execute paths and the transient credit

```mermaid
flowchart TD
    A["executeWithOffchainCount(i, newCount, target, value, data)"] --> G{"msg.sender is the EntryPoint?"}
    G -->|no| R0["revert NotFromEntryPoint"]
    G -->|yes| C{"transient credit[i] above 0?"}
    C -->|no| R1["revert OwnerIndexMismatch"]
    C -->|yes| C2["credit[i] -= 1"]
    C2 --> S{"target is the wallet itself?"}
    S -->|yes| R2["revert SelfCallForbidden (H-2)"]
    S -->|no| N{"newCount at least offchainSigCount[i]?"}
    N -->|no| R3["revert OffchainSigCountNotMonotonic"]
    N -->|yes| K{"slotUses[i] + newCount at most 65,536?"}
    K -->|no| R4["revert CombinedSlotCapExceeded"]
    K -->|yes| WR["offchainSigCount[i] = newCount"]
    WR --> CALL["target.call(value, data)"]
    CALL -->|reverts| R5["revert with the target's revert data"]
    CALL -->|succeeds| RET["return the target's return data"]
```

`executeBatchWithOffchainCount(i, newCount, targets, values, datas)` runs
the same caller, credit and count checks, then requires equal array lengths
(`BatchArrayLengthMismatch`), then for each call rejects the wallet as
target and bubbles any revert.

A revert in execution undoes that execution only: the credit decrement and
the count update roll back. The validation-phase `slotUses[i]` bump stays,
because v0.6 keeps validation state when an op's execution reverts. A
credit left over that way can only be consumed by the EntryPoint, with
calldata that passed validation for index `i`, in the same transaction.

The credit lives at `keccak256(i ‖ _TS_CREDIT_NAMESPACE)` in transient
storage and is a counter, so several ops for one wallet in one bundle each
fund exactly one execution. The bootstrap path uses no credit:
`addOwnerBytes` needs only `msg.sender == entryPoint`, and only a
bootstrap-validated op can carry that selector.

---

## 4. Factory

```mermaid
flowchart TD
    A["createAccount(masterPkSeed, masterPkRoot, slot0PkSeed, slot0PkRoot, chainId, factorySig), payable"] --> CH{"chainId == block.chainid?"}
    CH -->|no| R1["revert WrongChainId"]
    CH -->|yes| SALT["salt = sha256(masterPkSeed ‖ masterPkRoot)"]
    SALT --> CL["LibClone.createDeterministicERC1967(msg.value, implementation, salt)"]
    CL --> D{"proxy already deployed?"}
    D -->|yes| E["return it: msg.value was forwarded to it, slot-0 arguments and factorySig are ignored"]
    D -->|no| DG["digest = sha256('pqwallet-factory-add-slot' ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)"]
    DG --> V{"c10Verifier.verify(master key, digest, factorySig)?"}
    V -->|"false or revert"| R2["revert InvalidFactorySignature, which undoes the CREATE2"]
    V -->|true| I["proxy.initialize(master key, slot-0 key)"]
    I --> EV["emit AccountCreated"]
```

`getAddress(masterPkSeed, masterPkRoot)` returns
`LibClone.predictDeterministicAddressERC1967(implementation, salt, factory)`.
The device computes the same address from two firmware constants: the
factory address and the proxy init-code hash (`AUDIT_SCOPE.md` §1).

---

## 5. EIP-1271: two entry points, one nested check

```mermaid
flowchart TD
    E1["isValidSignature(bytes32 hash, bytes sig), from Solady"] --> PR{"sig empty and hash is 0x7739...7739?"}
    PR -->|yes| P7["return 0x77390001 (ERC-7739 support probe)"]
    PR -->|no| UW["ERC-6492: if sig ends with the 0x6492...6492 magic, use only the wrapped inner signature"]
    UW --> NE
    E2["isValidSignature(bytes data, bytes sig), legacy form used by Safe v1.3.0 and v1.4.1"] --> KH["hash = keccak256(data), no ERC-6492 unwrap"]
    KH --> NE["_erc1271IsValidSignature, overridden: nested EIP-712 workflow only"]
    NE --> TD{"sig ends with a TypedDataSign suffix that re-hashes to hash?"}
    TD -->|"yes, never produced by the device"| TDS["h = TypedDataSign hash with this wallet's domain fields, suffix removed"]
    TD -->|no| PS["h = EIP-712 hash of PersonalSign(hash) under (PQSmartWallet, 1, chainId, this wallet)"]
    TDS --> W
    PS --> W{"4128-byte wrapper, offset 0x40, inner length 4008, zero tail pad, ownerIndex not 0, key installed?"}
    W -->|no| F["invalid"]
    W -->|yes| V{"c10Verifier.verify(slot key, h, sig)?"}
    V -->|"false or revert"| F
    V -->|true| OK["valid"]
    OK --> M1["bytes32 entry returns 0x1626ba7e, legacy entry returns 0x20c13b0b"]
    F --> M2["either entry returns 0xffffffff"]
```

Solady's two raw-hash workflows, the MulticallerWithSigner "safe caller"
and the `tx.gasprice == 0` RPC path, are removed by the override (#691).
Both checked the bare hash, and the only bare hashes the device signs are
UserOp `sphincsDigest`s, which are public in on-chain calldata.

The ERC-6492 unwrap only strips the wrapper. Deploying the counterfactual
wallet is the job of the ERC-6492-aware verifier that calls in. The device's
counterfactual blob is `abi.encode(factory, initCode[20:], wrapper) ‖ magic`.

---

## 6. Actors and privileges

```mermaid
flowchart LR
    subgraph callers["Callers"]
        EP["EntryPoint v0.6 (immutable address)"]
        FA["PQSmartWalletFactory"]
        ANY["anyone"]
    end
    subgraph wallet["PQSmartWallet, reached through the user's proxy"]
        VAL["validateUserOp"]
        EXE["executeWithOffchainCount"]
        EXB["executeBatchWithOffchainCount"]
        ADD["addOwnerBytes"]
        INI["initialize, one-shot"]
        ISV["isValidSignature, both forms, view"]
        RCV["token receiver hooks and supportsInterface, pure"]
        ETH["receive, payable"]
        VIEW["views and constants"]
    end
    EP --> VAL
    EP -->|"slot op for index i, consumes credit i"| EXE
    EP -->|"slot op for index i, consumes credit i"| EXB
    EP -->|"bootstrap op only"| ADD
    FA -->|"in the CREATE2 transaction"| INI
    ANY --> ISV
    ANY --> RCV
    ANY --> ETH
    ANY --> VIEW
```

| Function | Caller check | Authorised by | Notes |
|---|---|---|---|
| `validateUserOp` | `msg.sender == entryPoint` | the C10 signature in the op | Returns 1 for every signature-shape, role, cap or verify failure. Reverts only for the wrong caller |
| `executeWithOffchainCount` | `msg.sender == entryPoint`, plus one transient credit for `ownerIndex` | slot key `ownerIndex` | Rejects the wallet as target (H-2). Updates `offchainSigCount` monotonically under the combined cap |
| `executeBatchWithOffchainCount` | same | same | Array lengths must match. Self-call check on every target |
| `addOwnerBytes` | `msg.sender == entryPoint` | bootstrap key, through the role split at validation | Appends at `nextOwnerIndex`. Refuses malformed bytes and any key ever installed. Changes no counter |
| `initialize` | none; reverts unless `nextOwnerIndex() == 0` | the factory, after it verified `factorySig` in the same call | The implementation's constructor installs a dummy owner, so `initialize` reverts on the implementation |
| `isValidSignature(bytes32,bytes)` | none (view) | a slot key, over the nested hash | Index 0 rejected. ERC-6492 unwrap. ERC-7739 probe |
| `isValidSignature(bytes,bytes)` | none (view) | the same, over `keccak256(data)` | No ERC-6492 unwrap |
| `onERC721Received`, `onERC1155Received`, `onERC1155BatchReceived`, `supportsInterface` | none (pure) | none | Always accept. No state. `supportsInterface` is true for `0x01ffc9a7`, `0x150b7a02`, `0x4e2312e0` only |
| `receive()` | none | none | Accepts ETH. There is no fallback, so unknown selectors revert |
| Views (`entryPoint`, `c10Verifier`, `ownerAtIndex`, `nextOwnerIndex`, `ownerCount`, `isOwnerBytes`, counters, `masterPkSeed`, `masterPkRoot`, `sphincsDigest`, `eip712Domain`, constants) | none | none | Read only |
| Factory `createAccount` | none (payable) | bootstrap signature over the slot-0 digest, first deployment only | Already deployed: forwards `msg.value`, ignores the rest |
| Factory `getAddress`, `addSlot0Digest` | none | none | View / pure |

### Roles

- **Bootstrap key (`ownerIndex == 0`).** Signs only `addOwnerBytes`
  UserOps, plus the factory's slot-0 authorisation once per chain. Never
  accepted by EIP-1271. Nothing can remove or replace it. Cap:
  `bootstrapUses ≤ 65,536` per chain.
- **Slot keys (`ownerIndex ≥ 1`).** Sign only the two execute selectors,
  for their own index, and off-chain messages (nested hash only). Cap:
  `slotUses[i] + offchainSigCount[i] ≤ 65,536` per chain.
- **Factory.** Its only power over a wallet is the atomic `initialize`. It
  has no admin; `implementation` and `c10Verifier` are immutable.
- **EntryPoint.** Trusted to run v0.6 `handleOps` semantics: validate, then
  execute the validated `callData`.
- There is no admin, guardian, pause, upgrade or recovery role anywhere.

---

## 7. Invariants

Where an invariant is checked mechanically, the check is named. Lean
theorem names are under `contracts/verification/lean/SphincsCVerify/Wallet/`.

### Storage (always)

| ID | Invariant | Enforced by | Checked by |
|---|---|---|---|
| S-1 | `ownerAtIndex[0]` is set on every initialised proxy and never changes | `initialize` is one-shot; `addOwnerBytes` appends at `nextOwnerIndex ≥ 2`; there is no removal | Over a run: fuzz `invariant_owner_set_append_only` (every index, 0 included, keeps its key). Per step: Lean `cannot_remove_bootstrap` (one `addOwner` step on an initialised state leaves index 0 unchanged) plus the closed-world mutator gate `verify-storage-mutators`; Kontrol `KontrolBootstrapUnremovable` |
| S-2 | Every installed owner is 64 bytes | `InvalidOwnerBytesLength` | Halmos `HalmosMultiOwnable` |
| S-3 | Owner keys use the N-mask layout: the low 16 bytes of `pkSeed` and of `pkRoot` are zero | `InvalidNMaskLayout` | unit tests |
| S-4 | `bootstrapUses` is monotonic and `≤ 65,536` | validation pre-check; `_bumpBootstrapUses` `require` | fuzz `invariant_bootstrapUses_capped`, `invariant_bootstrapUses_monotonic`; Lean `no_reset_path` (per operation); Halmos `check_bootstrap_bumps_cap_at_validation` |
| S-5 | For every `i`: `slotUses[i] + offchainSigCount[i] ≤ 65,536` | validation pre-check (`< 65,536` before the bump); `_setOffchainSigCount` (`CombinedSlotCapExceeded`) | fuzz invariants; Lean `reachable_implies_combinedCap` |
| S-6 | `slotUses[i]` and `offchainSigCount[i]` never decrease | increment only; `OffchainSigCountNotMonotonic` | fuzz invariants; Lean `no_reset_path` |
| S-7 | The owner set is append-only: `nextOwnerIndex` only grows, `ownerAtIndex[k]` for `k < nextOwnerIndex` never changes, and `isOwner` never goes back to false | no removal path | Over time: fuzz `invariant_owner_set_append_only`. Per state: Lean `reachable_ownerTableWF` (on every reachable state the table is injective and every installed key is flagged and below `nextOwnerIndex`) |
| S-8 | A key is installed at most once in a wallet's life, so its counters can never be reset by re-installing it | `AlreadyOwner` | `test_installedKeyCanNeverBeInstalledAgain`; Lean `reachable_key_installed_at_most_once` |
| S-9 | The reserved field `removedOwnersCount` is always zero, and `ownerCount() == nextOwnerIndex()` | no code writes the field; `ownerCount()` returns `nextOwnerIndex` | Source inspection; Halmos `HalmosMultiOwnable` checks that `addOwnerBytes` and the removed selector leave the reserved slot unchanged |
| S-10 | `entryPoint` and `c10Verifier` (wallet) and `implementation` and `c10Verifier` (factory) never change | `immutable` | codehash pins |
| S-11 | The ERC-7201 storage location is `0x470749eea5ac4a541d6582e535445f94e7300bac9e0e4e5577fd3336b407d000` | constant | `StorageSlotParity.t.sol` |
| S-12 | A proxy's ERC-1967 implementation slot never changes | no upgrade function | `invariant_impl_slot_unchanged` |

### Transient (within one transaction)

| ID | Invariant | Enforced by |
|---|---|---|
| T-1 | Each slot op validated for index `i` adds exactly one credit for `i` | `_stampValidatedCredit`, after a successful verify only |
| T-2 | An execute for index `i` runs only if a credit for `i` exists, and consumes exactly one | `_consumeValidatedCredit`, `OwnerIndexMismatch` |
| T-3 | A credit for `i` is stamped only by an op whose calldata names `i`, so it cannot fund another index | H-3 parity at validation |
| T-4 | The bootstrap path stamps no credit | `_validateSignature` |
| T-5 | Credits are gone at the end of the transaction | EIP-1153 |

### Validation (per call)

| ID | Invariant |
|---|---|
| V-1 | An op validated under index 0 calls `addOwnerBytes` and nothing else |
| V-2 | An op validated under index `i ≥ 1` calls `executeWithOffchainCount` or `executeBatchWithOffchainCount` with first argument `i` |
| V-3 | The signed message is `sphincsDigest(userOp)`, which binds `block.chainid` and the EntryPoint address. `userOpHash` is ignored |
| V-4 | A wrapper that is not exactly 4128 bytes, has an offset other than `0x40`, an inner length other than 4008, or a non-zero tail pad fails |
| V-5 | A malformed or wrong signature returns 1 and never reverts. The only revert is `NotFromEntryPoint` (the counters' `require`s are unreachable because the caps are checked first) |
| V-6 | A verifier that returns false or reverts gives 1 |
| V-7 | Counters change only after a successful verify, one counter per accepted op |

The Halmos rules `HalmosValidateUserOpEquiv` and `HalmosExecuteEquiv` check
the compiled bytecode against the Lean model of these paths, point by point.

### Off-chain signatures

| ID | Invariant |
|---|---|
| E-1 | Both EIP-1271 entries accept only a signature over one of Solady's two nested EIP-712 forms, each bound to `("PQSmartWallet", "1", block.chainid, address(this))`: `PersonalSign` (the only form the device signs) and `TypedDataSign` (the wallet's domain fields inside a struct under the app's domain) |
| E-2 | Index 0 is never accepted off-chain |
| E-3 | EIP-1271 changes no state |
| E-4 | The legacy entry returns `0x20c13b0b` exactly when the `bytes32` entry returns `0x1626ba7e` for `keccak256(data)` and the same signature without an ERC-6492 wrapper. By construction (both call `_erc1271IsValidSignature`); Halmos `check_legacy_isValidSignature_agrees_with_bytes32_entry` checks one instance class (66-byte `data`, `ownerIndex` 1, symbolic verifier answer), and `LegacyERC1271.t.sol` exercises real paths |

### Addresses

| ID | Invariant |
|---|---|
| A-1 | `salt = sha256(masterPkSeed ‖ masterPkRoot)` |
| A-2 | The same master key gives the same proxy address on every chain where this exact contract set is deployed at the same addresses |
| A-3 | The first deployment requires a bootstrap signature over `sha256("pqwallet-factory-add-slot" ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)` |
| A-4 | `createAccount` requires `chainId == block.chainid` |
| A-5 | The production build's factory address and proxy init-code hash equal the firmware constants (CI: `DeployedBytecodeReproCheck`, deploy profile) |

---

## 8. Glossary

| Term | Meaning |
|---|---|
| **SPHINCS+** | A stateless hash-based signature design, standardised by NIST as SLH-DSA (FIPS 205). Its security rests on properties of the hash function, SHA-256 here, with no number-theoretic assumption. |
| **SPHINCS+C10** | The parameter set used here: a SPHINCS+ variant with the "C" (grinding) optimisations, `h=18, d=2, a=11, k=13, w=8, l=43, target_sum=205`. Signatures are 4,008 bytes. It is not one of the FIPS 205 parameter sets. The hypertree has 2^18 leaves; the contracts cap each key at 65,536 signatures per chain. |
| **Bootstrap key** | The wallet's root C10 key at `ownerIndex 0`. Fixed at deployment. Signs only `addOwnerBytes` and the factory's slot-0 authorisation. The wallet address derives from it. |
| **Slot key** | A C10 key at `ownerIndex ≥ 1`. Device slot `s` signs as `ownerIndex s+1`. Slot keys differ per chain. Rotating means adding a new slot; old slots stay installed. |
| **N-mask layout** | A 32-byte word holding a 16-byte value in its top half, with the low 16 bytes zero. C10 has `n = 16`; the verifier and the EVM work in 32-byte words. |
| **`pkSeed`, `pkRoot`** | The two halves of a C10 public key, each in the N-mask layout. Together they are the 64 owner bytes. |
| **ERC-4337 v0.6** | The account-abstraction version targeted. Frozen: its EntryPoint address is part of every signed digest and of the wallet address derivation. |
| **UserOp** | A v0.6 UserOperation: `sender, nonce, initCode, callData, callGasLimit, verificationGasLimit, preVerificationGas, maxFeePerGas, maxPriorityFeePerGas, paymasterAndData, signature`. |
| **`sphincsDigest`** | The SHA-256 hash the device signs for a UserOp: `sha256(sender ‖ nonce ‖ sha256(initCode) ‖ sha256(callData) ‖ the five gas words ‖ sha256(paymasterAndData) ‖ entryPoint ‖ chainId)`. Used instead of the keccak `userOpHash` because the device has a SHA-256 accelerator and no keccak hardware. |
| **Signature wrapper** | `abi.encode(uint256 ownerIndex, bytes c10Sig)`, exactly 4,128 bytes. Used for UserOps and for EIP-1271. |
| **Type-1 signature** | A bootstrap-key signature on a UserOp, which can only call `addOwnerBytes`. Counts against `bootstrapUses`. |
| **Type-2 signature** | A slot-key signature on a UserOp, which can only call one of the two execute selectors. Counts against `slotUses[i]`. |
| **`bootstrapUses`** | Per-chain count of accepted Type-1 signatures, bumped in the validation phase. Cap 65,536. |
| **`slotUses[i]`** | Per-chain count of accepted Type-2 signatures for index `i`, bumped in the validation phase. |
| **`offchainSigCount[i]`** | The number of off-chain signatures the device reports having made with key `i`, carried by every execute call. Monotonic. |
| **Combined cap** | `slotUses[i] + offchainSigCount[i] ≤ 65,536`: UserOps and off-chain signatures share one budget per key and chain. |
| **Transient credit** | An EIP-1153 counter per `ownerIndex` that validation increments and execution decrements, so that one validated op buys at most one execution. |
| **H-2, H-3, M-1, L-1, L-2, L-3** | Finding IDs from the internal review `AUDIT_2026-05-18.md`. H-2: no self-calls from execute. H-3: calldata index equals signing index. M-1: the bootstrap count, now done in validation. L-1: zero tail pad. L-2: `_erc1271Signer` tripwire. L-3: custom batch error. |
| **EIP-1271** | `isValidSignature(bytes32, bytes)` returning `0x1626ba7e`. The legacy form `isValidSignature(bytes, bytes)` returns `0x20c13b0b`. |
| **Nested EIP-712 (ERC-7739)** | Solady's scheme that wraps the dapp's hash in a typed structure under this wallet's domain (`name "PQSmartWallet"`, `version "1"`, chain id, wallet address), so a signature verifies for one wallet on one chain only. The device uses the `PersonalSign` form. |
| **ERC-6492** | A wrapper that lets a not-yet-deployed wallet's signature be checked: `abi.encode(factory, factoryCalldata, signature) ‖ 0x6492…6492`. The verifier deploys the wallet, then calls `isValidSignature`. |
| **ERC-7201** | Namespaced storage. The wallet's state lives in one struct at the slot derived from `pqsigner.storage.PQMultiOwnable`. |
| **ERC-1967 proxy** | The 61-byte per-user contract the factory deploys. It delegates every call to the shared implementation. |
| **Squat defence** | The factory's requirement of a bootstrap signature over the slot-0 key and chain id. Without it, anyone who knows a master public key could deploy the victim's address with their own slot 0. |
| **Arachnid deployer** | The deterministic CREATE2 deployer at `0x4e59b44847b379578588920cA78FbF26c0B4956C`, used with salt 0 so the contract addresses are the same on every chain. |
| **Halmos, Kontrol** | Symbolic-execution tools run on the compiled bytecode: Halmos on Foundry `check_*` harnesses (`test/halmos/`), Kontrol (KEVM) on `prove_*` harnesses (`../verification/kontrol/`). |
| **PQ1** | The hardware wallet: an STM32U585 microcontroller with two secure elements. It holds the seed and produces every signature these contracts verify. |
