# PQSmartWallet — Audit Review Goals

**Project:** PQ1 hardware wallet, on-chain account-abstraction contracts.
**Scope:** `contracts/smart-wallet/src/`, including the Yul SPHINCS+C10
verifier. Freeze and build: `AUDIT_SCOPE.md`.
**Prior review:** `AUDIT_2026-05-18.md`, an internal review (3H/2M/3L/3I),
with `AUDIT_2026-05-18_CROSS_CHECK.md`. Several of its fixes have since been
replaced; see `AUDIT_SCOPE.md` §3.

This document tells the reviewer what we want them to look at, what we are
afraid of, and which residual risks we already accept.

---

## 1. Security objectives (what must hold)

1. **One signature primitive.** SPHINCS+C10 only. There is one
   `c10Verifier` per chain, used by validation, EIP-1271 and the factory.
2. **The bootstrap key is permanent.** Index 0 is installed at deployment
   and never changes. There is no owner removal, `addOwnerBytes` appends at
   `nextOwnerIndex ≥ 2`, and `initialize` is one-shot. The CREATE2 salt
   depends only on the bootstrap key, so replacing it would change the
   address.
3. **Per-chain caps are monotonic and cannot be reset, per index and per
   key.** `bootstrapUses ≤ 65,536`; `slotUses[i] + offchainSigCount[i] ≤ 65,536`.
   There is no reset or increase path. Because the owner set is append-only
   and `addOwner` refuses installed keys, a key keeps one index and one set
   of counters for the life of the wallet.
4. **Role split.**
   - The bootstrap key (`ownerIndex == 0`) may sign only `addOwnerBytes`,
     and never off-chain.
   - Slot keys (`ownerIndex ≥ 1`) may sign only
     `executeWithOffchainCount` / `executeBatchWithOffchainCount` for their
     own index (H-3 parity), and may not call the wallet itself (H-2).
5. **One validated op, at most one execution.** Validation stamps a
   transient per-index credit; each execute consumes one. With no
   preceding validation in the same transaction, execution reverts.
6. **Replay separation.**
   - UserOps: `sphincsDigest` binds `chainId` and the EntryPoint; the
     EntryPoint binds `sender` and nonce.
   - Off-chain signatures: verified over Solady's nested EIP-712 hash,
     bound to `chainId` and the wallet address, on both 1271 entry points.
   - No raw-hash path remains.
7. **CREATE2 squat defence.** The first deployment requires a bootstrap
   signature over `sha256("pqwallet-factory-add-slot" ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)`.
8. **Counterfactual signing.** ERC-6492 blobs carry `factoryCalldata` =
   the exact `createAccount` call whose result is the predicted address.
9. **Address determinism.** The production build reproduces the firmware's
   CREATE2 constants exactly. CI enforces this
   (`DeployedBytecodeReproCheck`, deploy profile).

---

## 2. Areas of concern (where we want eyes)

Roughly in decreasing order of how much they worry us.

### 2.1 Yul C10 verifier (`SPHINCsC10Asm.sol`)

146 SLOC of hand-written Yul. A bug here is a universal forgery. It has
byte-level parity with the Rust reference `sphincs-c10/`: ADRS encoding,
force-zero, htIdx extraction (now also bound into the FORS addresses),
branchless Merkle swap, WOTS+C digit extraction, N-mask truncation and the
length check. KATs (`test/c10_test_vectors.json`,
`test/c10_primitive_kat_vectors.json`) and a mutant corpus
(`test/SPHINCsC10AsmMutantCorpus.t.sol`) back it.

Concerns:
- (a) the `memory-safe` annotation while writing the free-memory pointer
  and zero slot (old M-2);
- (b) bounds of the in-memory work area;
- (c) SHA-256 precompile failure handling;
- (d) anything that makes `verify` return `true` for a signature the Rust
  verifier rejects.

### 2.2 Role split and owner table

- `_validateSignature` checks by selector: index 0 allows only
  `addOwnerBytes`; index ≥ 1 allows only the two execute selectors, with the
  calldata's first word equal to the signing index.
- `addOwnerBytes` requires `msg.sender == entryPoint`; execute paths reject
  `target == address(this)`.
- Owner removal was deleted. A slot-signed op carrying its old selector
  (`0x89625b57`) fails validation and has nothing to dispatch to.

**Question:** is there any other path that lets a slot key reach
`addOwnerBytes`, write the owner table, or act as index 0? Examples:
delegatecall from a target, the receiver hooks, `supportsInterface`, the
legacy 1271 entry, `initialize` on a proxy or on the implementation.

### 2.3 Transient credits (EIP-1153)

`PQSmartWallet.sol`, "Transient validated-op credits".
- Validation stamps `credit[ownerIndex] += 1` at
  `keccak256(ownerIndex, _TS_CREDIT_NAMESPACE)`.
- `execute*WithOffchainCount` consumes one, or reverts `OwnerIndexMismatch`.
- A per-index counter, not a single token, because v0.6 validates every op
  in a bundle before executing any.

Things to verify:
- No path stacks credits without a successful validation.
- A credit stamped for index *i* is never consumable for index *j*.
- A reverting execution rolls back its own decrement, so the credit stays
  live until the end of the transaction. We believe that is harmless,
  because only the EntryPoint can consume it and only with calldata that
  passed validation. The precise claim is "at most one consumed per
  validated op".
- Reentrancy: an execute target calling back into the wallet during
  execution.

### 2.4 Combined per-slot cap arithmetic

- Validation requires `slotUses[i] + offchainSigCount[i] < 65,536` before it
  bumps `slotUses[i]`.
- `_setOffchainSigCount` in the execute path requires
  `slotUses[i] (post-bump) + newOffchainCount ≤ 65,536` and monotonic
  `newOffchainCount`.

**Question:** is there a sequence that lands past the cap, or one that
lets `offchainSigCount` decrease?

### 2.5 EIP-1271: two entry points, nested only

- `isValidSignature(bytes32,bytes)` is Solady's: an ERC-7739 probe, then
  ERC-6492 unwrap, then `_erc1271IsValidSignature`.
- `_erc1271IsValidSignature` is overridden to run only
  `_erc1271IsValidSignatureViaNestedEIP712`, dropping Solady's safe-caller
  and RPC raw-hash workflows (#691).
- `isValidSignature(bytes,bytes)` (new, #995) returns `0x20c13b0b` iff
  `_erc1271IsValidSignature(keccak256(data), sig)`, with no ERC-6492 unwrap.
- `_erc1271IsValidSignatureNowCalldata`: exact 4128-byte wrapper, index 0
  rejected, C10 verify against the slot key.
- `_erc1271Signer()` reverts. It is unreachable, and Slither reports it as
  dead code; it is kept as a tripwire (L-2).

Questions:
- Is there any input that makes either entry point verify a hash other
  than the nested one? Include the TypedDataSign branch of Solady's nested
  workflow, which the device never produces.
- Is the legacy entry safe for callers other than Safe? Such callers pass
  data the device can only sign through its loud "blind RAW32" tier.

### 2.6 Factory squat defence, ETH forwarding, address prediction

- First deployment: the bootstrap signature over the slot-0 digest is
  verified, then `initialize` runs atomically.
- Already deployed: `msg.value` is forwarded by Solady's
  `createDeterministicERC1967`, and the slot-0 arguments are ignored by
  design.
- `getAddress` must equal what the device computes from the firmware
  constants. `test/DeployedBytecodeReproCheck.t.sol` checks this.

### 2.7 ERC-4337 / ERC-7562 validation rules

Validation writes the account's own storage: `bootstrapUses`, `slotUses`,
and transient credits.

- It calls only the immutable verifier, through `staticcall`.
- `test/ERC7562ValidationRules.t.sol` covers the storage and call-graph
  subset.
- **Not covered:** banned opcodes, gas and stack limits, and real bundler
  tracers. Of particular interest: whether v0.6-era tracers accept
  `TSTORE`/`TLOAD` in validation.
- A real C10 validation costs about 230k gas.

### 2.8 Token receiver hooks and ERC-165

Three `pure` hooks always accept, and `supportsInterface` reports three
IDs. There is no fallback.

**Question:** does accepting arbitrary NFTs create any risk beyond spam?
Note that moving an NFT out is blind-signed on the device (§4).

### 2.9 Implementation lock-out

The implementation's constructor installs a dummy owner so `initialize`
reverts on the implementation. Proxies start empty. Never delegate an EOA
to the implementation with EIP-7702: anyone could then `initialize` it.

---

## 3. Worst cases (in terms of money moving)

1. **Forge a C10 signature.** That drains every wallet of that seed, on
   every chain. Defended by the verifier's correctness plus SPHINCS+C
   EUF-CMA.
2. **Squat a victim's address on an unused chain.** Defended by the
   factory signature.
3. **Slot-key escalation to bootstrap powers (H-2):** a full takeover.
4. **Cross-slot counter poisoning or credit theft (H-3):** freezes a
   victim slot.
5. **Bootstrap-budget under-count:** reopens few-time forgery on the
   master key. Fixed by counting in validation.
6. **Per-key budget reset by re-installing a key (#131):** reopens
   few-time forgery on a slot key. Closed by deleting removal.
7. **A public UserOp signature presented as an EIP-1271 signature (#691).**
   Closed with the raw-hash workflows.
8. **EntryPoint impersonation:** reaching execution without validation.

---

## 4. Accepted residual risks (please confirm the reasoning, not re-litigate the decision)

These are owner decisions recorded before the freeze.

- **No on-chain key revocation.**
  - What a leaked slot key can do:
    - sign UserOps until its per-chain cap (65,536 combined) is spent;
    - sign EIP-1271 signatures indefinitely: those are `view` and uncapped
      on-chain, even after the slot is exhausted (#89).
  - Recovery means moving funds to a new account index. The device could
    never produce a removal anyway.
  - The removed function also let any slot key delete the others.
- **No in-wallet spending policy (#867).** There is no guard hook, delay or
  cap on value. Funds at the wallet's own address are not protected against
  a leaked seed. A separate vault contract can be added later without
  touching the wallet.
- **Out-of-order slot registration.**
  - The device signs a slot key for `ownerIndex = slot_index + 1`, but
    `addOwnerBytes` installs at whatever `nextOwnerIndex` is. A misordered
    registration puts a key at an index the device will never sign for.
  - With the owner set append-only, that key is dead on that chain; the
    bootstrap use is spent.
  - Companions must check `nextOwnerIndex == slot_index + 1` before a
    rotation.
- **Off-chain budget is device-local.**
  - `offchainSigCount` is what the firmware reports.
  - Two devices on one seed, or a restore that loses the device's counter
    page, can exceed the per-key budget off-chain (#89, #179).
- **The bootstrap key's budget is per chain, but the key is not.** The same
  master key signs on every chain, and its factory signatures (one per
  chain) are not counted in `bootstrapUses`. The per-key bound across *C*
  chains is *C* × 65,536 (documented P14 caveat).
- **NFT outflows are blind-signed.** The firmware has no ERC-721/1155
  transfer decoder, so moving a received NFT goes through the loud blind
  path.
- **Chain requirements.**
  - Cancun or later (`TSTORE`/`TLOAD`, `evm_version = prague`), EntryPoint
    v0.6 at its canonical address, and the Arachnid deployer.
  - On any other chain the address may exist but cannot validate.
  - EntryPoint v0.6 is frozen by design.
- **Safe-side caveat for the legacy entry.** Safe v1.3.0's public
  `checkNSignatures(dataHash, data, …)` does not check that `data` hashes to
  `dataHash`. A third-party module passing mismatched values obtains the
  wallet's approval of `keccak256(data)`, the hash the user signed.

---

## 5. Specific questions

1. Does `SPHINCsC10Asm`'s `memory-safe` annotation hold given its writes to
   `0x40` and `0x60`, under current and future solc?
2. Can a credit be consumed for a different index than the one validated,
   or twice for one validation, under any reentrancy shape?
3. Is the masked tail-pad check (`calldataload(sig + 4096)` & low 24 bytes)
   exactly the ABI padding of the 4128-byte wrapper?
4. Are the pre-bump strict `<` (validation) and post-bump `≤` (execution)
   cap checks equivalent in every interleaving, including several ops for
   one slot in one bundle?
5. Does the manual wrapper parse accept anything `abi.decode` would reject,
   or reject anything it would accept, in a way that matters?
6. Can either EIP-1271 entry be made to accept a signature over a value
   other than the nested hash? Consider ERC-6492 wrappers, the ERC-7739
   probe, and the TypedDataSign branch.
7. ERC-6492: does `factoryCalldata` = `initCode[20:]` always reproduce the
   predicted address, and does the counterfactual signature stop verifying
   on every other chain?
8. Is anything in validation incompatible with ERC-7562 as enforced by
   production v0.6 bundlers (transient storage, storage writes, gas)?
9. Is `uint64(block.chainid)` in the factory a problem on any realistic
   target chain?

---

## 6. Already settled (re-derive if you like; we are not asking for re-attestation)

- ERC-7201 slot derivation and no collision with upstream
  (`test/StorageSlotParity.t.sol`).
- `c10Verifier`, `_entryPoint` and the factory's `implementation` are
  immutable. There is no upgrade path: the wallet inherits no upgrade
  mechanism, and nothing writes the ERC-1967 implementation slot
  (`invariant_impl_slot_unchanged`).
- Real-signature validation gas is about 230k (verifier about 180k).
- Codehash pinning of the production build, and the CREATE2 constants
  matching the firmware (CI).
- The formal verification is described in
  `../verification/docs/THE_CLAIM.md`. It covers control flow on the
  compiled bytecode (Halmos and Kontrol) and the Lean models. Theft-freedom
  rests on the cited EUF-CMA assumption, not on a composed proof.
