# PQSmartWallet — Audit Review Goals

**Project:** PQ1 hardware wallet, on-chain account-abstraction contracts.
**Scope:** `contracts/smart-wallet/src/` + the Yul SPHINCS+C10 verifier.
**Prior review:** `AUDIT_2026-05-18.md` (3H/2M/3L/3I, all fixed; see
`AUDIT_2026-05-18_CROSS_CHECK.md` for verification).

This document tells the next reviewer what we want them to look at, what
we're afraid of, and what we've already convinced ourselves of.

---

## 1. Scope (in / out)

In-scope production Solidity + Yul (1,280 LoC):

| File | LoC | Purpose |
|------|----:|---------|
| `src/PQSmartWallet.sol` | 569 | ERC-4337 v0.6 account behind ERC-1967 proxy. `validateUserOp`, `execute*WithOffchainCount`, EIP-1271, addOwner/removeOwner. |
| `src/PQMultiOwnable.sol` | 267 | ERC-7201 storage: `ownerAtIndex`, `bootstrapUses`, `slotUses[i]`, `offchainSigCount[i]` + bumps. |
| `src/PQSmartWalletFactory.sol` | 148 | CREATE2 ERC-1967 proxy factory; bootstrap-sig squat defence. |
| `src/verifiers/SPHINCsC10Asm.sol` | 228 | Stateless Yul C10 verifier (hypertree + FORS + WOTS+C). Single immutable, reused for Type 1 / Type 2 / EIP-1271. |
| `src/verifiers/ISPHINCSVerifier.sol` | 20 | Verifier interface (test/prod swap). |
| `src/generated/PqsignerProto.sol` | 48 | Auto-generated from `pqsigner-proto` Rust IDL; CI-checked for drift. |

Out of scope (but relevant context):

- `lib/solady`, `lib/account-abstraction` (pinned versions).
- `reference/` — upstream Coinbase Smart Wallet fork-base, kept for diff.
- `test/`, `certora/`, `script/`, `broadcast/`.
- Firmware (`secure/`, `nonsecure/`) — separate review.
- EntryPoint v0.6 itself (battle-tested, unchanged).

The verifier is a coupled unit with the wallet: same chain, same
deployment, called via `try c10Verifier.verify(...) returns (bool)`.

---

## 2. Security objectives (what must hold)

These are the CLAUDE.md invariants that this contract enforces:

1. **One signature primitive.** SPHINCS+C10 only — no ECDSA / P-256 /
   Ed25519 fallback anywhere in the wallet code path. Verify by reading
   the source: there is one `c10Verifier`.
2. **Bootstrap key immutable per wallet.** `_removeOwnerAtIndex` rejects
   index 0; no `rotateMasterKeys`; CREATE2 salt depends only on
   `(masterPkSeed, masterPkRoot)` so any rotation would change the
   address.
3. **Per-chain caps monotonic, unresettable.** `bootstrapUses <
   MAX_BOOTSTRAP_USES = 65,536`; `slotUses[i] + offchainSigCount[i] <
   MAX_SLOT_USES = 65,536`. No reset/increase path exists.
4. **Role split between bootstrap and slot keys.**
   - Bootstrap (`ownerIndex == 0`) can sign **only**
     `addOwnerBytes(...)` UserOps. Forbidden from EIP-1271.
   - Slot (`ownerIndex >= 1`) can sign **only**
     `executeWithOffchainCount` / `executeBatchWithOffchainCount` /
     `removeOwnerAtIndex`. Cannot self-call (would re-enter
     `addOwnerBytes`). Cannot add owners.
5. **Cross-chain / cross-wallet replay resistance.** `sphincsDigest`
   binds `chainId + entryPoint`; EIP-1271 path nests via Solady EIP-712
   binding `chainId + verifyingContract`.
6. **No new per-signature persistent state.** Off-chain sig count is the
   only per-slot counter beyond `slotUses`; bumped only on signed
   `executeWithOffchainCount(...)`.
7. **CREATE2 squat defence.** Factory requires a bootstrap C10 sig over
   `sha256(DOMAIN || chainId || slot0PkSeed || slot0PkRoot)` on first
   deploy. Same 24 words → same address on every chain, but only the
   bootstrap-key holder can populate slot 0.
8. **Counterfactual signing works.** EIP-6492 wraps `(factory,
   factoryCalldata, sigWrapper) || 0x6492…6492`; `factoryCalldata` must
   match the calldata whose hash is baked into the CREATE2 address.

---

## 3. Areas of concern (where we want eyes)

Listed in roughly decreasing order of "this is the part that scares
us." Items already audited in 2026-05-18 are marked **[re-check]** —
fixes landed in `aa537ad`.

### 3.1 Yul C10 verifier (`SPHINCsC10Asm.sol`)

228 lines of Yul implementing SPHINCS+C10 verification. Byte-level
parity with Rust `sphincs-c10/` reference. Previously cross-checked at
the byte level (ADRS encoding, force-zero, htIdx extraction, branchless
Merkle swap, WOTS+C digit extraction, N-mask truncation, length check).

Concerns: (a) memory-safe annotations write the FMP and zero slot —
**[re-check M-2]** — confirmed safe in audit but want second eyes; (b)
absence of bounds checks on the in-memory work area; (c) any
divergence in SHA-256 precompile error handling.

### 3.2 Transient-storage one-shot tokens (EIP-1153)

`PQSmartWallet.sol:97-98` defines two transient slots:

- `_TS_VALIDATED_OWNER_INDEX_PLUS_ONE` (slot 0) — written by
  `_validateSignature` for slot-key UserOps (offset +1; 0 sentinel
  means "no validation in this tx"); read+cleared by
  `executeWithOffchainCount` / `executeBatchWithOffchainCount`. This is
  the **fix for H-3** (cross-slot offchainSigCount poisoning).
- `_TS_PENDING_BOOTSTRAP_BUMP` (slot 1) — set by `_validateSignature`
  for bootstrap UserOps; read+cleared by `addOwnerBytes` to defer the
  bootstrap counter bump until after `_addOwner` succeeds. This is the
  **fix for M-1** (counter consumed on reverted execution).

**Things to verify:**

- Token clearing is unconditional after read (not skipped on early
  revert paths).
- No path in this tx can re-enter `_validateSignature` and stack a
  second token before the execute consumes the first.
- The +1 offset is preserved everywhere (no place writes a raw
  `ownerIndex` to the slot).
- Bundlers that batch multiple UserOps within one bundle each get their
  own validate → execute pair separated by EntryPoint's
  `_innerHandleOp`, so tokens cannot leak across UserOps in a bundle.
  **(Halmos contracts in `test/halmos/` discharge this; please confirm
  the contract bounds match the spec.)**

### 3.3 Role split between bootstrap and slot keys **[re-check H-2]**

- `_validateSignature` enforces by selector: `ownerIndex == 0` ⇒
  selector must be `addOwnerBytes.selector`; `ownerIndex >= 1` ⇒
  selector must be in `_isSlotAllowedSelector` (execute / executeBatch
  / removeOwnerAtIndex).
- `addOwnerBytes` is `onlySelf` (`msg.sender == address(this)`).
- `executeWithOffchainCount` / `executeBatchWithOffchainCount` reject
  `target == address(this)` (closes the self-call escape — H-2 fix).

Question: are there any other ways a slot key can cause `address(this)`
to be the caller of `addOwnerBytes`?

- Solady multicall? Not exposed.
- Static delegatecall through a target that delegatecalls back? Slot
  execute is `target.call`, not `delegatecall`; targets cannot fake
  `msg.sender`.
- ERC-721/1155 receiver hooks? `receive() external payable {}` is bare;
  no token receiver overrides.

### 3.4 Combined per-slot cap arithmetic **[re-check H-3]**

`slotUses[i] + offchainSigCount[i] < MAX_SLOT_USES` (pre-bump) at
validate; `slotUses[i] + offchainSigCount[i] <= MAX_SLOT_USES`
(post-bump, after validate's `_bumpSlotUses(+1)`) at execute. Note the
off-by-one shift — the test in `_validateSignature` is strict-`>=`,
in `executeWithOffchainCount` the cap check is inside
`_setOffchainSigCount` and is `>`.

Question: any way to land at exactly `MAX_SLOT_USES` via a sequence
that side-steps the post-bump check?

### 3.5 Wrapper ABI parse (`SignatureWrapper`)

`_validateSignature` and `_erc1271IsValidSignatureNowCalldata` both
manually parse `abi.encode(uint256 ownerIndex, bytes sig)` rather than
using `abi.decode`. Parse asserts: exact length `96 + paddedInner`,
offset field == 0x40, inner length == 4008, **tail-pad == 0**
**[re-check L-1]**. Why manual: a `4128`-byte memory expansion per
validate is ~3k gas, and the parse is verbatim across `validateUserOp`
and `isValidSignature`.

Question: are there ABI-encoded wrappers our manual parse accepts that
`abi.decode` would reject (or vice versa)?

### 3.6 Factory squat defence + ETH forwarding **[re-check H-1]**

`createAccount`:

- First-deploy path: verify factorySig over
  `sha256(DOMAIN || chainId || slot0PkSeed || slot0PkRoot)`.
- Subsequent-deploy path: skip squat re-check, forward `msg.value` via
  `LibClone.createDeterministicERC1967`'s built-in already-deployed
  branch (which uses `call`, not stranding ETH — **H-1 fix**).

Questions:

- Is the `LibClone.createDeterministicERC1967` already-deployed branch
  guaranteed to forward `msg.value`? Confirm against Solady's source.
- Does the second-call path actually update the wallet's owners if a
  legitimate user re-runs with new slot0 bytes? (Answer: no — by design;
  factory ignores `slot0*` args once the wallet exists. Document and
  confirm UX.)
- `WrongChainId` carries `(uint64(block.chainid), chainId)` — fine on
  chains where `block.chainid` fits in `uint64`. Any deployment target
  where it would not?

### 3.7 EIP-1271 + ERC-6492 (off-chain sig)

- Inherits Solady `ERC1271`.
- Override: `_erc1271Signer()` reverts as a tripwire if some future
  refactor drops the `_erc1271IsValidSignatureNowCalldata` override
  **[re-check L-2]**.
- Bootstrap (`ownerIndex == 0`) forbidden from off-chain validate.
- ERC-6492 path: dapp-side validator must check `signer == predicted
  CREATE2 address` **[re-check I-3]**.

Question: Solady's `ERC1271` has had several revisions for nested
EIP-712 handling. Is the version we pinned (`lib/solady`) compatible
with the assumptions in `_erc1271IsValidSignatureNowCalldata`? See
`docs/companion-app-integration.md` for the firmware-side wrapping that
must remain in lockstep.

### 3.8 ERC-7201 storage **[re-check]**

Slot derived from `"pqsigner.storage.PQMultiOwnable"` — pinned in
`test/StorageSlotParity.t.sol`. No collision with Coinbase upstream
slot. Confirm pinning catches accidental tag rename.

### 3.9 Impl lockout

Constructor seeds a dummy `(bytes32(0), bytes32(0))` owner at index 0
so `nextOwnerIndex() != 0` on the impl, making `initialize` revert if
called directly. Proxies have empty storage so they still initialise.

Question: does any path on the impl let `initialize` slip through —
e.g. via a transient-storage trick or a `delegatecall` from somewhere
unexpected?

---

## 4. Worst-case scenarios

The PR description for the audit doc should be in terms of "money
moves." Listed worst-first:

1. **Forge a C10 signature.** Drains every wallet on every chain that
   shares the bootstrap pubkey (= 256 wallets per seed, every chain).
   Mitigated by SPHINCS+ EUF-CMA + 16-byte N-mask security; mostly out
   of scope for the contract audit, but the verifier must implement the
   spec faithfully.
2. **Squat the victim's wallet address on an unused chain.** Pre-fix
   for squat defence: attacker installs their own slot 0 and exfiltrates
   funds sent to the predicted address. Mitigated by `factorySig`.
3. **Slot-key escape to bootstrap-only operations** (audit H-2 closed).
   Promote a compromised slot key to add owners → full wallet takeover.
4. **Cross-slot off-chain count poisoning** (audit H-3 closed). One
   compromised slot key flips another slot's counter to its cap,
   freezing the victim slot.
5. **Bootstrap-budget exhaustion via failed UserOps** (audit M-1
   closed). Burn the 16-bit bootstrap budget by sending UserOps that
   revert in execution.
6. **ETH stranded on factory** (audit H-1 closed). Lost funds on
   re-deploy with attached value.
7. **EntryPoint impersonation.** All `onlyEntryPoint` checks pin
   `msg.sender == address(_entryPoint)` (immutable). Verify there is no
   alternate path that confuses `msg.sender` (e.g. trusted forwarder).
8. **Cross-chain replay of an EIP-1271 sig** — Solady's nested EIP-712
   binds `chainId + verifyingContract`. Verify our override does not
   bypass this.

---

## 5. Specific questions for auditors

1. Does the Yul verifier's `memory-safe` block annotation actually hold
   given that we write to the Solidity FMP (`0x40`) and zero slot
   (`0x60`)? Audit M-2 concluded "yes by Solidity's docs"; is the
   reasoning robust under future solc?
2. Are the two transient-storage tokens **provably** one-shot under
   every reentrancy shape we can construct? In particular: a slot-key
   UserOp whose target is a contract that calls back into the wallet's
   public functions during execution.
3. The `tailPad` check at `_validateSignature:375-378` uses a masked
   read of the last word. Is the mask correct given Solidity's
   right-aligned `bytes` ABI encoding for the 4128-byte wrapper?
4. The combined-cap pre-bump strict-`>=` vs post-bump strict-`>` shift
   — is there a sequencing where these are not equivalent?
5. Does the absence of a `multicall` or `executeBatch` that ALSO
   accepts `target == this` open any social-engineering / dapp
   ergonomics gap relative to upstream Coinbase Smart Wallet that users
   will hit?
6. The factory unconditionally forwards `msg.value` via Solady. What is
   the gas profile of that forward when the wallet is already deployed
   and has a single bare `receive()`? Could a hostile target chain
   intentionally bork it?
7. Counterfactual EIP-6492 mode: the firmware mints `signatureWrapper =
   abi.encode(1, c10Sig)` (ownerIndex 1 = slot 0 in our scheme).
   `factoryCalldata` must match exactly the calldata the factory will
   be invoked with at deploy. Any byte that differs causes the
   `address(this)` recovery inside Solady's ERC-6492 unwrap to point at
   a different CREATE2 address. We rely on a single canonical encoding
   — please cross-check against the Solady deployer side.

---

## 6. What we believe is already settled (from 2026-05-18 + tests)

Items the prior audit explicitly checked and passed. The auditor is
welcome to re-derive, but we are not asking for re-attestation:

- Verifier byte parity with Rust reference (ADRS, force-zero, hash
  inputs, N-mask).
- ERC-7201 slot non-collision.
- `_removeOwnerAtIndex` blocking index 0.
- `c10Verifier` and `_entryPoint` immutables; no UUPS upgrade path.
- Real-sig `validateUserOp` gas: 229,830 (verifier alone: 180,306) —
  within mainstream bundler caps.
- Bytecode-freeze defense-in-depth via codehash pinning
  (`test/PinnedCodehashes.t.sol`).

---

## 7. Out-of-scope but related

- `secure/` firmware (Rust no-std) — separate audit track.
- `pqsigner-proto`, `pqsigner-tx`, `pqsigner-domain` workspace crates —
  produce the auto-generated `PqsignerProto.sol`; CI drift check.
- EntryPoint v0.6 itself (vetted upstream).
- The verifier's SHA-256 precompile (Ethereum-native).

We will **not** be migrating to EntryPoint v0.7 / v0.8: the v0.6
address and ABI are baked into `initCode`, the userOpHash preimage, and
the factory, so a version bump would break invariant #6 (same 24 words
→ same address on every chain). See `CLAUDE.md` "What NOT to do".
