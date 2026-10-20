# Trail of Bits — Pre-Meeting Intake

Updated 2026-10-20 for the audit freeze (`AUDIT_SCOPE.md` §1).

## 1. What the software is

The on-chain side of **PQ1**, a post-quantum ERC-4337 **v0.6** smart-account
wallet. It is a fork of Coinbase Smart Wallet with every classical signer path
deleted; the only accepted signature primitive is **SPHINCS+C10** (hash-based,
SHA-256, 4008-byte signatures).

- Signatures come from the PQ1 hardware device (STM32U585 with two secure
  elements). A companion app builds the UserOp, the device signs it, and a
  4337 bundler submits it.
- The same 24-word seed gives the same wallet address on every EVM chain
  where the contract set is deployed (CREATE2 salt =
  `sha256(masterPkSeed‖masterPkRoot)`; contracts deployed through the
  Arachnid deterministic deployer).
- End users are retail self-custody customers.
- Nothing is deployed for users yet; the freeze set is not deployed on any
  chain.

## 2. SLOC (excluding blank lines and comments)

| File | Lang | SLOC |
|---|---|---:|
| `src/PQSmartWallet.sol` | Solidity | 342 |
| `src/PQMultiOwnable.sol` | Solidity | 119 |
| `src/PQSmartWalletFactory.sol` | Solidity | 71 |
| `src/verifiers/SPHINCsC10Asm.sol` | Yul in Solidity | 146 |
| `src/verifiers/ISPHINCSVerifier.sol` | Solidity | 9 |
| `src/generated/PqsignerProto.sol` | Solidity (generated constants) | 12 |
| **Total** | | **699** |

1,421 lines including comments and blank lines.

## 3. Third-party dependencies and forks

- **Forked from** [`coinbase/smart-wallet`](https://github.com/coinbase/smart-wallet)
  at `503363d7`. Removed: all classical owner types, cross-chain replayable
  nonces, the UUPS upgrade path, and (at this freeze) owner removal. Added:
  the bootstrap/slot role split, per-key usage caps, transient
  validated-op credits, and the SPHINCS+ verifier.
- **Dependencies** (restored at exact `foundry.lock` revisions, not git
  submodules):
  - `solady` v0.1.26: `ERC1271`, `EIP712`, `SignatureCheckerLib`,
    `LibClone`.
  - `account-abstraction` (the `legacy/v06` interfaces only).
  - OpenZeppelin and forge-std (tests only).
- **Written from scratch:** the Yul `SPHINCsC10Asm.sol` verifier. No
  upstream Solidity verifier exists for the C10 parameter set.

## 4. Open source?

Not yet public. We will give the review team access to the repository at the
freeze tag. The contracts will be released under MIT, matching upstream.

## 5. Greatest concerns

1. **Yul C10 verifier correctness.** 146 SLOC of hand-written assembly; any
   bug is a universal forgery.
2. **Bootstrap vs. slot role split.** The bootstrap key (index 0) may only
   `addOwnerBytes`; slot keys (index ≥ 1) may only call the two
   `execute*WithOffchainCount` paths for their own index. Any path that lets
   one act as the other is catastrophic.
3. **Transient (EIP-1153) validated-op credits.** One validation must buy at
   most one execution for exactly the signing slot, including with several
   ops for one wallet in one bundle.
4. **Usage caps.**
   - `bootstrapUses ≤ 65,536` and `slotUses[i] + offchainSigCount[i] ≤ 65,536`.
   - Monotonic, with no reset path.
   - Per key as well as per index: the owner set is append-only, so a key
     can never be re-installed with fresh counters.
5. **EIP-1271.**
   - Two entry points: `isValidSignature(bytes32,bytes)`, and the legacy
     `(bytes,bytes)` form that Safe v1.3.0 / v1.4.1 use.
   - Both must accept only Solady's nested EIP-712 forms, which bind the
     wallet and the chain (PersonalSign, which the device signs, and
     TypedDataSign, which it never produces), never a bare hash.
   - Public UserOp signatures are over bare SHA-256 digests.
6. **CREATE2 squat defence and ERC-6492.** The factory requires a bootstrap
   signature over `sha256("pqwallet-factory-add-slot" ‖ chainId ‖ slot0PkSeed ‖ slot0PkRoot)`.
   Counterfactual signatures must not verify on any other chain.
7. **Address determinism.** The production build must reproduce the CREATE2
   constants compiled into the device firmware. CI checks this.
8. **EntryPoint v0.6 is frozen.** Its address and ABI are baked into
   `initCode`, the signed digest and the factory. There is no v0.7/v0.8
   migration.

Accepted residual risks, which we would like confirmed rather than reported
as new findings, are listed in `AUDIT_REVIEW_GOALS.md` §4. They include no
on-chain key revocation, no in-wallet spending policy, and EIP-1271
signatures not counting against on-chain caps.
