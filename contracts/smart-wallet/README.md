# PQSmartWallet

The on-chain half of **PQ1**, a post-quantum hardware wallet: an ERC-4337
**EntryPoint v0.6** smart account whose only signature scheme is
**SPHINCS+C10** (hash-based, SHA-256; 4008-byte signatures). There is no
ECDSA, P-256 or other classical signer anywhere in the contracts. Signatures
come from the PQ1 device; a companion app builds UserOps and a bundler submits
them.

Forked from [`coinbase/smart-wallet`](https://github.com/coinbase/smart-wallet)
(upstream commit `503363d7`, "Add warning for safe 7702 upgrades (#156)"), with
every classical owner type, the cross-chain replayable-nonce path and the UUPS
upgrade path removed.

## Contracts (`src/`)

| File | Role |
|---|---|
| `PQSmartWallet.sol` | The account implementation behind every user's ERC-1967 proxy: `validateUserOp`, the two slot execute paths, `addOwnerBytes`, EIP-1271 (both forms), token receiver hooks |
| `PQMultiOwnable.sol` | ERC-7201 storage: append-only owner table and the per-chain usage counters |
| `PQSmartWalletFactory.sol` | CREATE2 factory for the proxies; requires a bootstrap-key signature over the slot-0 key (squat defence) |
| `verifiers/SPHINCsC10Asm.sol` | Stateless SPHINCS+C10 verifier in Yul (uses the SHA-256 precompile) |
| `verifiers/ISPHINCSVerifier.sol` | Verifier interface |
| `generated/PqsignerProto.sol` | Constants generated from the firmware's `proto` crate (`cargo run -p pqsigner-xtask -- gen-solidity-constants`); CI fails on drift |

## How it works

**Owners.** Each owner is a C10 public key, 64 bytes = `pkSeed (32) ‖ pkRoot (32)`,
both in the N-mask layout (low 16 bytes zero).

- **Index 0, the bootstrap key**, is installed at deployment and never changes.
  It may sign exactly one thing: `addOwnerBytes(newSlotKey)`. Its few-time
  budget is `bootstrapUses ≤ 65,536` per chain, counted in the validation
  phase.
- **Indices ≥ 1, slot keys**, sign everything else, through exactly two
  selectors: `executeWithOffchainCount` and `executeBatchWithOffchainCount`.
  Each slot index has a combined per-chain budget
  `slotUses[i] + offchainSigCount[i] ≤ 65,536`.
- **The owner set is append-only.** There is no owner removal. The device
  rotates to a new slot by having the bootstrap key add one. A key that was
  ever installed can never be installed again (`AlreadyOwner`), so its
  counters can never be reset.

**Validation.** `PQSmartWallet` ignores the EntryPoint's keccak `userOpHash`
and verifies over `sphincsDigest(userOp)`, a SHA-256 hash of the UserOp fields
plus the EntryPoint address and `block.chainid`, because the device has a
SHA-256 accelerator and no keccak. The signature is
`abi.encode(uint256 ownerIndex, bytes c10Sig)` with an exact 4128-byte layout
(zero ABI tail pad enforced). For a slot op, the calldata's first argument
must equal the signing `ownerIndex` (audit H-3); validation stamps a transient
(EIP-1153) per-index credit that the matching execute consumes. Execute paths
reject calls to the wallet itself (audit H-2).

**Off-chain signatures (EIP-1271).** Two entry points:

- `isValidSignature(bytes32 hash, bytes sig)`, returning `0x1626ba7e`; and
- `isValidSignature(bytes data, bytes sig)`, the legacy form Safe v1.3.0 and
  v1.4.1 call on a contract owner, returning `0x20c13b0b` for `hash = keccak256(data)`.

Both verify the slot key's signature over one of Solady's two nested EIP-712
forms, each bound to this wallet and `block.chainid`: the PersonalSign hash
("replay-safe hash"), which is the only thing the device signs off-chain, and
the TypedDataSign hash, which the device never produces. Solady's two raw-hash
workflows are disabled. The bootstrap key is never accepted off-chain. EIP-1271 is `view`;
it consumes no on-chain budget. The firmware reports its off-chain count on
the next UserOp, where `offchainSigCount` enforces the combined cap.

**Tokens.** `receive()` accepts ETH. `onERC721Received`, `onERC1155Received`
and `onERC1155BatchReceived` accept every token, and `supportsInterface`
reports ERC-165, ERC-721 receiver and ERC-1155 receiver. There is no fallback
function, so calls to unknown selectors revert.

**Deployment.** The verifier, implementation and factory are deployed through
Arachnid's deterministic CREATE2 deployer (`0x4e59…956C`, salt 0) from the
`deploy` Foundry profile. The build sets `bytecode_hash = "none"`, so the
addresses depend only on the code and compiler settings, not on comments or
paths. Every user wallet is a 61-byte ERC-1967 proxy at
`CREATE2(factory, sha256(masterPkSeed ‖ masterPkRoot), proxyInitCode(impl))`;
the device computes the same address from two constants compiled into its
firmware (`proto/src/lib.rs`), mirrored in
`script/generated/PqsignerDeployment.sol`. The same seed therefore yields the
same wallet address on every chain where this exact contract set is deployed.
That requires Cancun or later, EntryPoint v0.6 at its canonical address, and
the Arachnid deployer.

There is no upgrade path. A contract change means a new implementation, a
new factory, new wallet addresses and new firmware constants.

**Do not delegate an EOA to the implementation with EIP-7702.** The EOA would
run this code against its own empty storage, so anyone could call
`initialize` and install their own keys.

## Addresses

The audit-freeze set (computed, not yet deployed on any chain):

| Contract | Address |
|---|---|
| `SPHINCsC10Asm` | `0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4` |
| `PQSmartWallet` (implementation) | `0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011` |
| `PQSmartWalletFactory` | `0xE3dbA404dCeC30093DE26764965a51689C1607BD` |
| proxy init-code hash | `0x17ca674095afe9dc82aa6f396ee01bd837449a127b6be59a0d947329f29b2570` |

`deployments/` records what is actually on chain. The 2026-06 Base Mainnet set
and the older Base Sepolia and Ethereum Mainnet sets are superseded; the
firmware no longer targets them.

## Build and test

Requirements: Foundry **v1.8.3** (the version CI pins), git, jq. `lib/` is not
a set of submodules: restore each dependency at its exact `foundry.lock`
revision. CI does exactly this, and the codehash pins assume the exact set.

```bash
cd contracts/smart-wallet
declare -A URL=(
  [forge-std]=https://github.com/foundry-rs/forge-std
  [solady]=https://github.com/vectorized/solady
  [account-abstraction]=https://github.com/eth-infinitism/account-abstraction
  [openzeppelin-contracts]=https://github.com/openzeppelin/openzeppelin-contracts
  [p256-verifier]=https://github.com/daimo-eth/p256-verifier
  [safe-singleton-deployer-sol]=https://github.com/wilsoncusack/safe-singleton-deployer-sol
  [webauthn-sol]=https://github.com/base-org/webauthn-sol
)
for key in $(jq -r 'keys[]' foundry.lock); do
  name="${key#lib/}"; rev=$(jq -r --arg k "$key" '.[$k].rev' foundry.lock)
  git clone -q "${URL[$name]}" "lib/$name" && git -C "lib/$name" checkout -q "$rev"
done

forge build
forge test                                   # unit, fuzz, invariant, real-signature tests
FOUNDRY_PROFILE=deploy forge test \
  --match-contract 'PinnedCodehashesTest|PinnedBytecodeImmutableLemmaTest|DeployedBytecodeReproCheckTest'
                                             # production codehashes, addresses and firmware constants
pip install slither-analyzer==0.11.6 && slither .   # config: slither.config.json
FOUNDRY_PROFILE=deploy forge script script/PrintProductionAddresses.s.sol
```

The sources import only `account-abstraction` (EntryPoint v0.6 interfaces
under `contracts/legacy/v06/`) and `solady` (`ERC1271`, which pulls in
`EIP712` and `SignatureCheckerLib`, and `LibClone`). OpenZeppelin and
forge-std appear in tests only.

Deploy with the chain-specific scripts, e.g.
`FOUNDRY_PROFILE=deploy forge script script/DeployImplAndFactoryBaseMainnet.s.sol --rpc-url <rpc> --account <name> --broadcast`.
`script/ProductionDeploy.sol` refuses to broadcast unless the predicted
addresses equal the firmware's constants. It routes every deployment through
the Arachnid deployer with an explicit call, because Foundry 1.8's
`new X{salt}` bypasses it when the broadcaster is an EIP-7702-delegated
account.

## Assurance

- Tests: `test/` (unit, stateful invariants, ERC-4337/ERC-7562 validation
  rules, ERC-6492, real firmware signatures, verifier KATs and a mutant
  corpus, codehash pins).
- Symbolic execution on the compiled bytecode:
  - `test/halmos/` — run with `make -C ../verification verify-bytecode`.
  - `../verification/kontrol/` — run with `make -C ../verification verify-kontrol`.
- Lean 4 models and proofs: `../verification/lean/`. See
  `../verification/docs/THE_CLAIM.md` for what is and is not proven.
- Audit preparation: `AUDIT_SCOPE.md` (start here), `AUDIT_REVIEW_GOALS.md`,
  `AUDIT_DIAGRAMS.md`, `AUDIT_STATIC_ANALYSIS.md`, `TOB_INTAKE.md`.
  `AUDIT_2026-05-18.md` is an earlier internal review, not a third-party audit.

## License

MIT, see `LICENSE.md` (inherited from upstream Coinbase Smart Wallet).
