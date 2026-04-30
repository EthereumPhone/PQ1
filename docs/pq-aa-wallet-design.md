# Post-Quantum ERC-4337 Wallet: Final Design Spec

> **🟠 Design archive — superseded on parameter choice (2026-04-30 audit).**
>
> This is the original two-tier design spec from 2026-04-09. The two-tier
> architecture itself (bootstrap key + per-slot keys, BIP-85 derivation, stable
> cross-chain CREATE2 address, on-chain rotation budget) is still the shipping
> design — the on-chain contracts, factory, slot registration, and recovery
> flows all match what's deployed.
>
> What changed is **the signature primitive**:
>
> | Doc says (2026-04-09)             | Shipping (post 2026-04-17)        |
> |-----------------------------------|------------------------------------|
> | Bootstrap = ML-DSA-44             | Bootstrap = SPHINCS+C10            |
> | Main = XMSS h=20 *or* SPHINCS+    | Slot = SPHINCS+C10 (same as boot)  |
> | "~2^20 sigs per keypair" budget   | `MAX_SLOT_USES = 65,536` per chain |
> | "Two PQ verifiers in the wallet"  | One `c10Verifier` shared by both   |
>
> The all-C10 cutover (commit `7b2a339`) collapsed the two signer classes onto
> a single primitive: 4008-byte signatures, SHA-256, single Yul Solidity
> verifier (`SPHINCsC10Asm.sol`) reused for Type 1 / Type 2 / EIP-1271. ML-DSA
> verifier work and XMSS state-tracking infrastructure are no longer in scope;
> the rationale below for *why* they were considered is preserved as historical
> context for the parameter-set decision.
>
> Current authoritative spec:
> - `CLAUDE.md` § "Recovery / Key derivation" — actual KDF tags, slot derivation
> - `contracts/smart-wallet/src/PQSmartWallet.sol` — `validateUserOp` dispatch
> - `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` — the verifier
> - `docs/companion-app-integration.md` — wire format

A hardware-wallet-backed, seed-phrase-recoverable, post-quantum ERC-4337 account abstraction wallet. Built as a fork of Coinbase Smart Wallet, modified for stateful hash-based PQ signers with unlimited rotations and stable cross-chain addresses.

## Design goals

1. **Stable address across all chains**, forever, regardless of rotation history on any individual chain
2. **Unlimited rotations** of the main signer, recoverable deterministically from the BIP-39 seed phrase
3. **Zero cryptographic contamination** between chains — one chain's signing activity never weakens another's
4. **Crash-consistent state management** — losing the hardware device and recovering on a new one is always safe, with no risk of OTS index reuse
5. **Production compatibility with Gnosis Safe and CowSwap today**, without relying on ERC-6492 adoption
6. **Graceful handling of the stateful hash-based signature budget** (~2^20 signatures per keypair)

---

## Core architectural decisions

### 1. Two-tier signer architecture

The wallet has **two classes of signer**, both derived from the same BIP-39 seed:

- **Bootstrap signer**: a single, stateless PQ keypair (ML-DSA-44 recommended, ~2.4 KB signatures). Used only for administrative operations: initial deployment on each chain, and emergency rotation if state is lost. Never rotates. One key for the lifetime of the wallet.
- **Main signer**: the active signing key for day-to-day transactions on a specific chain. Stateful hash-based (XMSS h=20 or SPHINCS+ few-time 128s). Rotates every ~1M signatures. **Per-chain and per-epoch.**

### 2. Per-chain key derivation

Each chain gets its own independent sequence of main signers, derived via BIP-85 from the seed:

```
bootstrap            = BIP85(seed, m/83696968'/PQ_BOOTSTRAP'/0')
<chain>-main-key_i   = BIP85(seed, m/83696968'/PQ_MAIN'/<chainId>'/<i>')
```

For example:
- `base-main-key_0`     = `m/83696968'/PQ_MAIN'/8453'/0'`
- `base-main-key_1`     = `m/83696968'/PQ_MAIN'/8453'/1'`
- `mainnet-main-key_0`  = `m/83696968'/PQ_MAIN'/1'/0'`
- `arbitrum-main-key_0` = `m/83696968'/PQ_MAIN'/42161'/0'`

Keys on different chains are cryptographically independent. OTS indices on Base can never collide with OTS indices on mainnet because the underlying keypairs are different.

### 3. CREATE2 salt is bootstrap-only

The factory computes the CREATE2 address using **only** the bootstrap public key:

```
salt = keccak256(bootstrapPubKey)
address = keccak256(0xff ‖ factory ‖ salt ‖ keccak256(proxyInitCode))
```

The `proxyInitCode` is a constant ERC-1967 proxy pointing at a fixed implementation slot. **Nothing chain-specific or main-signer-specific goes into the initCode or salt**, so the address is identical on every chain.

### 4. On-chain state per chain

Each chain's deployed wallet stores its own state independently:

```solidity
struct PQSignerStorage {
    bytes32 bootstrapPubKeyHash;   // set at init, immutable
    uint32  currentKeyIndex;       // epoch index: 0, 1, 2, ...
    bytes32 currentMainPubKeyHash; // keccak256(current main signer pubkey)
    uint32  currentOTSIndex;       // next unused OTS leaf for current main key
    uint32  maxOTSIndex;           // 2^20 - 1 = 1,048,575
}
```

The blockchain is the **authoritative state**. The hardware wallet's local OTS counter is a convenience optimization; on any ambiguity, the on-chain value wins.

---

## Factory contract

```solidity
contract PQWalletFactory {
    address public immutable implementation;
    bytes32 public immutable proxyInitCodeHash;

    event WalletDeployed(address indexed wallet, bytes32 indexed bootstrapPubKeyHash);

    constructor(address _implementation) {
        implementation = _implementation;
        // proxy bytecode is a constant ERC-1967 minimal proxy
        proxyInitCodeHash = keccak256(_proxyInitCode());
    }

    /// @notice Deploys a wallet at a deterministic address derived from bootstrapPubKey.
    /// @dev The address is the same on every chain for the same bootstrapPubKey.
    function createAccount(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner,
        bytes calldata bootstrapSig
    ) external returns (address account) {
        // Verify the bootstrap signature authorizes this initial main signer.
        // Note: no chainId in the signed message — it's intentionally replayable
        // across chains, because the user wants the same initial signer everywhere.
        bytes32 authMsg = keccak256(abi.encodePacked("PQWALLET_INIT_V1", initialMainSigner));
        require(
            _verifyBootstrapSig(bootstrapPubKey, authMsg, bootstrapSig),
            "bad bootstrap sig"
        );

        bytes32 salt = keccak256(bootstrapPubKey);
        account = _deployProxy(salt);

        IPQWallet(account).initialize(bootstrapPubKey, initialMainSigner);

        emit WalletDeployed(account, keccak256(bootstrapPubKey));
    }

    /// @notice Computes the CREATE2 address for a given bootstrap key.
    /// @dev Same inputs → same address on every chain.
    function getAddress(bytes calldata bootstrapPubKey) external view returns (address) {
        bytes32 salt = keccak256(bootstrapPubKey);
        return address(uint160(uint256(keccak256(abi.encodePacked(
            bytes1(0xff), address(this), salt, proxyInitCodeHash
        )))));
    }

    function _deployProxy(bytes32 salt) internal returns (address) {
        bytes memory initCode = _proxyInitCode();
        address addr;
        assembly {
            addr := create2(0, add(initCode, 0x20), mload(initCode), salt)
        }
        require(addr != address(0), "create2 failed");
        return addr;
    }

    function _proxyInitCode() internal view returns (bytes memory) {
        // Constant ERC-1967 proxy with `implementation` baked in via immutable
        // (not storage), so the initCode depends only on `implementation`.
        // Returned bytes are identical on every chain where this factory is
        // deployed at the same address with the same implementation.
        // ... standard ERC-1967 proxy bytecode ...
    }

    function _verifyBootstrapSig(
        bytes calldata pubKey,
        bytes32 message,
        bytes calldata sig
    ) internal view returns (bool) {
        // Verify ML-DSA-44 signature (or whatever bootstrap scheme is chosen).
        // Likely a call to a verifier library or precompile (EIP-8051 when available).
    }
}
```

### Why the bootstrap signature is required and chain-agnostic

- **Required**: without it, a front-runner who sees your `bootstrapPubKey` (public, in the salt) could deploy your wallet on a chain you haven't touched yet, initialized with *their* chosen main signer. You'd recover via bootstrap-authorized rotation, but it wastes gas and creates an ugly race.
- **Chain-agnostic**: the signed message deliberately omits `chainId`. This lets the user produce *one* bootstrap signature over `initialMainSigner` and use it on every chain they ever deploy to. A replayed signature on a new chain is not a threat — it can only deploy the wallet with the *exact* main signer the user chose, which is what they wanted anyway.

---

## Wallet contract

```solidity
contract PQWallet is IPQWallet, BaseAccount {
    // ERC-7201 namespaced storage
    bytes32 private constant STORAGE_SLOT =
        keccak256(abi.encode(uint256(keccak256("pqwallet.storage.v1")) - 1))
        & ~bytes32(uint256(0xff));

    struct Storage {
        bytes32 bootstrapPubKeyHash;
        uint32  currentKeyIndex;
        bytes32 currentMainPubKeyHash;
        uint32  currentOTSIndex;
        bool    initialized;
    }

    uint32 constant MAX_OTS = (1 << 20) - 1;

    event MainSignerRotated(uint32 indexed newKeyIndex, bytes32 indexed newPubKeyHash);
    event OTSConsumed(uint32 indexed keyIndex, uint32 indexed otsIndex);

    modifier onlySelf() {
        require(msg.sender == address(this), "only self");
        _;
    }

    function initialize(
        bytes calldata bootstrapPubKey,
        bytes calldata initialMainSigner
    ) external {
        Storage storage s = _s();
        require(!s.initialized, "already init");
        s.initialized = true;
        s.bootstrapPubKeyHash = keccak256(bootstrapPubKey);
        s.currentKeyIndex = 0;
        s.currentMainPubKeyHash = keccak256(initialMainSigner);
        s.currentOTSIndex = 0;
    }

    /// @notice Rotate the main signer. Authorized by EITHER the current main
    /// signer (normal rotation) OR the bootstrap signer (recovery rotation).
    function rotateMainSigner(
        uint32 newKeyIndex,
        bytes calldata newMainPubKey
    ) external onlySelf {
        Storage storage s = _s();
        require(newKeyIndex == s.currentKeyIndex + 1, "sequential only");

        s.currentKeyIndex = newKeyIndex;
        s.currentMainPubKeyHash = keccak256(newMainPubKey);
        s.currentOTSIndex = 0;

        emit MainSignerRotated(newKeyIndex, s.currentMainPubKeyHash);
    }

    /// @notice ERC-4337 validation. Accepts signatures from either the current
    /// main signer or the bootstrap signer.
    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        Storage storage s = _s();
        PQSignatureWrapper memory wrapper = abi.decode(userOp.signature, (PQSignatureWrapper));

        if (wrapper.signerType == SignerType.MAIN) {
            // Normal path: stateful PQ signature from current main signer
            require(wrapper.keyIndex == s.currentKeyIndex, "wrong key epoch");
            require(wrapper.otsIndex == s.currentOTSIndex, "wrong ots index");
            require(wrapper.otsIndex <= MAX_OTS, "key exhausted");
            require(
                keccak256(wrapper.pubKey) == s.currentMainPubKeyHash,
                "pubkey mismatch"
            );

            bool ok = _verifyStatefulPQ(
                wrapper.pubKey,
                userOpHash,
                wrapper.otsIndex,
                wrapper.signature
            );
            if (!ok) return SIG_VALIDATION_FAILED;

            // Consume the OTS index atomically with validation success
            s.currentOTSIndex = wrapper.otsIndex + 1;
            emit OTSConsumed(s.currentKeyIndex, wrapper.otsIndex);

            return 0;
        } else if (wrapper.signerType == SignerType.BOOTSTRAP) {
            // Admin path: stateless PQ signature from bootstrap signer
            require(
                keccak256(wrapper.pubKey) == s.bootstrapPubKeyHash,
                "bootstrap mismatch"
            );
            bool ok = _verifyStatelessPQ(wrapper.pubKey, userOpHash, wrapper.signature);
            return ok ? 0 : SIG_VALIDATION_FAILED;
        }

        return SIG_VALIDATION_FAILED;
    }

    /// @notice EIP-1271 for Safe and CowSwap compatibility (when deployed).
    function isValidSignature(bytes32 hash, bytes calldata signature)
        external view returns (bytes4)
    {
        // Verify against current main signer OR bootstrap.
        // For large PQ signatures, prefer ZK-wrapped proofs here to keep size
        // compatible with Safe/CowSwap calldata limits.
        // ...
        return 0x1626ba7e;
    }

    function _s() private pure returns (Storage storage s) {
        bytes32 slot = STORAGE_SLOT;
        assembly { s.slot := slot }
    }

    function _verifyStatefulPQ(
        bytes memory pubKey,
        bytes32 message,
        uint32 otsIndex,
        bytes memory sig
    ) internal view returns (bool) {
        // XMSS or SPHINCS+ few-time verification.
        // Likely wrapped as a ZK proof of validity to fit in validateUserOp's
        // gas budget — raw verification is 4.4M gas (XMSS) or 11.6M gas (SPHINCS+),
        // both over the practical bundler limit.
    }

    function _verifyStatelessPQ(
        bytes memory pubKey,
        bytes32 message,
        bytes memory sig
    ) internal view returns (bool) {
        // ML-DSA-44 verification. Cheap enough to do inline once EIP-8051
        // precompile lands; until then, use a verifier library or ZK wrapper.
    }
}
```

---

## Key derivation spec

All keys derive from a single BIP-39 seed phrase (24 words recommended for post-quantum security margin) via BIP-85.

```
Application ID: 83696968' (standard BIP-85 prefix)

Bootstrap signer (global, never rotates):
    m/83696968'/PQ_BOOTSTRAP'/0'
    → ML-DSA-44 keygen seed → (bootstrap_sk, bootstrap_pk)

Main signers (per-chain, per-epoch):
    m/83696968'/PQ_MAIN'/<chainId>'/<keyIndex>'
    → XMSS or SPHINCS+ few-time keygen seed → (main_sk_i, main_pk_i)
```

Recommended constants (pick final values before deployment; they become permanent):
- `PQ_BOOTSTRAP` = `0x50510001'` (or similar, any unused BIP-85 app code)
- `PQ_MAIN`      = `0x50510002'`

BIP-85 derivation produces 64 bytes of entropy per path; use as the seed input to the PQ scheme's deterministic KeyGen.

---

## Operational flows

### Flow A: first-time deployment on a new chain

```
User action: "Use my wallet on chain X for the first time"

1. Companion app derives:
     - bootstrap_pk (from seed)
     - chainX-main-key_0 (from seed, using chainId X)
2. Companion app computes wallet address via factory.getAddress(bootstrap_pk)
3. User confirms bootstrap-authorized deployment on hardware wallet
4. Hardware wallet produces bootstrap signature over:
     keccak256("PQWALLET_INIT_V1" ‖ chainX-main-key_0)
   (Same signature is valid on every chain, can be cached.)
5. Companion app submits UserOp on chain X:
     initCode = factory.createAccount(
         bootstrap_pk,
         chainX-main-key_0,
         bootstrapSig
     )
     callData = <optional first action, e.g. setPreSignature for CowSwap>
6. Bundler deploys + optionally executes the first action atomically
7. Wallet state on chain X:
     bootstrapPubKeyHash  = keccak256(bootstrap_pk)
     currentKeyIndex      = 0
     currentMainPubKeyHash = keccak256(chainX-main-key_0)
     currentOTSIndex      = 0
```

### Flow B: normal rotation (main signer exhausted on chain X)

```
Trigger: currentOTSIndex approaches MAX_OTS (e.g., 1,048,000 of 1,048,575)

1. Companion app reads state from chain X
2. Hardware wallet derives chainX-main-key_<i+1> from seed
3. Construct rotation UserOp signed by current main signer at the next OTS index:
     callData = rotateMainSigner(i+1, chainX-main-key_<i+1>)
     signature = stateful PQ sig from chainX-main-key_i at OTS index currentOTSIndex
4. Submit to bundler; wallet state updates to:
     currentKeyIndex      = i+1
     currentMainPubKeyHash = keccak256(chainX-main-key_<i+1>)
     currentOTSIndex      = 0
5. Old chainX-main-key_i is now permanently retired for this chain
```

### Flow C: hardware wallet lost, recover on new device, continue on same chain

```
Scenario: user was at currentKeyIndex=1, currentOTSIndex=432117 on Base

1. User enters seed phrase on new hardware wallet
2. Companion app reads Base state via eth_getStorageAt:
     currentKeyIndex=1, currentOTSIndex=432117, currentMainPubKeyHash=H
3. New device derives base-main-key_1 from seed (deterministic, same as old)
4. Sanity check: keccak256(base-main-key_1) must equal H ✓
5. Set local OTS counter to 432117
6. Resume signing; next signature uses OTS index 432118
7. (Optional paranoia rotation: if old device may be stolen, immediately
    submit a rotation UserOp to base-main-key_2 to invalidate the old device)
```

### Flow D: hardware wallet lost, recover on new device, use on a DIFFERENT chain for the first time

```
Scenario: user had Base wallet (already rotated to key_1), loses device,
           recovers, wants to transact on mainnet (never deployed there)

1. User enters seed phrase on new hardware wallet
2. Companion app checks mainnet: eth_getCode(walletAddress) = 0x → not deployed
3. Derive from seed:
     - bootstrap_pk
     - mainnet-main-key_0  (NEVER been used anywhere — fresh key)
4. Hardware wallet produces bootstrap signature over mainnet-main-key_0
5. Deploy on mainnet via factory.createAccount(
       bootstrap_pk, mainnet-main-key_0, bootstrapSig)
6. Wallet address on mainnet = wallet address on Base ✓
     (both derived from keccak256(bootstrap_pk))
7. Mainnet state initializes to:
     currentKeyIndex=0, currentMainPubKeyHash=keccak256(mainnet-main-key_0),
     currentOTSIndex=0
8. Base remains completely independent: still at key_1, still ticking along
9. Zero cross-contamination: mainnet's key_0 has never signed anything on Base,
    so there's no OTS reuse risk even in principle
```

### Flow E: emergency state recovery (on-chain state suspected corrupt)

```
Scenario: unclear what currentOTSIndex is, or suspect a race condition

1. Companion app reads on-chain state; if state looks suspicious:
2. User authorizes bootstrap-level rotation
3. Hardware wallet derives chainX-main-key_<current+1> from seed
4. Bootstrap-signed UserOp calling rotateMainSigner(current+1, new_pk)
5. Wallet advances to next key epoch, resetting currentOTSIndex to 0
6. Any ambiguity about old state is now moot — old key is retired
```

---

## Bootstrap key security properties

The bootstrap key is powerful: it can rotate the main signer on any chain without the current main signer's cooperation. Treat it accordingly:

- **Never leaves the hardware wallet**. Derived fresh from seed each use.
- **Explicit UX on every use**: "You are authorizing an administrative operation that can move your wallet to a new signer. This should only happen during first deployment on a chain or emergency recovery."
- **Stateless**, so state loss is never a bootstrap security issue — no OTS counter to corrupt.
- **Optional timelock** (recommended for high-value wallets): bootstrap-authorized rotations take effect after N hours, with a cancel-by-main-signer escape hatch. Gives you a window to notice and cancel if the seed is compromised.
- **Different crypto family from main signer** (ML-DSA vs. hash-based): a cryptanalytic break in one family doesn't compromise the other. This is a valuable hedge given the relative youth of PQ schemes.

---

## EIP-1271 / Safe / CowSwap integration

### Deployment detection

```typescript
async function isDeployed(provider: Provider, walletAddress: string): Promise<boolean> {
    const code = await provider.getCode(walletAddress);
    return code !== '0x' && code.length > 2;
}
```

Check per chain. Never rely on EntryPoint queries (deposits can exist without deployment).

### CowSwap: setPreSignature pattern (recommended)

Avoid passing PQ signatures through CowSwap entirely. When the user places a CowSwap order:

1. Ensure wallet is deployed on the chain (deploy via Flow A if not)
2. Submit a UserOp: `wallet.execute(GPv2Settlement, 0, abi.encodeCall(setPreSignature, (orderUid, true)))`
3. The UserOp's signature is a normal PQ signature (main signer), verified inside `validateUserOp` only
4. CowSwap's settlement sees a PreSign flag, not a signature — it checks `preSignature[orderUid] == PRE_SIGNED`
5. CowSwap API receives just the 20-byte wallet address as "signature"

This completely sidesteps large PQ signature compatibility issues with CowSwap.

### Gnosis Safe: signMessage pattern (recommended)

For Safe transactions where the PQ wallet is a signer on a Safe:

1. Ensure PQ wallet is deployed on the chain
2. Submit a UserOp: `wallet.execute(safeAddress, 0, abi.encodeCall(Safe.signMessage, (msgHash)))`
3. Safe marks the hash as signed in its own storage
4. When the Safe transaction executes, Safe's `checkSignatures` sees the pre-approved hash and accepts it
5. The PQ signature is verified only once, inside the PQ wallet's `validateUserOp` — never passed to the Safe

### Direct EIP-1271 (fallback, for off-chain gasless flows)

When a protocol absolutely requires `isValidSignature` to be called and there's no on-chain pre-approval path:

1. The PQ wallet must be deployed on the target chain
2. `isValidSignature` verifies a **ZK proof** of PQ signature validity, not the raw PQ signature
    - Groth16 proof: ~128–200 bytes, cheap verification
    - STARK proof: larger but post-quantum secure
3. The ZK proof fits comfortably in Safe's ~64 KB practical signature limit
4. Raw PQ signatures (7.8–50 KB) would exceed practical Safe/CowSwap signature size limits and should never be passed directly

---

## Cross-chain deployment cost summary

| Chain    | Deployment gas | Cost at typical gas price |
|----------|---------------|---------------------------|
| Mainnet  | ~200,000      | ~$1–3 at 30 gwei          |
| Base     | ~200,000      | <$0.01                    |
| Arbitrum | ~200,000      | <$0.01                    |
| Optimism | ~200,000      | <$0.01                    |

Can be bundled with the first real action (e.g., a CowSwap setPreSignature) to save a transaction.

---

## Signature scheme selection

### Main signer (stateful, rotates)

**Recommended: SPHINCS+ few-time 128s** with parameters (n=16, h=17, d=1, log(t)=20, k=8, w=16)
- Signature size: ~3.4 KB
- Public key: 32 bytes
- Signature budget: ~2^20 per keypair
- Graceful degradation on OTS overuse (safer than XMSS if state is lost)

**Alternative: XMSS with h=20**
- Signature size: ~2.75 KB
- Public key: 68 bytes
- Signature budget: exactly 2^20 per keypair
- Catastrophic failure on OTS reuse — only choose if you have high confidence in state management

On-chain verification cost is prohibitive for both (4.4M/11.6M gas). Wrap verification in a ZK-STARK proof (~200–500K gas) for `validateUserOp` compatibility.

### Bootstrap signer (stateless, global)

**Recommended: ML-DSA-44 (Dilithium2)**
- Signature size: ~2.4 KB
- Public key: ~1.3 KB
- NIST standardized (FIPS 204)
- Lattice-based (different family from main signer — hedge against hash-based breaks)
- Verification fast enough for direct on-chain use when EIP-8051 precompile lands

**Alternative: SPHINCS+-128s (standard, not few-time)**
- Signature size: ~7.8 KB
- Same hash-based family as main signer (less hedging value)
- Larger signatures but simpler crypto review

---

## Implementation checklist

- [ ] Fork Coinbase Smart Wallet (`coinbase/smart-wallet`)
- [ ] Replace `MultiOwnable` with `PQSignerStorage` layout
- [ ] Implement `_validateSignature` with dual-path (main/bootstrap) logic
- [ ] Implement `rotateMainSigner` with `onlySelf` modifier
- [ ] Implement `isValidSignature` for EIP-1271 (ZK-wrapped verification)
- [ ] Write `PQWalletFactory` with bootstrap-signature-gated `createAccount`
- [ ] Use ERC-1967 proxy with immutable implementation to keep initCode constant
- [ ] Verify CREATE2 addresses match across chains in testing (deploy to at least 3 testnets, confirm identical addresses)
- [ ] Build the PQ verifier library (or ZK circuit) for the chosen main signer scheme
- [ ] Build the ML-DSA verifier library (or wait for EIP-8051)
- [ ] Define BIP-85 app codes for `PQ_BOOTSTRAP` and `PQ_MAIN`; document them permanently
- [ ] Hardware wallet firmware: implement BIP-85 derivation, XMSS/SPHINCS+ signing, ML-DSA signing, OTS counter sync from chain
- [ ] Companion app: deployment detection per chain, factory deployment flow, rotation flow, recovery flow
- [ ] Companion app: CowSwap setPreSignature integration
- [ ] Companion app: Safe signMessage integration
- [ ] Test Flow D extensively — cross-chain first-deployment after rotation on another chain is the most subtle path
- [ ] Security audit focused on: OTS reuse scenarios, front-running on new chains, bootstrap key exposure, ZK circuit soundness
- [ ] Consider timelock on bootstrap-authorized rotations for high-value deployments

---

## Open questions to resolve before mainnet

1. **Exact main signer scheme**: final parameter selection for SPHINCS+ few-time vs. XMSS. Pending completion of the C reference implementation.
2. **ZK wrapping strategy**: Groth16 (smaller proofs, trusted setup) vs. STARK (no trusted setup, post-quantum secure, larger proofs). STARK is philosophically better aligned with a PQ wallet.
3. **EIP-8051 timing**: if ML-DSA precompile lands before mainnet, bootstrap verification becomes nearly free and the design simplifies.
4. **Timelock default**: should bootstrap-authorized rotations have a default timelock? What's the right duration? (Suggestion: 24h default, user-configurable, 0h for low-value wallets.)
5. **Chain ID collisions**: the per-chain derivation path uses `chainId` — what happens if a chain forks and creates a duplicate? (Unlikely but worth specifying: the wallet commits to a specific chainId at deploy time via its state, so a fork creates two independent states naturally.)
