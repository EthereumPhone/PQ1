# Phase 5 — Solidity contract gut + C11 verifier port

**Status:** not started.
**Depends on:** none (Solidity side is independent of firmware phases; can
run in parallel with phases 1–4).
**Blocks:** on-chain validation of what the firmware produces. Without this,
Type 1 / Type 2 signatures produced by the firmware will be rejected by
the existing `PQCoinbaseSmartWallet.validateUserOp`.

## Why this phase exists

The current `contracts/smart-wallet/` is a fork of Coinbase Smart Wallet with
three signer types (MAIN SLH-DSA, BOOTSTRAP ML-DSA, JARDÍN). After the
cutover, only JARDÍN exists. We gut the wallet in place (preserves factory
+ CREATE2 address scheme per the approved plan) and port the SPHINCs-C11 Yul
verifier from `/home/markus/Documents/SPHINCs-/src/SPHINCs-C11Asm.sol` so
Type 1 registration signatures validate.

## Source files (reference)

From `/home/markus/Documents/SPHINCs-/src/`:
- `JardinAccount.sol` — the shape we're porting. **Skip the ECDSA half.**
- `JardinAccountFactory.sol` — factory pattern.
- `SPHINCs-C11Asm.sol` — **port this verbatim** (Yul-optimized verifier).
- `JardinForsCVerifier.sol` — same logic as ours, but cross-check for drift.

## Files in this repo

| File | Action |
|---|---|
| `contracts/smart-wallet/src/PQCoinbaseSmartWallet.sol` | **Gut + rename** → `PQJardinWallet.sol`. Pure-PQ Type 1 / Type 2 dispatch, masterPkSeed + masterPkRoot immutables, slots mapping. Delete MAIN/BOOTSTRAP branches. |
| `contracts/smart-wallet/src/PQCoinbaseSmartWalletFactory.sol` | **Rename** → `PQJardinWalletFactory.sol`. Strip bootstrap-sig gate (first Type 1 UserOp authenticates itself). |
| `contracts/smart-wallet/src/PQOwnable.sol` | **Shrink**. Drop `currentKeyIndex`, `currentOTSIndex`, `bootstrapOTSIndex`, `currentMainPubKeyHash`, `bootstrapPubKeyHash`. Keep `slots` mapping + new `masterPkSeed` / `masterPkRoot` immutables. |
| `contracts/smart-wallet/src/verifiers/JardinForsCVerifier.sol` | **Keep unchanged** (already there, already tested). |
| `contracts/smart-wallet/src/verifiers/IJardinVerifier.sol` | **Keep.** |
| `contracts/smart-wallet/src/verifiers/SPHINCsC11Asm.sol` | **Create** — port from SPHINCs-/src/SPHINCs-C11Asm.sol. (Solidity identifiers can't contain hyphens; use `SPHINCsC11Asm` without the dash.) |
| `contracts/smart-wallet/src/verifiers/ISPHINCSVerifier.sol` | **Keep** if it matches the new C11 interface, else rewrite. |
| `contracts/smart-wallet/src/verifiers/SLHDSAVerifier.sol` | **Delete.** |
| `contracts/smart-wallet/src/verifiers/ISLHDSAVerifier.sol` | **Delete.** |
| `contracts/smart-wallet/src/verifiers/SphincsC7Asm.sol` | **Delete** (if present; the Rust `sphincs-c7` crate is actually C11 but the Solidity side may have a C7 artifact). |
| `contracts/smart-wallet/test/SLHDSAVerifier.t.sol` | **Delete.** |
| `contracts/smart-wallet/test/GasComparison.t.sol` | **Delete.** |
| `contracts/smart-wallet/test/PQCoinbaseSmartWallet.t.sol` | **Rewrite** → `PQJardinWallet.t.sol`. |
| `contracts/smart-wallet/test/JardinWalletE2E.t.sol` | **Create.** End-to-end: deploy factory, predict address, sign Type 1, sign Type 2, assert. |

## Target `PQJardinWallet.sol` (sketch)

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {BaseAccount} from "account-abstraction/core/BaseAccount.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/core/UserOperationLib.sol";

import {PQOwnable} from "./PQOwnable.sol";
import {IJardinVerifier} from "./verifiers/IJardinVerifier.sol";
import {ISPHINCSVerifier} from "./verifiers/ISPHINCSVerifier.sol";

contract PQJardinWallet is BaseAccount, PQOwnable {
    IEntryPoint private immutable _entryPoint;
    ISPHINCSVerifier public immutable c11Verifier;
    IJardinVerifier public immutable forscVerifier;

    // Master C11 keypair — derived from BIP-39 seed at provisioning, set
    // once by the factory at construction.
    bytes32 public immutable masterPkSeed;
    bytes32 public immutable masterPkRoot;

    // Signature-type markers
    uint8 constant TYPE_1_REGISTER = 0x01;
    uint8 constant TYPE_2_COMPACT  = 0x02;

    constructor(
        IEntryPoint ep_,
        ISPHINCSVerifier c11_,
        IJardinVerifier forsc_,
        bytes32 masterPkSeed_,
        bytes32 masterPkRoot_
    ) {
        _entryPoint = ep_;
        c11Verifier = c11_;
        forscVerifier = forsc_;
        masterPkSeed = masterPkSeed_;
        masterPkRoot = masterPkRoot_;
    }

    function entryPoint() public view override returns (IEntryPoint) {
        return _entryPoint;
    }

    function _validateSignature(
        PackedUserOperation calldata userOp,
        bytes32 userOpHash
    ) internal override returns (uint256) {
        bytes calldata sig = userOp.signature;
        if (sig.length < 65) return SIG_VALIDATION_FAILED;  // min is Type 1 marker + fields
        uint8 sigType = uint8(sig[0]);

        if (sigType == TYPE_1_REGISTER) {
            // Type 1: 1 + 32 + 16 + 16 + 3976 = 4041 bytes
            if (sig.length != 4041) return SIG_VALIDATION_FAILED;
            bytes32 r = bytes32(sig[1:33]);
            bytes16 subPkSeed = bytes16(sig[33:49]);
            bytes16 subPkRoot = bytes16(sig[49:65]);
            // C11 verify over userOpHash with master pk.
            if (!c11Verifier.verify(masterPkSeed, masterPkRoot, userOpHash, sig[65:4041])) {
                return SIG_VALIDATION_FAILED;
            }
            // Register slot. H(r) → H(subPkSeed || subPkRoot).
            // (Only if r is non-zero — zero means "no-op registration".)
            if (r != bytes32(0)) {
                bytes32 slotKey = keccak256(abi.encodePacked(r));
                bytes32 subVkHash = keccak256(abi.encodePacked(subPkSeed, subPkRoot));
                // Allow idempotent re-registration only if identical.
                bytes32 prev = _getStorage().jardinSlots[slotKey];
                if (prev != bytes32(0) && prev != subVkHash) {
                    return SIG_VALIDATION_FAILED;
                }
                _getStorage().jardinSlots[slotKey] = subVkHash;
            }
            return 0;  // SIG_VALIDATION_SUCCESS
        } else if (sigType == TYPE_2_COMPACT) {
            // Type 2: 1 + 32 + 16 + 16 + (2452 + q*16) = variable
            if (sig.length < 65 + 2468) return SIG_VALIDATION_FAILED;
            bytes32 slotKey = bytes32(sig[1:33]);
            bytes16 subPkSeed = bytes16(sig[33:49]);
            bytes16 subPkRoot = bytes16(sig[49:65]);
            bytes calldata forscSig = sig[65:];
            // Verify slot is registered.
            bytes32 subVkHash = keccak256(abi.encodePacked(subPkSeed, subPkRoot));
            if (_getStorage().jardinSlots[slotKey] != subVkHash) {
                return SIG_VALIDATION_FAILED;
            }
            // FORS+C verify.
            // Pad bytes16 → bytes32 (left-aligned, top 128 bits).
            bytes32 subPkSeed32 = bytes32(subPkSeed);
            bytes32 subPkRoot32 = bytes32(subPkRoot);
            if (!forscVerifier.verifyForsCUnbalanced(subPkSeed32, subPkRoot32, userOpHash, forscSig)) {
                return SIG_VALIDATION_FAILED;
            }
            return 0;
        }
        return SIG_VALIDATION_FAILED;
    }

    // execute() inherited from BaseAccount
}
```

## Target `PQJardinWalletFactory.sol`

```solidity
contract PQJardinWalletFactory {
    IEntryPoint public immutable entryPoint;
    ISPHINCSVerifier public immutable c11Verifier;
    IJardinVerifier public immutable forscVerifier;

    constructor(
        IEntryPoint ep,
        ISPHINCSVerifier c11,
        IJardinVerifier forsc
    ) {
        entryPoint = ep;
        c11Verifier = c11;
        forscVerifier = forsc;
    }

    /// CREATE2 address is a function of (masterPkSeed, masterPkRoot) only.
    /// Same 24 words → same wallet address on every chain.
    function createAccount(
        bytes32 masterPkSeed,
        bytes32 masterPkRoot
    ) external returns (PQJardinWallet) {
        bytes32 salt = keccak256(abi.encodePacked(masterPkSeed, masterPkRoot));
        address predicted = getAddress(masterPkSeed, masterPkRoot);
        if (predicted.code.length > 0) {
            return PQJardinWallet(payable(predicted));
        }
        return new PQJardinWallet{salt: salt}(
            entryPoint, c11Verifier, forscVerifier,
            masterPkSeed, masterPkRoot
        );
    }

    function getAddress(bytes32 masterPkSeed, bytes32 masterPkRoot) public view returns (address) {
        bytes32 salt = keccak256(abi.encodePacked(masterPkSeed, masterPkRoot));
        return Create2.computeAddress(salt, keccak256(_getCreationCode(masterPkSeed, masterPkRoot)));
    }

    function _getCreationCode(bytes32 masterPkSeed, bytes32 masterPkRoot) internal view returns (bytes memory) {
        return abi.encodePacked(
            type(PQJardinWallet).creationCode,
            abi.encode(entryPoint, c11Verifier, forscVerifier, masterPkSeed, masterPkRoot)
        );
    }
}
```

## Target `PQOwnable.sol` shrink

Keep only:
- The ERC-7201 storage struct with `mapping(bytes32 => bytes32) jardinSlots`
- The storage slot constant + `_getStorage()` helper

Delete:
- `currentKeyIndex`, `currentOTSIndex`, `bootstrapOTSIndex`, `currentMainPubKeyHash`, `bootstrapPubKeyHash`
- `rotateMainSigner`, `_consumeOTS`, `_consumeBootstrapOTS`
- All MAIN/BOOTSTRAP-related events and errors

## Porting `SPHINCs-C11Asm.sol`

Steps:

1. Read `/home/markus/Documents/SPHINCs-/src/SPHINCs-C11Asm.sol` in full.
2. Copy to `contracts/smart-wallet/src/verifiers/SPHINCsC11Asm.sol` (drop
   the hyphen in the filename — Solidity identifiers don't allow it, and
   Foundry gets confused by filenames with hyphens when contract and file
   names must match).
3. Rename the contract from `SPHINCs-C11Asm` (if that's the name) to
   `SPHINCsC11Asm`.
4. Update the import path in `PQJardinWallet.sol` → `ISPHINCSVerifier.sol`
   references (if the interface name changes).
5. Verify gas costs match SPHINCs- advertised values (~116K per Type 1
   verify).
6. Pin the exact EntryPoint address the port expects (v0.9 per SPHINCs-).

## Target `JardinWalletE2E.t.sol`

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.23;

import {Test} from "forge-std/Test.sol";
import {PQJardinWallet} from "../src/PQJardinWallet.sol";
import {PQJardinWalletFactory} from "../src/PQJardinWalletFactory.sol";
import {JardinForsCVerifier} from "../src/verifiers/JardinForsCVerifier.sol";
import {SPHINCsC11Asm} from "../src/verifiers/SPHINCsC11Asm.sol";

contract JardinWalletE2E is Test {
    PQJardinWalletFactory factory;
    JardinForsCVerifier forsc;
    SPHINCsC11Asm c11;

    function setUp() public {
        c11 = new SPHINCsC11Asm();
        forsc = new JardinForsCVerifier();
        // Deploy a mock EntryPoint or use the real one
        factory = new PQJardinWalletFactory(
            IEntryPoint(address(0x1)),
            c11,
            forsc
        );
    }

    function testFirstSignRegistersAndValidates() public {
        // 1. Use FFI to call SPHINCs-'s Python signer with a fixed mnemonic.
        //    It produces: masterPkSeed, masterPkRoot, a Type 1 sig for a
        //    chosen userOpHash, and the corresponding (r, subPkSeed, subPkRoot).
        // 2. Deploy wallet via factory.
        // 3. Build a UserOp with the Type 1 signature, call validateUserOp.
        // 4. Assert slot registered.
        // 5. Sign a second UserOp with Type 2 using the same slot.
        // 6. Call validateUserOp again, assert valid.
    }

    function testSecondSignSameSlotReusesType2() public {
        // Similar setup. Sign at q=1, q=2, q=3.
        // Assert verification passes for each with different signatures.
    }

    function testSlotExhaustionRotationTriggersNewType1() public {
        // Fast-forward q to 95, sign, then try to sign at q=96.
        // Firmware would rotate; simulate by passing a second slot's
        // Type 1 + Type 2 and asserting both validate.
    }
}
```

## EntryPoint version

Verify which EntryPoint address / version SPHINCs- uses:
```bash
grep -n "ENTRYPOINT\|0x4337\|BaseAccount" /home/markus/Documents/SPHINCs-/src/JardinAccount.sol /home/markus/Documents/SPHINCs-/script/DeployJardinSepolia.s.sol
```

SPHINCs- uses v0.9 (`0x4337...D009`). This repo's current contract uses v0.6
(`0x5FF137D4b0FDCD49DCA30c7CF57E578a026d2789`). Decide:
- **Option A:** Align to v0.9 (changes userOpHash computation in firmware — see
  phase 3).
- **Option B:** Keep v0.6, update SPHINCs- port.

Recommended: Option A (matches SPHINCs- exactly, less porting work on Yul verifier which is hash-packing-sensitive).

## Frozen invariants

- CREATE2 salt = `keccak256(masterPkSeed || masterPkRoot)`. Same 24 words →
  same address on every chain. Don't mix in chainId, factory nonce, or
  creation code hash (changes every deployment).
- Type 1 / Type 2 byte layouts are consumed both by firmware (phase 3) and
  the on-chain verifier. Change one, change the other, in the same commit.
- `JardinForsCVerifier` is already battle-tested. Don't modify it; just
  wire it in.

## What NOT to do

- **Don't reintroduce ECDSA validation**, even as a fallback. User
  explicitly vetoed hybrid.
- **Don't hardcode a bootstrap sig gate in the factory.** The first Type 1
  UserOp that gets sent to this account is self-authenticating (it signs
  the UserOp with the master C11 key that also defines the CREATE2 salt).
- **Don't add a `rotateMasterKeys` function.** Master C11 keys are
  immutable; if the user loses their seed, they fail-over via BIP-39
  recovery on a new device and end up at the same CREATE2 address.
- **Don't change `JardinForsCVerifier`** — it passes cross-codebase test
  vectors today; leave it.
- **Don't ship with a mock EntryPoint.** Point at the real canonical
  address in production deploy scripts.

## Verification

1. `cd contracts/smart-wallet && forge build` — clean compile.
2. `forge test -vv` — all existing JardinForsCVerifier tests still pass,
   new JardinWalletE2E tests pass.
3. Gas snapshot: Type 1 verify ~116K gas, Type 2 verify ~49K gas, wallet
   dispatch overhead ~10K gas.
4. Deploy to Sepolia via a ported `script/DeployJardinSepolia.s.sol`.
5. Cross-check: a fixed-mnemonic signer produces bytes that this contract
   accepts. Best test is actually running the webhid tool (phase 4)
   against the deployed contract.
