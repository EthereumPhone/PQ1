// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {SignatureCheckerLib} from "solady/utils/SignatureCheckerLib.sol";
import {ERC6492Verifier} from "./mocks/ERC6492Verifier.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {DigestBoundVerifier} from "./mocks/DigestBoundVerifier.sol";

/// @notice Negative tests for the ERC-6492 counterfactual signature path and
///         its cross-chain domain separation.
///
///         WHY THIS FILE EXISTS. The firmware ships a 6492 path in production:
///         when the companion's `eth_getCode` on the predicted CREATE2 address
///         comes back empty it clears `OFFCHAIN_FLAG_ACCOUNT_DEPLOYED`, and
///         `CMD_SIGN_OFFCHAIN` returns 8616 bytes whose tail is
///         `abi.encode(address factory, bytes factoryCalldata, bytes
///         signatureWrapper) || EIP6492_MAGIC` (proto/src/lib.rs:338-388).
///         A dapp routes that blob through an EIP-6492-aware verifier, which
///         deploys-then-verifies in one `eth_call`. Before this file,
///         `grep -n 6492 test/*.t.sol` returned nothing: the Solidity side of a
///         live product path had zero coverage. `aa/tests/negative_assumptions.rs`
///         covers the blob's WIRE SHAPE (length, magic suffix, wrapper layout);
///         what was untested is whether the thing actually verifies, and
///         whether it stops verifying where it must.
///
///         THE PROPERTY THAT MATTERS. A counterfactual signature carries its
///         own deploy instructions. Since the wallet address is chain-
///         independent by design (invariant #6: same 24 words -> same address
///         everywhere), the blob is byte-identical on every chain — so the ONLY
///         thing standing between "signature for chain A" and "authorises on
///         chain B" is the `chainId` field inside the Solady EIP-712 domain
///         that `replaySafeHash` mixes in. That is a single field in a hash
///         preimage. It deserves an executable test, not a comment.
///
///         HOW THE DIGEST IS PINNED WITHOUT DUPLICATING THE WALLET. Replicating
///         Solady's nesting in the test would prove only that the test agrees
///         with itself. Instead `_replaySafeHash` below recomputes the digest
///         from the SPEC (the same construction `aa/src/eip1271.rs` implements
///         for the firmware), and then `DigestBoundVerifier` is ARMED with that
///         value: the verifier accepts exactly one digest and nothing else. So
///         the positive assertion "isValidSignature returns the magic value"
///         is simultaneously proof that the test's digest equals the wallet's
///         digest. If the wallet's nesting ever changes, this file goes red on
///         the POSITIVE test — which is the failure mode you want, because the
///         firmware would have to change with it.
contract ERC6492ReplayTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    /// @dev The chain the signature is produced for. 31337 keeps the mock
    ///      verifiers' M14 local-chain guard happy.
    uint256 constant CHAIN_A = 31337;
    /// @dev A different chain that must NOT accept chain A's signature.
    uint256 constant CHAIN_B = 1337;

    bytes32 constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);
    bytes internal constant FACTORY_SIG = hex"aaaa";

    uint256 constant C10_SIG_LEN = 4008;
    bytes4 constant MAGIC_VALUE = 0x1626ba7e;
    bytes4 constant FAIL_VALUE = 0xffffffff;
    /// @dev proto::EIP6492_MAGIC — the 32-byte suffix that marks a wrapped sig.
    bytes32 constant EIP6492_MAGIC =
        0x6492649264926492649264926492649264926492649264926492649264926492;

    // Solady EIP-712 / PersonalSign constants, mirrored in aa/src/eip1271.rs.
    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;
    DigestBoundVerifier internal dbv;
    ERC6492Verifier internal v6492;

    function setUp() public {
        vm.chainId(CHAIN_A);
        // History: Solady's ERC1271 has a `_erc1271IsValidSignatureViaRPC`
        // branch for `eth_call` simulation, gated on `tx.gasprice == 0` —
        // Foundry's default. It checked the BARE hash (through the overridden
        // `_erc1271IsValidSignatureNowCalldata`, not `_erc1271Signer()`), and
        // without Solady's Basefee helper on chain its gas-burn guard hit
        // `invalid()`, so a failed check reverted instead of returning
        // 0xffffffff. That is why this line was mandatory. Since the 2026-10
        // freeze PQSmartWallet drops that branch (GitHub #691; the gas-price-0
        // cases are in LegacyERC1271.t.sol), so the gas price no longer
        // matters; it stays at 1 to read as the on-chain path.
        vm.txGasPrice(1);
        dbv = new DigestBoundVerifier();
        v6492 = new ERC6492Verifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), dbv);
        factory = new PQSmartWalletFactory(address(impl), dbv);
    }

    // ── helpers ──────────────────────────────────────────────────────

    /// @dev The digest the wallet verifies for `isValidSignature(rawHash, ...)`:
    ///      the Solady PersonalSign nesting, domain-separated by chainId AND by
    ///      the wallet address. Kept honest by the arming trick described in the
    ///      contract-level docs.
    function _replaySafeHash(address wallet, uint256 chainId, bytes32 rawHash)
        internal
        pure
        returns (bytes32)
    {
        bytes32 domainSep = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("PQSmartWallet")),
                keccak256(bytes("1")),
                chainId,
                wallet
            )
        );
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, rawHash));
        return keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
    }

    /// @dev The exact `factoryCalldata` the firmware puts in the blob:
    ///      `initCode[20..]`, i.e. the `createAccount` call whose hash is baked
    ///      into the CREATE2 address.
    function _factoryCalldata(uint64 chainId) internal pure returns (bytes memory) {
        return abi.encodeCall(
            PQSmartWalletFactory.createAccount,
            (MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, chainId, FACTORY_SIG)
        );
    }

    /// @dev `abi.encode(uint256 ownerIndex, bytes c10Sig)` — ownerIndex 1 is
    ///      slot 0, the only slot the factory seeds and therefore the only one
    ///      the 6492 path may carry (proto/src/lib.rs:351).
    function _wrapper() internal pure returns (bytes memory) {
        return abi.encode(uint256(1), new bytes(C10_SIG_LEN));
    }

    /// @dev Arm the BOOTSTRAP signature the factory checks inside
    ///      `createAccount`. The 6492 flow deploys before it verifies, so
    ///      without this the counterfactual check fails at the deploy step and
    ///      a test would "pass" its negative assertions for entirely the wrong
    ///      reason. `chainId` is the one baked into `factoryCalldata`, which is
    ///      what makes `_blob(CHAIN_B)` fail on chain A: `createAccount` itself
    ///      reverts with `WrongChainId` before any digest is ever checked.
    function _armDeploy(uint64 chainId) internal {
        dbv.arm(
            MASTER_PK_SEED,
            MASTER_PK_ROOT,
            factory.addSlot0Digest(chainId, SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
    }

    function _blob(uint64 deployChainId) internal view returns (bytes memory) {
        return abi.encodePacked(
            abi.encode(address(factory), _factoryCalldata(deployChainId), _wrapper()),
            EIP6492_MAGIC
        );
    }

    // ── tests ────────────────────────────────────────────────────────
    //
    // All counterfactual assertions go through `ERC6492Verifier`, a
    // spec-faithful deploy-then-verify helper in test/mocks/, and NOT through
    // `SignatureCheckerLib.isValidERC6492SignatureNow*`. Both Solady entry
    // points delegate to a canonical singleton (0x00007bd7…1626Ba7e /
    // 0x0000bc37…1626ba7E) that does not exist in a fresh Foundry EVM, and when
    // it is missing they return **false** unconditionally. Writing the negatives
    // against Solady therefore produces VACUOUS PASSES — observed, not assumed:
    // the first draft of this file had two of them, green for the wrong reason.
    //
    // Consequently every negative below is paired with a POSITIVE CONTROL in the
    // same test. A refusal is only evidence if the same machinery accepts the
    // honest input; otherwise it is indistinguishable from broken plumbing.

    /// The blob shape the firmware emits verifies against the counterfactual
    /// address on the chain it was produced for: deploy-then-verify in one
    /// call, with the wallet not yet on chain.
    function test_erc6492_blob_verifies_counterfactually_on_its_own_chain() public {
        vm.chainId(CHAIN_A);
        address predicted = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        assertEq(predicted.code.length, 0, "precondition: wallet must NOT be deployed");

        _armDeploy(uint64(CHAIN_A));
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(predicted, CHAIN_A, _raw()));

        assertTrue(
            v6492.isValidSig(
                predicted, _raw(), _blob(uint64(CHAIN_A))
            ),
            "6492 blob must verify against the undeployed CREATE2 address"
        );
        // Documents the side effect: this variant really did deploy the wallet,
        // at exactly the predicted address.
        assertTrue(predicted.code.length != 0, "the 6492 flow deploys at the predicted address");
    }

    /// The same bytes must NOT authorise on another chain. This is the whole
    /// point of the test file: the wallet address is chain-INDEPENDENT by
    /// design (invariant #6), so the blob is byte-identical everywhere and the
    /// `chainId` inside the EIP-712 domain is the only separator there is.
    ///
    /// The negative runs FIRST, while the wallet is genuinely undeployed, so it
    /// exercises the real counterfactual path rather than a post-deploy shortcut.
    ///
    /// HONEST SCOPE, established by mutation: pinning `chainId` to a constant
    /// inside `_replaySafeHash` does NOT turn this test red — only
    /// `test_replaySafeHash_is_chain_separated` catches that. The reason is
    /// that the counterfactual blob has TWO independent chain barriers, and
    /// this test only shows that at least one of them holds: the digest
    /// (checked directly by that other test) and the `chainId` argument bound
    /// into `factoryCalldata`, which makes `createAccount` revert with
    /// `WrongChainId` (checked directly by
    /// `test_erc6492_factoryCalldata_chainId_is_bound`). This test is the
    /// end-to-end statement; those two are the mechanism-specific ones. Do not
    /// delete either of them believing this one subsumes them.
    function test_erc6492_blob_does_not_replay_on_another_chain() public {
        address predicted = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        bytes memory blob = _blob(uint64(CHAIN_A));

        // Arm ONLY chain A's slot digest; arm the deploy digest for both chains
        // so a failure below can never be "the deploy step was not armed".
        _armDeploy(uint64(CHAIN_A));
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(predicted, CHAIN_A, _raw()));

        vm.chainId(CHAIN_B);
        assertEq(
            factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT),
            predicted,
            "invariant #6: the wallet address must be identical across chains"
        );
        assertFalse(
            v6492.isValidSig(predicted, _raw(), blob),
            "chain A's counterfactual signature must NOT authorise on chain B"
        );

        // POSITIVE CONTROL — without this the assertion above could be passing
        // because the blob is malformed, the factory reverted, or the mock was
        // never armed.
        vm.chainId(CHAIN_A);
        assertTrue(
            v6492.isValidSig(predicted, _raw(), blob),
            "the very same blob MUST verify on chain A"
        );
    }

    /// The separation above has to come from the DIGEST, not from something
    /// incidental. Pin that directly, on the deployed path so no 6492
    /// machinery is in the way: the wallet's own question to the verifier
    /// changes with chainId, and matches the spec formula this test computes.
    function test_replaySafeHash_is_chain_separated() public {
        vm.chainId(CHAIN_A);
        _armDeploy(uint64(CHAIN_A));
        PQSmartWallet w = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(CHAIN_A), FACTORY_SIG
        );

        bytes32 a = _replaySafeHash(address(w), CHAIN_A, _raw());
        bytes32 b = _replaySafeHash(address(w), CHAIN_B, _raw());
        assertTrue(a != b, "replaySafeHash must mix chainId");

        // Arming with `a` and getting the success magic proves the wallet's
        // digest EQUALS this test's formula — otherwise the line above is an
        // assertion about the test's own arithmetic and nothing else.
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, a);
        assertEq(
            w.isValidSignature(_raw(), _wrapper()),
            MAGIC_VALUE,
            "the wallet's digest must equal the spec digest this test computes"
        );

        // And arming with the OTHER chain's digest must not be accepted here.
        dbv.disarm(SLOT0_PK_SEED, SLOT0_PK_ROOT, a);
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, b);
        assertEq(
            w.isValidSignature(_raw(), _wrapper()),
            FAIL_VALUE,
            "chain B's digest must not satisfy a chain A verification"
        );
    }

    /// Also separated by wallet address: one seed makes up to 256 accounts, and
    /// a signature for account N must not verify for account M.
    function test_replaySafeHash_is_wallet_separated() public view {
        address w1 = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        address w2 = factory.getAddress(MASTER_PK_ROOT, MASTER_PK_SEED); // different salt
        assertTrue(w1 != w2, "precondition: distinct wallets");
        assertTrue(
            _replaySafeHash(w1, CHAIN_A, _raw()) != _replaySafeHash(w2, CHAIN_A, _raw()),
            "replaySafeHash must mix verifyingContract"
        );
    }

    /// The blob names its own factory. A blob naming a DIFFERENT factory must
    /// not verify against the honest predicted address: the address is a CREATE2
    /// function of (factory, salt, initCodeHash), so a substituted factory
    /// cannot land code there.
    function test_erc6492_rejects_a_substituted_factory() public {
        vm.chainId(CHAIN_A);
        address predicted = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        _armDeploy(uint64(CHAIN_A));
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(predicted, CHAIN_A, _raw()));

        PQSmartWalletFactory evil = new PQSmartWalletFactory(address(impl), dbv);
        // The evil factory's own deploy digest is armed too, so the refusal
        // below cannot be "the substituted factory reverted for lack of a sig".
        dbv.arm(
            MASTER_PK_SEED,
            MASTER_PK_ROOT,
            evil.addSlot0Digest(uint64(CHAIN_A), SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
        bytes memory tampered = abi.encodePacked(
            abi.encode(address(evil), _factoryCalldata(uint64(CHAIN_A)), _wrapper()),
            EIP6492_MAGIC
        );

        assertFalse(
            v6492.isValidSig(predicted, _raw(), tampered),
            "a blob naming a different factory must not verify at the honest address"
        );
        assertEq(predicted.code.length, 0, "and it must not have deployed anything there");

        // POSITIVE CONTROL: the honest blob still works.
        assertTrue(
            v6492.isValidSig(
                predicted, _raw(), _blob(uint64(CHAIN_A))
            ),
            "honest blob must verify"
        );
    }

    /// The chainId inside `factoryCalldata` is bound: `createAccount` reverts
    /// with `WrongChainId`, so a blob built for chain B cannot even complete the
    /// deploy half on chain A. This is a SECOND, independent barrier to the
    /// replay in `test_erc6492_blob_does_not_replay_on_another_chain` — the
    /// digest is the first.
    function test_erc6492_factoryCalldata_chainId_is_bound() public {
        vm.chainId(CHAIN_A);
        address predicted = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        // Arm everything either chain could possibly need, so the only
        // remaining explanation for a refusal is the chainId binding itself.
        _armDeploy(uint64(CHAIN_A));
        _armDeploy(uint64(CHAIN_B));
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(predicted, CHAIN_A, _raw()));

        assertFalse(
            v6492.isValidSig(
                predicted, _raw(), _blob(uint64(CHAIN_B))
            ),
            "factoryCalldata built for chain B must not deploy-and-verify on chain A"
        );
        assertEq(predicted.code.length, 0, "the wrong-chain deploy must not have landed");

        // POSITIVE CONTROL.
        assertTrue(
            v6492.isValidSig(
                predicted, _raw(), _blob(uint64(CHAIN_A))
            ),
            "the chain-A blob must verify"
        );
    }

    /// Once the wallet IS deployed the firmware sends the plain wrapper (the
    /// companion switches on `eth_getCode`), and that path must verify — and
    /// must be chain-separated too.
    function test_deployed_path_uses_plain_wrapper_and_still_verifies() public {
        vm.chainId(CHAIN_A);
        _armDeploy(uint64(CHAIN_A));

        PQSmartWallet w = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(CHAIN_A), FACTORY_SIG
        );
        assertTrue(address(w).code.length != 0, "wallet must be deployed");

        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(address(w), CHAIN_A, _raw()));
        assertEq(w.isValidSignature(_raw(), _wrapper()), MAGIC_VALUE, "deployed path must verify");

        vm.chainId(CHAIN_B);
        assertEq(
            w.isValidSignature(_raw(), _wrapper()),
            FAIL_VALUE,
            "the deployed path must be chain-separated too"
        );
    }

    function _raw() internal pure returns (bytes32) {
        return keccak256("a dapp-supplied hash the device nested before signing");
    }
}
