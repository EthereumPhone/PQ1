// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {DigestBoundVerifier} from "./mocks/DigestBoundVerifier.sol";

/// @dev The legacy EIP-1271 form that Safe v1.3.0 and v1.4.1 call on a
///      contract owner. Reached through an interface because
///      `PQSmartWallet.isValidSignature` is overloaded, which makes
///      `.selector` on the wallet type ambiguous.
interface ILegacyERC1271 {
    function isValidSignature(bytes calldata data, bytes calldata signature) external view returns (bytes4);
}

interface IERC1271 {
    function isValidSignature(bytes32 hash, bytes calldata signature) external view returns (bytes4);
}

/// @dev The contract-signature branch (`v == 0`) of Safe v1.3.0 / v1.4.1
///      `checkNSignatures`, copied from Safe's source with only the
///      surrounding loop removed: the owner address sits in `r`, `s` points
///      at a length-prefixed signature in the dynamic part, and the owner
///      must answer `isValidSignature(data, contractSignature)` with the
///      legacy magic `0x20c13b0b`. `data` is what Safe passes: the EIP-712
///      encoding whose keccak256 is the SafeTx (or SafeMessage) hash.
contract SafeV141ContractSignatureCheck {
    bytes4 internal constant EIP1271_MAGIC_VALUE = 0x20c13b0b;

    function signatureSplit(bytes memory signatures, uint256 pos)
        internal
        pure
        returns (uint8 v, bytes32 r, bytes32 s)
    {
        assembly ("memory-safe") {
            let signaturePos := mul(0x41, pos)
            r := mload(add(signatures, add(signaturePos, 0x20)))
            s := mload(add(signatures, add(signaturePos, 0x40)))
            v := and(mload(add(signatures, add(signaturePos, 0x41))), 0xff)
        }
    }

    function checkOneContractSignature(bytes memory data, bytes memory signatures) external view {
        uint256 requiredSignatures = 1;
        (uint8 v, bytes32 r, bytes32 s) = signatureSplit(signatures, 0);
        require(v == 0, "not a contract signature");
        address currentOwner = address(uint160(uint256(r)));
        require(uint256(s) >= requiredSignatures * 65, "GS021");
        require(uint256(s) + 32 <= signatures.length, "GS022");
        uint256 contractSignatureLen;
        assembly ("memory-safe") {
            contractSignatureLen := mload(add(add(signatures, s), 0x20))
        }
        require(uint256(s) + 32 + contractSignatureLen <= signatures.length, "GS023");
        bytes memory contractSignature;
        assembly ("memory-safe") {
            contractSignature := add(add(signatures, s), 0x20)
        }
        require(
            ILegacyERC1271(currentOwner).isValidSignature(data, contractSignature) == EIP1271_MAGIC_VALUE,
            "GS024"
        );
    }
}

/// @notice The legacy `isValidSignature(bytes,bytes)` entry point (GitHub
///         #995) and the closure of Solady's two raw-hash 1271 workflows
///         (GitHub #691).
///
///         Every positive assertion uses `DigestBoundVerifier`, armed with
///         the single digest the test expects the wallet to ask about. A
///         pass is therefore also a proof that the test's digest formula
///         equals the wallet's; an accept-everything mock could not tell
///         the nested hash from the bare one, which is exactly the property
///         under test here.
contract LegacyERC1271Test is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    bytes32 constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    bytes4 constant MAGIC_BYTES32 = 0x1626ba7e; // isValidSignature(bytes32,bytes)
    bytes4 constant MAGIC_LEGACY = 0x20c13b0b; // isValidSignature(bytes,bytes)
    bytes4 constant FAIL_VALUE = 0xffffffff;

    /// Solady's MulticallerWithSigner, the one caller Solady's
    /// `_erc1271CallerIsSafe` trusts with a raw hash.
    address constant SOLADY_SAFE_CALLER = 0x000000000000D9ECebf3C23529de49815Dac1c4c;
    /// Solady's Basefee helper. Where it is deployed (Ethereum mainnet,
    /// Base Sepolia), Solady's RPC branch skipped its gas burn and checked
    /// the raw hash at any gas.
    address constant SOLADY_BASEFEE_CONTRACT = 0x000000000000378eDCD5B5B0A24f5342d8C10485;

    bytes32 constant DOMAIN_TYPEHASH =
        keccak256("EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)");
    bytes32 constant PERSONAL_SIGN_TYPEHASH = keccak256("PersonalSign(bytes prefixed)");

    DigestBoundVerifier internal dbv;
    PQSmartWallet internal wallet;
    SafeV141ContractSignatureCheck internal safe;

    function setUp() public {
        dbv = new DigestBoundVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), dbv);
        PQSmartWalletFactory factory = new PQSmartWalletFactory(address(impl), dbv);
        bytes memory factorySig = hex"aaaa";
        dbv.arm(
            MASTER_PK_SEED,
            MASTER_PK_ROOT,
            factory.addSlot0Digest(uint64(block.chainid), SLOT0_PK_SEED, SLOT0_PK_ROOT)
        );
        wallet = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), factorySig
        );
        safe = new SafeV141ContractSignatureCheck();
    }

    // ── helpers ──────────────────────────────────────────────────────

    /// @dev The value the firmware signs for an off-chain hash `h`
    ///      (`aa::eip1271::replay_safe_hash`): Solady's PersonalSign nesting
    ///      under this wallet's EIP-712 domain.
    function _replaySafeHash(bytes32 h) internal view returns (bytes32) {
        bytes32 domainSep = keccak256(
            abi.encode(
                DOMAIN_TYPEHASH,
                keccak256(bytes("PQSmartWallet")),
                keccak256(bytes("1")),
                block.chainid,
                address(wallet)
            )
        );
        bytes32 structHash = keccak256(abi.encode(PERSONAL_SIGN_TYPEHASH, h));
        return keccak256(abi.encodePacked(hex"1901", domainSep, structHash));
    }

    function _wrapper(uint256 ownerIndex) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, new bytes(4008));
    }

    /// @dev A stand-in for Safe's `encodeTransactionData` output:
    ///      `0x19 || 0x01 || domainSeparator || safeTxStructHash`.
    function _safeTxData(bytes32 salt) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes1(0x19), bytes1(0x01), keccak256(abi.encode("safe-domain", salt)), keccak256(abi.encode("safe-tx", salt))
        );
    }

    /// @dev Safe's packed signature bytes for one contract owner: the
    ///      65-byte static part `{r = owner}{s = 65}{v = 0}` followed by the
    ///      length-prefixed contract signature.
    function _safeSignatures(address owner, bytes memory contractSignature) internal pure returns (bytes memory) {
        return abi.encodePacked(
            bytes32(uint256(uint160(owner))),
            bytes32(uint256(65)),
            uint8(0),
            uint256(contractSignature.length),
            contractSignature
        );
    }

    function _legacy(bytes memory data, bytes memory sig) internal view returns (bytes4) {
        return ILegacyERC1271(address(wallet)).isValidSignature(data, sig);
    }

    function _modern(bytes32 hash, bytes memory sig) internal view returns (bytes4) {
        return IERC1271(address(wallet)).isValidSignature(hash, sig);
    }

    // ── legacy entry (#995) ──────────────────────────────────────────

    function test_legacySelectorIsTheSafeV141One() external pure {
        assertEq(ILegacyERC1271.isValidSignature.selector, MAGIC_LEGACY, "legacy selector");
        assertEq(IERC1271.isValidSignature.selector, MAGIC_BYTES32, "modern selector");
    }

    /// Accepts exactly what the bytes32 entry accepts for keccak256(data).
    function test_legacyAcceptsSameSignatureAsModernEntry() external {
        bytes memory data = _safeTxData("ok");
        bytes32 h = keccak256(data);
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(h));

        assertEq(_legacy(data, _wrapper(1)), MAGIC_LEGACY, "legacy entry");
        assertEq(_modern(h, _wrapper(1)), MAGIC_BYTES32, "bytes32 entry, same signature");
    }

    function test_legacyRejectsOtherData() external {
        bytes memory data = _safeTxData("ok");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(keccak256(data)));

        bytes memory other = _safeTxData("other");
        assertEq(_legacy(other, _wrapper(1)), FAIL_VALUE, "different data must not verify");
    }

    /// The bootstrap key stays forbidden off-chain on the legacy entry too.
    function test_legacyRejectsBootstrapKey() external {
        bytes memory data = _safeTxData("boot");
        dbv.arm(MASTER_PK_SEED, MASTER_PK_ROOT, _replaySafeHash(keccak256(data)));
        assertEq(_legacy(data, _wrapper(0)), FAIL_VALUE, "bootstrap key accepted off-chain");
    }

    function test_legacyRejectsMalformedWrapper() external {
        bytes memory data = _safeTxData("pad");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(keccak256(data)));

        bytes memory sig = _wrapper(1);
        sig[sig.length - 1] = 0x01; // non-zero ABI tail pad (audit L-1)
        assertEq(_legacy(data, sig), FAIL_VALUE, "non-zero tail pad accepted");

        bytes memory short = new bytes(4127);
        assertEq(_legacy(data, short), FAIL_VALUE, "short wrapper accepted");
    }

    /// The gas price no longer changes anything: no raw-hash RPC branch,
    /// and a failed check returns 0xffffffff instead of reverting.
    function test_legacyIndependentOfGasPrice() external {
        bytes memory data = _safeTxData("gas");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(keccak256(data)));
        bytes memory bad = _safeTxData("gas-bad");

        vm.txGasPrice(0);
        assertEq(_legacy(data, _wrapper(1)), MAGIC_LEGACY, "gasprice 0 valid");
        assertEq(_legacy(bad, _wrapper(1)), FAIL_VALUE, "gasprice 0 invalid");
        vm.txGasPrice(1);
        assertEq(_legacy(data, _wrapper(1)), MAGIC_LEGACY, "gasprice 1 valid");
        assertEq(_legacy(bad, _wrapper(1)), FAIL_VALUE, "gasprice 1 invalid");
    }

    /// End to end through Safe v1.3.0 / v1.4.1's own contract-signature
    /// branch: PQ1 as a Safe owner.
    function test_safeV141ContractOwnerPathAccepts() external {
        bytes memory data = _safeTxData("safe");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(keccak256(data)));
        safe.checkOneContractSignature(data, _safeSignatures(address(wallet), _wrapper(1)));
    }

    function test_safeV141ContractOwnerPathRejectsWrongTx() external {
        bytes memory data = _safeTxData("safe");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(keccak256(data)));
        vm.expectRevert(bytes("GS024"));
        safe.checkOneContractSignature(_safeTxData("safe-other"), _safeSignatures(address(wallet), _wrapper(1)));
    }

    // ── raw-hash workflows closed (#691) ─────────────────────────────

    /// A signature over the BARE hash, the shape of every public UserOp
    /// signature (`c10Verifier.verify(pk, sphincsDigest(op), sig)`), is not
    /// an EIP-1271 signature for that hash, on any path.
    function test_bareHashSignatureRejectedInEthCallContext() external {
        bytes32 d = keccak256("a public UserOp digest");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, d);

        // eth_call context: gasprice 0, no Basefee contract (Base mainnet).
        vm.txGasPrice(0);
        assertEq(_modern(d, _wrapper(1)), FAIL_VALUE, "raw hash accepted at gasprice 0");

        // eth_call context with Solady's Basefee contract present (Ethereum
        // mainnet, Base Sepolia): the old RPC branch checked the raw hash
        // at any gas here. It must not now.
        vm.etch(SOLADY_BASEFEE_CONTRACT, hex"600160005260206000f3"); // returns 1
        assertEq(_modern(d, _wrapper(1)), FAIL_VALUE, "raw hash accepted with Basefee contract");

        // Control: the nested hash of the same value does verify, so the
        // rejections above are about the hash shape, not a broken setup.
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, _replaySafeHash(d));
        assertEq(_modern(d, _wrapper(1)), MAGIC_BYTES32, "nested control");
    }

    function test_bareHashSignatureRejectedFromSoladySafeCaller() external {
        bytes32 d = keccak256("raw hash via MulticallerWithSigner");
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, d);

        vm.prank(SOLADY_SAFE_CALLER);
        assertEq(_modern(d, _wrapper(1)), FAIL_VALUE, "raw hash accepted from the Solady safe caller");
    }

    /// The concrete #691 scenario: a real UserOp digest, signed bare as the
    /// device signs UserOps, presented back as an EIP-1271 signature.
    function test_publicUserOpSignatureIsNotAnOffchainSignature() external {
        UserOperation06 memory op;
        op.sender = address(wallet);
        op.callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (uint256(1), uint256(0), address(0xbeef), uint256(0), bytes(""))
        );
        op.signature = _wrapper(1);
        bytes32 d = wallet.sphincsDigest(op);
        dbv.arm(SLOT0_PK_SEED, SLOT0_PK_ROOT, d);

        vm.txGasPrice(0);
        assertEq(_modern(d, op.signature), FAIL_VALUE, "UserOp signature replayed as EIP-1271");
        vm.txGasPrice(1);
        assertEq(_modern(d, op.signature), FAIL_VALUE, "UserOp signature replayed as EIP-1271 (gasprice 1)");
    }
}
