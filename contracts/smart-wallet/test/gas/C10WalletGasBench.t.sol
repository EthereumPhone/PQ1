// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test, Vm, console2} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../../src/PQSmartWalletFactory.sol";
import {ISPHINCSVerifier} from "../../src/verifiers/ISPHINCSVerifier.sol";
import {SPHINCsC10Asm} from "../../src/verifiers/SPHINCsC10Asm.sol";
import {SPHINCsC10v2Asm} from "../../src/verifiers/SPHINCsC10v2Asm.sol";
import {RefSPHINCsC10Asm} from "../ref/RefSPHINCsC10Asm.sol";
import {RefSPHINCsC10v2Asm} from "../ref/RefSPHINCsC10v2Asm.sol";
import {MockSPHINCSVerifier} from "../mocks/MockSPHINCSVerifier.sol";

/// RESEARCH (#1155 gas track): what a user pays. MEASUREMENT ONLY, no production wiring.
///
/// The wallet implementation is bound (immutable) to one verifier address; each test contract
/// puts the runtime code of one verifier there with `vm.etch` in setUp (all four verifiers are
/// stateless, no immutables), so the reference and the candidate run behind the identical
/// wallet, calldata and storage, and the difference is the verifier alone.
///
///   * Type-2 `validateUserOp` (slot key, ownerIndex 1): v1 with the Rust-generated userOp vector
///     of test/c10_test_vectors.json (as PQSmartWalletRealSig.t.sol); v2 with the same userOp and
///     a v2 signature over the same `sphincsDigest`.
///   * EIP-1271 `isValidSignature(bytes32, bytes)` (Solady nested EIP-712, PersonalSign
///     workflow) on a fixed hash H, with signatures over the wallet's nested hash.
/// The v2 key and all three extra signatures are in test/gas/c10_wallet_bench_vectors.json,
/// produced by research/c10-gas/wallet_bench_sign.py from the Python references after
/// `test_print_signing_inputs` printed the inputs. Every measured call must accept.
///
/// Gas = `gasleft()` around the external call from this test (includes the call's own overhead
/// and ABI encoding of the 4 KB argument in the test, identical for ref and cand). The verifier
/// account is cold in the measured test, as in a real transaction (checked by the no-etch
/// control contract). Not measured: EntryPoint overhead, calldata (unchanged: same signature bytes). Each figure is ONE
/// signature: since the straight-line chain blocks, verifier gas varies slightly with the digit
/// pattern (tens of gas over the KATs).
abstract contract C10WalletGasBenchBase is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);
    bytes32 constant H = keccak256("PQ1 #1155 gas bench: EIP-1271 message");

    SPHINCsC10Asm internal verifierSlot; // the address the wallet impl is bound to
    MockSPHINCSVerifier internal mockC10;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;
    PQSmartWallet internal walletV1;
    PQSmartWallet internal walletV2;

    bytes internal userOpSigV1;
    bytes internal callDataFromVec;
    address internal senderFromVec;
    string internal fx;
    bool internal haveFixture;

    function setUp() public {
        verifierSlot = new SPHINCsC10Asm();
        mockC10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), ISPHINCSVerifier(address(verifierSlot)));
        factory = new PQSmartWalletFactory(address(impl), mockC10);
        mockC10.setValid(true);

        string memory json = vm.readFile("test/c10_test_vectors.json");
        userOpSigV1 = vm.parseJsonBytes(json, ".userOpBench.signature");
        callDataFromVec = vm.parseJsonBytes(json, ".userOpBench.callData");
        senderFromVec = vm.parseJsonAddress(json, ".userOpBench.sender");
        walletV1 = factory.createAccount(
            bytes32(uint256(0xdead) << 240), bytes32(uint256(0xbeef) << 240),
            vm.parseJsonBytes32(json, ".pkSeed"), vm.parseJsonBytes32(json, ".pkRoot"),
            uint64(block.chainid), hex"00"
        );

        string memory k2 = vm.readFile("test/c10v2_kat_vectors.json");
        walletV2 = factory.createAccount(
            bytes32(uint256(0xdeae) << 240), bytes32(uint256(0xbeef) << 240),
            vm.parseJsonBytes32(k2, ".v0.pkSeed"), vm.parseJsonBytes32(k2, ".v0.pkRoot"),
            uint64(block.chainid), hex"00"
        );
        if (vm.exists("test/gas/c10_wallet_bench_vectors.json")) {
            fx = vm.readFile("test/gas/c10_wallet_bench_vectors.json");
            haveFixture = true;
        }
        _install();
    }

    /// Which verifier code sits at the verifier address for this contract's tests. Done in setUp,
    /// a separate call, so the verifier account is cold again in the measured test (an etch in
    /// the test itself leaves it warm: about -2.8k, measured).
    function _install() internal virtual;

    function _op(bytes memory c10Sig) internal view returns (UserOperation06 memory op) {
        op.sender = senderFromVec;
        op.callData = callDataFromVec;
        op.signature = abi.encode(uint256(1), c10Sig);
    }

    function _wrap(bytes memory c10Sig) internal pure returns (bytes memory) {
        return abi.encode(uint256(1), c10Sig);
    }

    function _etch(bool v2, bool cand) internal {
        bytes memory code = v2
            ? (cand ? address(new SPHINCsC10v2Asm()).code : address(new RefSPHINCsC10v2Asm()).code)
            : (cand ? address(new SPHINCsC10Asm()).code : address(new RefSPHINCsC10Asm()).code);
        vm.etch(address(verifierSlot), code);
    }

    /// The nested hash the wallet hands the verifier for isValidSignature(H, ·), read from the
    /// recorded verifier call (so this test does not re-derive Solady's EIP-712 nesting).
    function _nestedHash(PQSmartWallet w) internal returns (bytes32 nested) {
        vm.startStateDiffRecording();
        w.isValidSignature(H, _wrap(new bytes(4008)));
        Vm.AccountAccess[] memory a = vm.stopAndReturnStateDiff();
        for (uint256 i = 0; i < a.length; i++) {
            if (a[i].account == address(verifierSlot) && a[i].data.length > 100) {
                bytes memory d = a[i].data;
                assembly {
                    nested := mload(add(d, 100)) // selector, pkSeed, pkRoot, then the message
                }
                return nested;
            }
        }
        revert("verifier not called");
    }

    function _validate(PQSmartWallet w, bytes memory c10Sig, string memory label) internal returns (uint256 used) {
        UserOperation06 memory op = _op(c10Sig);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 g0 = gasleft();
        uint256 vd = w.validateUserOp(op, bytes32(0), 0);
        used = g0 - gasleft();
        assertEq(vd, 0, string.concat(label, ": signature must validate"));
        console2.log(string.concat("WALLETGAS validateUserOp ", label), used);
    }

    function _1271(PQSmartWallet w, bytes memory c10Sig, string memory label) internal returns (uint256 used) {
        bytes memory sig = _wrap(c10Sig);
        uint256 g0 = gasleft();
        bytes4 r = w.isValidSignature(H, sig);
        used = g0 - gasleft();
        assertEq(r, bytes4(0x1626ba7e), string.concat(label, ": signature must validate"));
        console2.log(string.concat("WALLETGAS isValidSignature ", label), used);
    }

    /// The fixture's v2 signatures were made for these exact inputs.
    function _checkFixture() internal {
        vm.skip(!haveFixture);
        assertEq(vm.parseJsonBytes32(fx, ".v1_1271_nested"), _nestedHash(walletV1));
        assertEq(vm.parseJsonBytes32(fx, ".v2_1271_nested"), _nestedHash(walletV2));
        assertEq(vm.parseJsonBytes32(fx, ".userop_digest"), walletV1.sphincsDigest(_op(userOpSigV1)));
    }
}

/// v1 (deployed format) verifier at the wallet's verifier address.
abstract contract C10WalletGasBenchV1 is C10WalletGasBenchBase {
    function _label() internal pure virtual returns (string memory);

    function test_validateUserOp() public {
        _validate(walletV1, userOpSigV1, _label());
    }

    function test_isValidSignature() public {
        vm.skip(!haveFixture);
        _1271(walletV1, vm.parseJsonBytes(fx, ".v1_1271_sig"), _label());
    }
}

/// v2 DRAFT 0.3 verifier at the wallet's verifier address.
abstract contract C10WalletGasBenchV2 is C10WalletGasBenchBase {
    function _label() internal pure virtual returns (string memory);

    function test_validateUserOp() public {
        vm.skip(!haveFixture);
        _validate(walletV2, vm.parseJsonBytes(fx, ".v2_userop_sig"), _label());
    }

    function test_isValidSignature() public {
        vm.skip(!haveFixture);
        _1271(walletV2, vm.parseJsonBytes(fx, ".v2_1271_sig"), _label());
    }
}

contract C10WalletGasBenchV1RefTest is C10WalletGasBenchV1 {
    function _install() internal override {
        _etch(false, false);
    }

    function _label() internal pure override returns (string memory) {
        return "v1 ref";
    }
}

contract C10WalletGasBenchV1CandTest is C10WalletGasBenchV1 {
    function _install() internal override {
        _etch(false, true);
    }

    function _label() internal pure override returns (string memory) {
        return "v1 cand";
    }
}

/// Control: no etch at all (the candidate deployed in setUp, as in PQSmartWalletRealSig.t.sol);
/// must equal C10WalletGasBenchV1CandTest. Also prints the signing inputs for the fixture and
/// checks the fixture against them.
contract C10WalletGasBenchV1CandNoEtchTest is C10WalletGasBenchV1 {
    function _install() internal override {}

    function _label() internal pure override returns (string memory) {
        return "v1 cand (no etch)";
    }

    function test_print_signing_inputs() public {
        console2.log("SIGNING-INPUT v1-1271-nested");
        console2.logBytes32(_nestedHash(walletV1));
        console2.log("SIGNING-INPUT v2-1271-nested");
        console2.logBytes32(_nestedHash(walletV2));
        console2.log("SIGNING-INPUT userop-digest");
        console2.logBytes32(walletV1.sphincsDigest(_op(userOpSigV1)));
    }

    function test_fixture_matches_inputs() public {
        _checkFixture();
    }
}

contract C10WalletGasBenchV2RefTest is C10WalletGasBenchV2 {
    function _install() internal override {
        _etch(true, false);
    }

    function _label() internal pure override returns (string memory) {
        return "v2 ref";
    }
}

contract C10WalletGasBenchV2CandTest is C10WalletGasBenchV2 {
    function _install() internal override {
        _etch(true, true);
    }

    function _label() internal pure override returns (string memory) {
        return "v2 cand";
    }
}
