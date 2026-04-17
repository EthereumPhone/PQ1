// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {PQJardinWallet} from "../src/PQJardinWallet.sol";
import {PQJardinWalletFactory} from "../src/PQJardinWalletFactory.sol";
import {MockJardinVerifier} from "./mocks/MockJardinVerifier.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice End-to-end test for the JARDÍN-only wallet using mock verifiers.
///         Validates the Type 1 / Type 2 dispatch state machine, CREATE2
///         determinism, and the on-chain slot registry.
contract PQJardinWalletTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    MockJardinVerifier internal forsc;
    PQJardinWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED =
        bytes32(uint256(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) << 128);
    bytes32 internal constant MASTER_PK_ROOT =
        bytes32(uint256(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) << 128);

    bytes32 internal constant R = bytes32(uint256(0xc0ffee));
    bytes16 internal constant SUB_PK_SEED_16 = bytes16(uint128(0xdeadbeefdeadbeefdeadbeefdeadbeef));
    bytes16 internal constant SUB_PK_ROOT_16 = bytes16(uint128(0xcafebabecafebabecafebabecafebabe));

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        forsc = new MockJardinVerifier();
        factory = new PQJardinWalletFactory(IEntryPoint(ENTRY_POINT_ADDR), c10, forsc);
    }

    // ── CREATE2 determinism ─────────────────────────────────────────

    function test_create2Deterministic() public {
        address predicted = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        assertEq(address(w), predicted, "predicted must match deployed");
    }

    function test_create2IdempotentOnSecondCall() public {
        PQJardinWallet a = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        PQJardinWallet b = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        assertEq(address(a), address(b), "second createAccount returns same address");
    }

    function test_create2DifferentMasterKeysDifferentAddresses() public {
        address a = factory.getAddress(MASTER_PK_SEED, MASTER_PK_ROOT);
        address b = factory.getAddress(bytes32(uint256(1)), MASTER_PK_ROOT);
        address c = factory.getAddress(MASTER_PK_SEED, bytes32(uint256(1)));
        assertTrue(a != b);
        assertTrue(a != c);
        assertTrue(b != c);
    }

    // ── Type 1: slot registration ───────────────────────────────────

    function test_type1RegistersSlot() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        bytes32 userOpHash = keccak256("hash-type-1");

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), userOpHash, 0);
        assertEq(vd, 0, "Type 1 must validate");

        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes32 subVkHash = sha256(abi.encodePacked(SUB_PK_SEED_16, SUB_PK_ROOT_16));
        assertEq(w.jardinSlot(slotKey), subVkHash, "slot must be registered");
    }

    function test_type1C10FailRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(false);
        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "Type 1 with failing C10 must fail validation");
    }

    function test_type1IdempotentReRegistration() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);

        vm.startPrank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("a"), 0), 0);
        // Same (r, subKey) re-registration is a no-op, not a revert.
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("b"), 0), 0);
        vm.stopPrank();
    }

    function test_type1ConflictingReRegistrationReverts() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        bytes memory first = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), first), keccak256("a"), 0), 0);

        // Same r, different sub-key → must revert.
        bytes16 otherSeed = bytes16(uint128(0x1111));
        bytes memory second = _buildType1Sig(R, otherSeed, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        vm.expectRevert(bytes("slot conflict"));
        w.validateUserOp(_packedOp(address(w), second), keccak256("b"), 0);
    }

    function test_type1BadLengthRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        // Chop off the last byte.
        bytes memory short = new bytes(sig.length - 1);
        for (uint i = 0; i < short.length; i++) short[i] = sig[i];

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), short), keccak256("x"), 0);
        assertEq(vd, 1, "bad length must fail validation");
    }

    // ── Type 2: registered-slot sign ────────────────────────────────

    function test_type2WithRegisteredSlotValidates() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        // Step 1: register the slot via a Type 1.
        c10.setValid(true);
        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);

        // Step 2: Type 2 against the now-registered slot.
        forsc.setValid(true);
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory forscSig = new bytes(2468); // q=1 length
        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16, forscSig);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), t2), keccak256("user-tx"), 0);
        assertEq(vd, 0, "Type 2 against registered slot must validate");
    }

    function test_type2UnregisteredSlotRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        forsc.setValid(true);

        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory forscSig = new bytes(2468);
        bytes memory sig = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16, forscSig);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "unregistered slot must fail validation");
    }

    function test_type2WrongSubKeyRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(
            _packedOp(address(w), _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16)),
            keccak256("reg"),
            0
        );

        forsc.setValid(true);
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes16 wrongSeed = bytes16(uint128(0x1234));
        bytes memory forscSig = new bytes(2468);
        bytes memory sig = _buildType2Sig(slotKey, wrongSeed, SUB_PK_ROOT_16, forscSig);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "wrong sub-key must fail validation");
    }

    function test_type2FORSCFailRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(
            _packedOp(address(w), _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16)),
            keccak256("reg"),
            0
        );

        forsc.setValid(false);
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory forscSig = new bytes(2468);
        bytes memory sig = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16, forscSig);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "FORS+C fail must fail validation");
    }

    // ── Bootstrap counter ──────────────────────────────────────────

    /// @notice Every accepted Type 1 must bump `bootstrapUses` by exactly 1
    ///         and emit `BootstrapKeyUsed(newCount)`. Rejected Type 1s (bad
    ///         length, bad C10 sig, zero r) must NOT bump the counter.
    function test_bootstrapCounterIncrementsOnSuccess() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);
        assertEq(w.bootstrapUses(), 0, "counter starts at 0");

        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("a"), 0), 0);
        assertEq(w.bootstrapUses(), 1, "counter bumps on success");

        // Same (r, subKey) is idempotent for the slot registry, but it is
        // still a new Type 1 acceptance and must bump the counter.
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("b"), 0), 0);
        assertEq(w.bootstrapUses(), 2, "idempotent re-reg still bumps counter");
    }

    function test_bootstrapCounterDoesNotIncrementOnFailure() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        // Failing C10 sig.
        c10.setValid(false);
        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("a"), 0), 1);
        assertEq(w.bootstrapUses(), 0, "failed C10 must not bump counter");

        // Bad length.
        c10.setValid(true);
        bytes memory short = new bytes(sig.length - 1);
        for (uint i = 0; i < short.length; i++) short[i] = sig[i];
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), short), keccak256("b"), 0), 1);
        assertEq(w.bootstrapUses(), 0, "bad length must not bump counter");

        // r == 0.
        bytes memory zeroR = _buildType1Sig(bytes32(0), SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), zeroR), keccak256("c"), 0), 1);
        assertEq(w.bootstrapUses(), 0, "zero r must not bump counter");
    }

    /// @notice Push the counter to exactly `MAX_BOOTSTRAP_USES - 1` via a
    ///         storage write, confirm the next Type 1 is still accepted and
    ///         fills the cap, then confirm the following Type 1 is rejected
    ///         with SIG_VALIDATION_FAILED (not a revert).
    ///
    ///         Rather than running 65,536 full validations (would burn gas
    ///         and forge test time), we write the counter directly to the
    ///         canonical ERC-7201 slot + the `bootstrapUses` offset.
    function test_bootstrapCounterCapRejectsOverflow() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        uint256 cap = w.MAX_BOOTSTRAP_USES();
        assertEq(cap, 65_536, "cap must be 65536");

        // bootstrapUses lives at slot + 1 (mapping is slot + 0).
        bytes32 baseSlot =
            0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700;
        bytes32 counterSlot = bytes32(uint256(baseSlot) + 1);
        vm.store(address(w), counterSlot, bytes32(cap - 1));
        assertEq(w.bootstrapUses(), cap - 1, "counter primed to cap-1");

        // Last allowed Type 1 — accepted, counter fills the cap.
        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("last"), 0), 0);
        assertEq(w.bootstrapUses(), cap, "final Type 1 fills the cap");

        // Next Type 1 — rejected with SIG_VALIDATION_FAILED, no revert.
        bytes32 otherR = bytes32(uint256(0xd00d));
        bytes memory sig2 = _buildType1Sig(otherR, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig2), keccak256("over"), 0), 1);
        assertEq(w.bootstrapUses(), cap, "counter stays at cap after rejection");
    }

    /// @notice Once the cap is full, Type 2 against the already-registered
    ///         slot must still work (the current JARDÍN slot keeps signing
    ///         until its own q-exhaustion).
    function test_bootstrapExhaustedAllowsType2() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        // Register one slot (counter 1).
        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);
        assertEq(w.bootstrapUses(), 1);

        // Push counter to cap.
        bytes32 baseSlot =
            0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700;
        vm.store(address(w), bytes32(uint256(baseSlot) + 1), bytes32(w.MAX_BOOTSTRAP_USES()));

        // Type 2 against the already-registered slot should still work.
        forsc.setValid(true);
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory forscSig = new bytes(2468);
        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16, forscSig);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), t2), keccak256("tx"), 0),
            0,
            "Type 2 must still work when C10 bootstrap is exhausted"
        );
    }

    // ── Access control ─────────────────────────────────────────────

    function test_validateUserOpOnlyFromEntryPoint() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.expectRevert(PQJardinWallet.NotFromEntryPoint.selector);
        w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
    }

    function test_executeOnlyFromEntryPoint() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        vm.expectRevert(PQJardinWallet.NotFromEntryPoint.selector);
        w.execute(address(0xdead), 0, "");
    }

    // ── Helpers ──────────────────────────────────────────────────

    function _buildType1Sig(bytes32 r, bytes16 subSeed, bytes16 subRoot)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(1 + 32 + 16 + 16 + 4008);
        out[0] = 0x01;
        for (uint i = 0; i < 32; i++) out[1 + i] = r[i];
        for (uint i = 0; i < 16; i++) out[33 + i] = subSeed[i];
        for (uint i = 0; i < 16; i++) out[49 + i] = subRoot[i];
        // The remaining 4008 bytes of C10 sig are zero — the mock verifier
        // ignores them and returns its pre-set validity flag.
    }

    function _buildType2Sig(bytes32 slotKey, bytes16 subSeed, bytes16 subRoot, bytes memory forscSig)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(1 + 32 + 16 + 16 + forscSig.length);
        out[0] = 0x02;
        for (uint i = 0; i < 32; i++) out[1 + i] = slotKey[i];
        for (uint i = 0; i < 16; i++) out[33 + i] = subSeed[i];
        for (uint i = 0; i < 16; i++) out[49 + i] = subRoot[i];
        for (uint i = 0; i < forscSig.length; i++) out[65 + i] = forscSig[i];
    }

    function _packedOp(address sender, bytes memory signature)
        internal
        pure
        returns (PackedUserOperation memory)
    {
        return PackedUserOperation({
            sender: sender,
            nonce: 0,
            initCode: "",
            callData: "",
            accountGasLimits: bytes32(0),
            preVerificationGas: 0,
            gasFees: bytes32(0),
            paymasterAndData: "",
            signature: signature
        });
    }
}
