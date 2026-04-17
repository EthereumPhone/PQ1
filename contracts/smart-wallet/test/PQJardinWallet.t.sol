// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/interfaces/IEntryPoint.sol";
import {PackedUserOperation} from "account-abstraction/interfaces/PackedUserOperation.sol";

import {PQJardinWallet} from "../src/PQJardinWallet.sol";
import {PQJardinWalletFactory} from "../src/PQJardinWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice End-to-end test for the all-C10 wallet using a single mock
///         SPHINCS+C10 verifier for both the bootstrap path and per-slot
///         paths. Validates Type 1 / Type 2 dispatch, CREATE2 determinism,
///         the on-chain slot registry, and the two use-count caps.
contract PQJardinWalletTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    PQJardinWalletFactory internal factory;

    bytes32 internal constant MASTER_PK_SEED =
        bytes32(uint256(0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) << 128);
    bytes32 internal constant MASTER_PK_ROOT =
        bytes32(uint256(0xbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb) << 128);

    bytes32 internal constant R = bytes32(uint256(0xc0ffee));
    bytes16 internal constant SUB_PK_SEED_16 = bytes16(uint128(0xdeadbeefdeadbeefdeadbeefdeadbeef));
    bytes16 internal constant SUB_PK_ROOT_16 = bytes16(uint128(0xcafebabecafebabecafebabecafebabe));

    /// @dev ERC-7201 base slot for PQOwnable — must mirror the constant in
    ///      `PQOwnable._PQ_OWNABLE_STORAGE_LOCATION`.
    bytes32 internal constant BASE_SLOT =
        0xcb4cadeb7787e52e28ca307d180c484d592168b4843855f610dadfd7a22bd700;

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        factory = new PQJardinWalletFactory(IEntryPoint(ENTRY_POINT_ADDR), c10);
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
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), t2), keccak256("user-tx"), 0);
        assertEq(vd, 0, "Type 2 against registered slot must validate");
    }

    function test_type2UnregisteredSlotRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory sig = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);

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

        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes16 wrongSeed = bytes16(uint128(0x1234));
        bytes memory sig = _buildType2Sig(slotKey, wrongSeed, SUB_PK_ROOT_16);

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "wrong sub-key must fail validation");
    }

    function test_type2C10FailRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        // Register via a passing C10 verifier.
        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(
            _packedOp(address(w), _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16)),
            keccak256("reg"),
            0
        );

        // Then flip it: the SAME verifier now returns false → Type 2 fails.
        c10.setValid(false);
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory sig = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), sig), keccak256("x"), 0);
        assertEq(vd, 1, "C10 fail must fail validation");
    }

    function test_type2BadLengthRejects() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);

        c10.setValid(true);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(
            _packedOp(address(w), _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16)),
            keccak256("reg"),
            0
        );

        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory sig = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        bytes memory shortSig = new bytes(sig.length - 1);
        for (uint i = 0; i < shortSig.length; i++) shortSig[i] = sig[i];

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = w.validateUserOp(_packedOp(address(w), shortSig), keccak256("x"), 0);
        assertEq(vd, 1, "wrong-length Type 2 must fail validation");
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

        // Idempotent re-reg still bumps the counter (policy: we're accepting
        // a new signature even if the slot entry is unchanged).
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

    /// @notice Push the counter to `MAX_BOOTSTRAP_USES - 1` via a storage
    ///         write, confirm the final Type 1 is still accepted and fills
    ///         the cap, then confirm the next Type 1 is rejected cleanly.
    function test_bootstrapCounterCapRejectsOverflow() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        uint256 cap = w.MAX_BOOTSTRAP_USES();
        assertEq(cap, 65_536, "cap must be 65536");

        // bootstrapUses lives at BASE_SLOT + 1 (the `jardinSlots` mapping
        // is at offset 0; `slotUses` at offset 2 was added after it).
        bytes32 counterSlot = bytes32(uint256(BASE_SLOT) + 1);
        vm.store(address(w), counterSlot, bytes32(cap - 1));
        assertEq(w.bootstrapUses(), cap - 1, "counter primed to cap-1");

        bytes memory sig = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig), keccak256("last"), 0), 0);
        assertEq(w.bootstrapUses(), cap, "final Type 1 fills the cap");

        bytes32 otherR = bytes32(uint256(0xd00d));
        bytes memory sig2 = _buildType1Sig(otherR, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig2), keccak256("over"), 0), 1);
        assertEq(w.bootstrapUses(), cap, "counter stays at cap after rejection");
    }

    /// @notice Once the bootstrap cap is full, Type 2 against already-
    ///         registered slots must still work (up to each slot's own
    ///         `MAX_SLOT_USES`).
    function test_bootstrapExhaustedAllowsType2() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        // Register one slot (bootstrapUses = 1).
        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);
        assertEq(w.bootstrapUses(), 1);

        // Push counter to cap.
        vm.store(address(w), bytes32(uint256(BASE_SLOT) + 1), bytes32(w.MAX_BOOTSTRAP_USES()));

        // Type 2 against the already-registered slot must still work.
        bytes32 slotKey = sha256(abi.encodePacked(R));
        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(
            w.validateUserOp(_packedOp(address(w), t2), keccak256("tx"), 0),
            0,
            "Type 2 must still work when bootstrap cap is hit"
        );
    }

    // ── Slot counter ───────────────────────────────────────────────

    /// @notice Every accepted Type 2 bumps `slotUses[slotKey]` by exactly 1.
    function test_slotCounterIncrementsOnSuccess() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        // Register the slot.
        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);

        bytes32 slotKey = sha256(abi.encodePacked(R));
        assertEq(w.slotUses(slotKey), 0, "slot counter starts at 0");

        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.startPrank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), t2), keccak256("tx1"), 0), 0);
        assertEq(w.slotUses(slotKey), 1, "slot counter bumps on success");
        assertEq(w.validateUserOp(_packedOp(address(w), t2), keccak256("tx2"), 0), 0);
        assertEq(w.slotUses(slotKey), 2, "slot counter keeps bumping");
        vm.stopPrank();
    }

    /// @notice Rejected Type 2s (wrong sub-key, C10 fail, bad length)
    ///         must not bump the slot counter.
    function test_slotCounterDoesNotIncrementOnFailure() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);

        bytes32 slotKey = sha256(abi.encodePacked(R));
        assertEq(w.slotUses(slotKey), 0);

        // Wrong sub-key.
        bytes memory wrong = _buildType2Sig(slotKey, bytes16(uint128(0x1234)), SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), wrong), keccak256("a"), 0), 1);
        assertEq(w.slotUses(slotKey), 0, "wrong sub-key must not bump");

        // Failing C10 verifier.
        c10.setValid(false);
        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), t2), keccak256("b"), 0), 1);
        assertEq(w.slotUses(slotKey), 0, "failed C10 must not bump");

        // Wrong length.
        c10.setValid(true);
        bytes memory shortSig = new bytes(t2.length - 1);
        for (uint i = 0; i < shortSig.length; i++) shortSig[i] = t2[i];
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), shortSig), keccak256("c"), 0), 1);
        assertEq(w.slotUses(slotKey), 0, "bad length must not bump");
    }

    /// @notice Prime slotUses to `MAX_SLOT_USES - 1`, confirm the final
    ///         Type 2 is accepted and fills the cap, then confirm the
    ///         next Type 2 is rejected cleanly with SIG_VALIDATION_FAILED
    ///         (no revert — bundler-friendly).
    function test_slotCounterCapRejectsOverflow() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        bytes memory t1 = _buildType1Sig(R, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), t1), keccak256("reg"), 0);

        bytes32 slotKey = sha256(abi.encodePacked(R));
        uint256 cap = w.MAX_SLOT_USES();
        assertEq(cap, 65_536, "slot cap must be 65536");

        // slotUses mapping lives at BASE_SLOT + 2.
        // Mapping-slot derivation: keccak256(abi.encode(key, mappingSlot)).
        bytes32 mappingSlot = bytes32(uint256(BASE_SLOT) + 2);
        bytes32 entrySlot = keccak256(abi.encode(slotKey, mappingSlot));
        vm.store(address(w), entrySlot, bytes32(cap - 1));
        assertEq(w.slotUses(slotKey), cap - 1, "slot counter primed to cap-1");

        bytes memory t2 = _buildType2Sig(slotKey, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), t2), keccak256("last"), 0), 0);
        assertEq(w.slotUses(slotKey), cap, "final Type 2 fills the cap");

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), t2), keccak256("over"), 0), 1);
        assertEq(w.slotUses(slotKey), cap, "slot counter stays at cap after rejection");
    }

    /// @notice The slot cap must be independent per slotKey — burning one
    ///         slot to exhaustion must not affect another slot.
    function test_slotCounterIsPerSlot() public {
        PQJardinWallet w = factory.createAccount(MASTER_PK_SEED, MASTER_PK_ROOT);
        c10.setValid(true);

        bytes32 r1 = bytes32(uint256(0x1001));
        bytes32 r2 = bytes32(uint256(0x1002));
        bytes16 seed2 = bytes16(uint128(0xeeee));
        bytes16 root2 = bytes16(uint128(0xffff));

        // Register two distinct slots.
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), _buildType1Sig(r1, SUB_PK_SEED_16, SUB_PK_ROOT_16)), keccak256("r1"), 0);
        vm.prank(ENTRY_POINT_ADDR);
        w.validateUserOp(_packedOp(address(w), _buildType1Sig(r2, seed2, root2)), keccak256("r2"), 0);

        bytes32 slot1 = sha256(abi.encodePacked(r1));
        bytes32 slot2 = sha256(abi.encodePacked(r2));

        // Exhaust slot1 via direct storage write.
        bytes32 mappingSlot = bytes32(uint256(BASE_SLOT) + 2);
        bytes32 entry1 = keccak256(abi.encode(slot1, mappingSlot));
        vm.store(address(w), entry1, bytes32(w.MAX_SLOT_USES()));

        // slot1 is dead; slot2 must still work.
        bytes memory sig1 = _buildType2Sig(slot1, SUB_PK_SEED_16, SUB_PK_ROOT_16);
        bytes memory sig2 = _buildType2Sig(slot2, seed2, root2);
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig1), keccak256("x"), 0), 1, "slot1 exhausted");
        vm.prank(ENTRY_POINT_ADDR);
        assertEq(w.validateUserOp(_packedOp(address(w), sig2), keccak256("y"), 0), 0, "slot2 still fine");
        assertEq(w.slotUses(slot2), 1, "slot2 counter bumps independently");
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
        // The remaining 4008 bytes are zero — the mock verifier ignores
        // them and returns its pre-set validity flag.
    }

    /// @notice Build a Type 2 (all-C10) signature frame. Fixed 4073 bytes.
    function _buildType2Sig(bytes32 slotKey, bytes16 subSeed, bytes16 subRoot)
        internal
        pure
        returns (bytes memory out)
    {
        out = new bytes(1 + 32 + 16 + 16 + 4008);
        out[0] = 0x02;
        for (uint i = 0; i < 32; i++) out[1 + i] = slotKey[i];
        for (uint i = 0; i < 16; i++) out[33 + i] = subSeed[i];
        for (uint i = 0; i < 16; i++) out[49 + i] = subRoot[i];
        // Trailing 4008 bytes ignored by the mock.
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
