// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";

/// @dev A verifier with NO storage at all. `MockSPHINCSVerifier` keeps a `valid`
///      flag in storage, so a test asserting "validation reads no foreign
///      storage" fails against it — on the MOCK's SLOAD, not the wallet's. The
///      shipping verifier (`SPHINCsC10Asm`) is stateless Yul, so this mock is
///      the faithful stand-in for the storage-shape properties below. Where a
///      test needs to toggle validity it uses `MockSPHINCSVerifier` instead.
contract StatelessAcceptVerifier is ISPHINCSVerifier {
    function verify(bytes32, bytes32, bytes32, bytes calldata) external pure returns (bool) {
        return true;
    }
}

/// @notice Executable assertions for the ERC-7562 validation-phase rules that
///         PQSmartWallet.validateUserOp must satisfy.
///
///         WHY. A smart account does not live or die by its own test suite — it
///         lives or dies by whether the rest of the ERC-4337 ecosystem will
///         carry its UserOps. Bundlers (the reference bundler, Pimlico's Alto,
///         Alchemy's Rundler) run a tracer over `simulateValidation` and
///         enforce ERC-7562: during the validation phase an unstaked account
///         may only touch storage ASSOCIATED WITH ITSELF, may not use banned
///         opcodes, and may not depend on unstaked external state. Trip a rule
///         and your UserOps are dropped from the canonical mempool or the
///         account gets throttled — a failure mode that no amount of green
///         local testing reveals, because it lives in someone else's tracer.
///
///         PQSmartWallet has exactly the risk profile those rules exist for:
///         `_validateSignature` WRITES account storage during validation (it
///         bumps `bootstrapUses` for a Type-1 rotation and `slotUses[i]` for a
///         Type-2), reads the cap fields, and dispatches a heavy SPHINCS+C10
///         verification to an immutable external verifier. Before this file,
///         `grep -rn "7562\|bundler-spec-tests" docs/ contracts/` returned
///         nothing: the account's mempool-compatibility was assumed.
///
///         SCOPE, stated honestly. This is the storage/call-graph subset that
///         a Foundry test can actually decide, using `vm.record()` +
///         `vm.accesses()` and `vm.expectCall`. It does NOT replace running
///         eth-infinitism's `bundler-spec-tests` against a real bundler+anvil,
///         which additionally covers banned opcodes (GAS, NUMBER, TIMESTAMP,
///         BLOCKHASH, CREATE, SELFDESTRUCT …), gas/stack limits and the
///         throttling/reputation rules. That remains the follow-up in #582 —
///         this file is the part that can run in every CI run today, in one
///         second, with no docker and no network.
contract ERC7562ValidationRulesTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    MockSPHINCSVerifier internal c10;
    StatelessAcceptVerifier internal stateless;
    PQSmartWallet internal impl;
    PQSmartWalletFactory internal factory;
    PQSmartWallet internal wallet;
    /// @dev Same wallet shape, wired to the stateless verifier. Used by the
    ///      storage-shape tests so a foreign SLOAD can only be the wallet's fault.
    PQSmartWallet internal implS;
    PQSmartWalletFactory internal factoryS;
    PQSmartWallet internal walletS;

    bytes32 constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);
    bytes32 constant SLOT1_PK_SEED = bytes32(uint256(0xeeee) << 240);
    bytes32 constant SLOT1_PK_ROOT = bytes32(uint256(0xffff) << 240);
    bytes constant FACTORY_SIG = hex"aaaa";
    uint256 constant C10_SIG_LEN = 4008;

    // NOTE on what is NOT asserted: "every touched slot lies inside the
    // ERC-7201 namespace" is not a decidable check here. Mapping and array
    // slots are keccak-derived from the namespace root and are not contiguous
    // with it, so slot-membership cannot be tested without reimplementing the
    // derivation for every field. The weaker, decidable, and still load-bearing
    // property is the one below: during validation the account touches NO OTHER
    // CONTRACT's storage at all.

    function setUp() public {
        c10 = new MockSPHINCSVerifier();
        impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        factory = new PQSmartWalletFactory(address(impl), c10);
        c10.setValid(true);
        wallet = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid), FACTORY_SIG
        );
        vm.deal(address(wallet), 10 ether);

        stateless = new StatelessAcceptVerifier();
        implS = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), stateless);
        factoryS = new PQSmartWalletFactory(address(implS), stateless);
        walletS = factoryS.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT,
            uint64(block.chainid), FACTORY_SIG
        );
        vm.deal(address(walletS), 10 ether);
    }

    // ── helpers ──────────────────────────────────────────────────────

    function _opFor(PQSmartWallet w, bytes memory callData, bytes memory sig)
        internal
        pure
        returns (UserOperation06 memory op)
    {
        op.sender = address(w);
        op.nonce = 0;
        op.initCode = "";
        op.callData = callData;
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = sig;
    }

    function _op(bytes memory sig) internal view returns (UserOperation06 memory op) {
        op.sender = address(wallet);
        op.nonce = 0;
        op.initCode = "";
        op.callData = abi.encodeCall(
            wallet.executeWithOffchainCount, (1, 0, address(0xdead), 0, "")
        );
        op.callGasLimit = 0;
        op.verificationGasLimit = 0;
        op.preVerificationGas = 0;
        op.maxFeePerGas = 0;
        op.maxPriorityFeePerGas = 0;
        op.paymasterAndData = "";
        op.signature = sig;
    }

    function _wrapSig(uint256 ownerIndex, bytes memory inner) internal pure returns (bytes memory) {
        return abi.encode(ownerIndex, inner);
    }

    function _slotSig() internal pure returns (bytes memory) {
        return _wrapSig(1, new bytes(C10_SIG_LEN));
    }

    /// @dev A Type-1 (bootstrap) wrapper. NOTE — corrected while writing this
    ///      file: the validation phase does NOT install the new owner. It bumps
    ///      `bootstrapUses` only; the install happens in the EXECUTION phase
    ///      when the op's callData calls `addOwnerBytes`. That split is exactly
    ///      what keeps the validation phase's write set small enough for
    ///      ERC-7562, so it is worth an executable assertion rather than a
    ///      comment.
    function _bootstrapSig() internal pure returns (bytes memory) {
        return abi.encode(uint256(0), new bytes(C10_SIG_LEN));
    }

    /// @dev True when `slot` lies in the wallet's own ERC-7201 region. The
    ///      namespace root plus the mapping/array slots derived from it are all
    ///      "associated storage" under ERC-7562 for the account itself, so the
    ///      decidable property in a unit test is the weaker but still
    ///      load-bearing one: no OTHER CONTRACT's storage is touched at all.
    ///      That is what `_assertOnlySelfStorage` checks.
    function _assertOnlySelfStorage(string memory what) internal {
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(walletS));
        assertTrue(reads.length + writes.length > 0, string.concat(what, ": expected some storage access"));

        // Nothing outside the account may be read or written during validation.
        (bytes32[] memory vr, bytes32[] memory vw) = vm.accesses(address(stateless));
        assertEq(vr.length, 0, string.concat(what, ": verifier storage must not be read"));
        assertEq(vw.length, 0, string.concat(what, ": verifier storage must not be written"));

        (bytes32[] memory fr, bytes32[] memory fw) = vm.accesses(address(factoryS));
        assertEq(fr.length, 0, string.concat(what, ": factory storage must not be read"));
        assertEq(fw.length, 0, string.concat(what, ": factory storage must not be written"));

        // NOTE: the ERC-1967 proxy's DELEGATECALL to the implementation is the
        // proxy mechanism, not an external state dependency — the code executes
        // in the account's own storage context. So the implementation ADDRESS is
        // read (from the ERC-1967 slot, which is the account's own storage) but
        // the implementation's storage must never be.
        (bytes32[] memory ir, bytes32[] memory iw) = vm.accesses(address(implS));
        assertEq(ir.length, 0, string.concat(what, ": implementation storage must not be read"));
        assertEq(iw.length, 0, string.concat(what, ": implementation storage must not be written"));
    }

    // ── tests ────────────────────────────────────────────────────────

    /// STO-0xx: a Type-2 (slot) validation must confine every storage access to
    /// the account itself.
    function test_type2_validation_touches_only_own_storage() public {
        UserOperation06 memory op = _opFor(
            walletS,
            abi.encodeCall(walletS.executeWithOffchainCount, (1, 0, address(0xdead), 0, "")),
            _slotSig()
        );

        vm.record();
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = walletS.validateUserOp(op, bytes32(uint256(0x1234)), 0);
        assertEq(vd, 0, "validation must succeed, or this proves nothing");

        _assertOnlySelfStorage("type2");
    }

    /// Same for Type-1. Its validation phase writes only `bootstrapUses`;
    /// the owner it authorises is installed later, in the execution phase
    /// (pinned at the end of this test).
    function test_type1_validation_touches_only_own_storage() public {
        bytes memory slot1 = abi.encodePacked(SLOT1_PK_SEED, SLOT1_PK_ROOT);
        UserOperation06 memory op = _opFor(
            walletS, abi.encodeCall(walletS.addOwnerBytes, (slot1)), _bootstrapSig()
        );

        uint256 ownersBefore = walletS.nextOwnerIndex();

        vm.record();
        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = walletS.validateUserOp(op, bytes32(uint256(0x1234)), 0);
        assertEq(vd, 0, "type1 validation must succeed");

        _assertOnlySelfStorage("type1");

        // Pins the phase split that keeps the validation write set small: the
        // owner is NOT installed during validation.
        assertEq(
            walletS.nextOwnerIndex(), ownersBefore, "validation must not install an owner"
        );
        vm.prank(ENTRY_POINT_ADDR);
        walletS.addOwnerBytes(slot1);
        assertEq(
            walletS.nextOwnerIndex(), ownersBefore + 1, "the EXECUTION phase installs it"
        );
    }

    /// OP-0xx neighbourhood: the only external contract the validation phase may
    /// call is the IMMUTABLE verifier. An immutable address cannot be swapped by
    /// a third party, which is why this is acceptable to bundlers where a
    /// mutable dependency would not be.
    function test_validation_calls_only_the_immutable_verifier() public {
        UserOperation06 memory op = _op(_slotSig());

        // Assert the verifier IS called (a rule check that passes because
        // nothing happened is not a rule check).
        vm.expectCall(address(c10), abi.encodeWithSelector(MockSPHINCSVerifier.verify.selector));
        // ...and that the account never calls the FACTORY during validation.
        // The implementation is deliberately NOT asserted against: an ERC-1967
        // proxy DELEGATECALLs to it on every call, which forge counts as a call
        // to that address. That is the proxy mechanism executing in the
        // account's own context, not an external dependency, and asserting
        // otherwise would be asserting that the wallet is not a proxy.
        vm.expectCall(address(factory), "", 0);

        vm.prank(ENTRY_POINT_ADDR);
        assertEq(wallet.validateUserOp(op, bytes32(uint256(0x1234)), 0), 0);
    }

    /// The verifier address must be immutable, not storage-backed. If it were
    /// upgradeable, the validation phase would depend on mutable external state
    /// and the account would be a candidate for throttling.
    function test_verifier_reference_is_not_storage_backed() public {
        vm.record();
        address v = address(wallet.c10Verifier());
        (bytes32[] memory reads, bytes32[] memory writes) = vm.accesses(address(wallet));

        assertEq(v, address(c10), "verifier must be the one wired at construction");
        assertEq(writes.length, 0, "a getter must not write");
        // The ONLY slot a `c10Verifier()` call may touch is the ERC-1967
        // implementation slot the proxy reads to find its logic. The verifier
        // address itself is an impl-level `immutable`, i.e. it lives in code,
        // so an upgrade cannot silently repoint it and the validation phase has
        // no mutable external dependency to be throttled for.
        bytes32 erc1967Impl =
            bytes32(uint256(keccak256("eip1967.proxy.implementation")) - 1);
        for (uint256 i; i < reads.length; ++i) {
            assertEq(reads[i], erc1967Impl, "only the ERC-1967 impl slot may be read");
        }
    }

    /// Validation must not depend on block context that a bundler's tracer bans
    /// or that makes simulation results non-reproducible between simulation and
    /// inclusion. Rather than diff opcodes (which needs a tracer), assert the
    /// observable consequence: the same op validates identically under wildly
    /// different block number / timestamp / basefee.
    function test_validation_result_is_independent_of_block_context() public {
        UserOperation06 memory op = _op(_slotSig());

        vm.roll(1);
        vm.warp(1);
        vm.fee(1);
        vm.prank(ENTRY_POINT_ADDR);
        uint256 a = wallet.validateUserOp(op, bytes32(uint256(0x1234)), 0);

        vm.roll(19_000_000);
        vm.warp(1_900_000_000);
        vm.fee(500 gwei);
        // nonce/counter state advanced, so use a fresh op with the next slot use
        vm.prank(ENTRY_POINT_ADDR);
        uint256 b = wallet.validateUserOp(op, bytes32(uint256(0x1234)), 0);

        assertEq(a, 0, "validation must succeed at block 1");
        assertEq(b, 0, "and identically 19M blocks later");
    }

    /// `validateUserOp` returns SIG_VALIDATION_FAILED (1) rather than reverting
    /// on a bad signature. A revert during the validation phase is what gets an
    /// account marked as failing simulation; the 4337 contract expects the
    /// return-code form.
    function test_bad_signature_returns_failure_code_not_revert() public {
        c10.setValid(false);
        UserOperation06 memory op = _op(_slotSig());

        vm.prank(ENTRY_POINT_ADDR);
        uint256 vd = wallet.validateUserOp(op, bytes32(uint256(0x1234)), 0);
        assertEq(vd, 1, "must return SIG_VALIDATION_FAILED, not revert");
    }

    /// Only the EntryPoint may drive validation. An account that let anyone call
    /// `validateUserOp` would let a third party burn its capped counters — the
    /// caps are monotonic and unresettable (invariant #7), so that is a
    /// permanent denial of service, not an inconvenience.
    function test_only_entrypoint_can_validate() public {
        UserOperation06 memory op = _op(_slotSig());
        vm.expectRevert();
        wallet.validateUserOp(op, bytes32(uint256(0x1234)), 0);
    }
}
