// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Base} from "./Base.t.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

/// @notice Helper target for gas benchmarks.
contract Sink {
    uint256 public value;
    function set(uint256 v) external payable { value = v; }
}

/// @notice Gas benchmarks with mock verifier. Run with
///         `forge test --mc GasBenchmark -vvv`
contract GasBenchmarkTest is Base {
    Sink internal sink;

    function setUp() public override {
        super.setUp();
        sink = new Sink();
        vm.label(address(sink), "Sink");
    }

    // ── Account creation ──────────────────────────────────────────────

    function test_gas_createAccount_newWallet() public {
        bytes32 freshSeed = bytes32(uint256(0xff01));
        bytes32 freshRoot = bytes32(uint256(0xff02));
        bytes memory dummySig = new bytes(3704);

        uint256 gasBefore = gasleft();
        factory.createAccount(freshSeed, freshRoot, TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT, dummySig);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_createAccount_new", gasUsed);
    }

    function test_gas_createAccount_existingWallet() public {
        bytes memory dummySig = new bytes(3704);

        uint256 gasBefore = gasleft();
        factory.createAccount(
            TEST_BOOTSTRAP_PK_SEED, TEST_BOOTSTRAP_PK_ROOT,
            TEST_MAIN_PK_SEED, TEST_MAIN_PK_ROOT,
            dummySig
        );
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_createAccount_existing", gasUsed);
    }

    // ── validateUserOp ────────────────────────────────────────────────

    function test_gas_validateUserOp_mainSigner() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(sink), 0, abi.encodeCall(Sink.set, (42))))
        );

        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.validateUserOp(op, keccak256("hash"), 0);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_validateUserOp_main", gasUsed);
    }

    function test_gas_validateUserOp_bootstrapSigner() public {
        UserOperation memory op = _buildBootstrapUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(sink), 0, abi.encodeCall(Sink.set, (42))))
        );

        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.validateUserOp(op, keccak256("hash"), 0);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_validateUserOp_bootstrap", gasUsed);
    }

    function test_gas_validateUserOp_mainSigner_secondOTS() public {
        // Consume OTS 0 first
        UserOperation memory op1 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(sink), 0, abi.encodeCall(Sink.set, (1))))
        );
        vm.prank(ENTRY_POINT);
        wallet.validateUserOp(op1, keccak256("h1"), 0);

        // Measure OTS 1 (warm storage)
        UserOperation memory op2 = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(sink), 0, abi.encodeCall(Sink.set, (2))))
        );
        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.validateUserOp(op2, keccak256("h2"), 0);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_validateUserOp_main_warmOTS", gasUsed);
    }

    // ── execute ────────────────────────────────────────────────────────

    function test_gas_execute_simple() public {
        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.execute(address(sink), 0, abi.encodeCall(Sink.set, (99)));
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_execute_simple", gasUsed);
    }

    // ── rotateMainSigner ──────────────────────────────────────────────

    function test_gas_rotateMainSigner() public {
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        vm.prank(address(wallet));
        uint256 gasBefore = gasleft();
        wallet.rotateMainSigner(1, newSeed, newRoot);
        uint256 gasUsed = gasBefore - gasleft();

        emit log_named_uint("gas_rotateMainSigner", gasUsed);
    }

    // ── Full UserOp flow (validate + execute) ─────────────────────────

    function test_gas_fullUserOp_mainSigner() public {
        UserOperation memory op = _buildUserOp(
            abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(sink), 0, abi.encodeCall(Sink.set, (42))))
        );

        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.validateUserOp(op, keccak256("hash"), 0);
        uint256 validateGas = gasBefore - gasleft();

        vm.prank(ENTRY_POINT);
        gasBefore = gasleft();
        wallet.execute(address(sink), 0, abi.encodeCall(Sink.set, (42)));
        uint256 executeGas = gasBefore - gasleft();

        emit log_named_uint("gas_fullUserOp_main_validate", validateGas);
        emit log_named_uint("gas_fullUserOp_main_execute", executeGas);
        emit log_named_uint("gas_fullUserOp_main_total", validateGas + executeGas);
    }

    function test_gas_fullUserOp_bootstrapRotate() public {
        bytes32 newSeed = bytes32(uint256(0xdeadbeef));
        bytes32 newRoot = bytes32(uint256(0xcafebabe));
        bytes memory rotateCalldata = abi.encodeCall(
            PQCoinbaseSmartWallet.execute,
            (address(wallet), 0, abi.encodeCall(PQCoinbaseSmartWallet.rotateMainSigner, (1, newSeed, newRoot)))
        );

        UserOperation memory op = _buildBootstrapUserOp(rotateCalldata);

        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        wallet.validateUserOp(op, keccak256("hash"), 0);
        uint256 validateGas = gasBefore - gasleft();

        vm.prank(ENTRY_POINT);
        gasBefore = gasleft();
        wallet.execute(
            address(wallet), 0,
            abi.encodeCall(PQCoinbaseSmartWallet.rotateMainSigner, (1, newSeed, newRoot))
        );
        uint256 executeGas = gasBefore - gasleft();

        emit log_named_uint("gas_fullUserOp_bootstrapRotate_validate", validateGas);
        emit log_named_uint("gas_fullUserOp_bootstrapRotate_execute", executeGas);
        emit log_named_uint("gas_fullUserOp_bootstrapRotate_total", validateGas + executeGas);
    }
}
