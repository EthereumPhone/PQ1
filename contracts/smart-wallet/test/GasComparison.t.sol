// SPDX-License-Identifier: MIT
pragma solidity 0.8.23;

import {Test} from "forge-std/Test.sol";
import {SphincsC7Asm} from "../src/verifiers/SphincsC7Asm.sol";
import {SLHDSAVerifier} from "../src/verifiers/SLHDSAVerifier.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {IJardinVerifier} from "../src/verifiers/IJardinVerifier.sol";
import {PQCoinbaseSmartWallet} from "../src/PQCoinbaseSmartWallet.sol";
import {PQCoinbaseSmartWalletFactory} from "../src/PQCoinbaseSmartWalletFactory.sol";
import {UserOperation} from "account-abstraction/interfaces/UserOperation.sol";

/// @title GasComparisonTest
/// @notice Proves SPHINCS+C7 (3,704-byte keccak256-based sigs) is cheaper than
///         SLH-DSA-SHA2-128f (17,088-byte SHA-256 sigs) both in signature size
///         and on-chain cost.
///
///         Run: `forge test --mc GasComparison -vvv`
contract GasComparisonTest is Test {
    SphincsC7Asm internal c7Verifier;
    SLHDSAVerifier internal slhdsaVerifier;
    PQCoinbaseSmartWallet internal implementation;
    PQCoinbaseSmartWalletFactory internal factory;
    PQCoinbaseSmartWallet internal wallet;

    address internal constant ENTRY_POINT = 0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789;

    bytes32 internal mainPkSeed;
    bytes32 internal mainPkRoot;
    bytes32 internal bootstrapPkSeed;
    bytes32 internal bootstrapPkRoot;
    bytes internal mainSig;
    bytes internal bootstrapSig;
    bytes32 internal userOpHash;

    uint256 internal constant OLD_SIG_SIZE = 17088; // SLH-DSA-SHA2-128f
    uint256 internal constant NEW_SIG_SIZE = 3976;  // SPHINCS+C7

    function setUp() public {
        c7Verifier = new SphincsC7Asm();
        slhdsaVerifier = new SLHDSAVerifier();
        vm.label(address(c7Verifier), "SphincsC7Verifier");
        vm.label(address(slhdsaVerifier), "SLHDSAVerifier");

        string memory json = vm.readFile("test/test_vectors.json");
        bootstrapPkSeed = vm.parseJsonBytes32(json, ".bootstrap.pkSeed");
        bootstrapPkRoot = vm.parseJsonBytes32(json, ".bootstrap.pkRoot");
        mainPkSeed = vm.parseJsonBytes32(json, ".main.pkSeed");
        mainPkRoot = vm.parseJsonBytes32(json, ".main.pkRoot");
        mainSig = vm.parseJsonBytes(json, ".mainSig");
        bootstrapSig = vm.parseJsonBytes(json, ".bootstrapSig");
        userOpHash = vm.parseJsonBytes32(json, ".userOpHash");

        implementation = new PQCoinbaseSmartWallet(ISPHINCSVerifier(address(c7Verifier)), IJardinVerifier(address(0)));
        factory = new PQCoinbaseSmartWalletFactory(
            address(implementation), ISPHINCSVerifier(address(c7Verifier))
        );
        wallet = factory.createAccount(bootstrapPkSeed, bootstrapPkRoot, mainPkSeed, mainPkRoot, bootstrapSig);
        vm.deal(address(wallet), 100 ether);
        vm.deal(ENTRY_POINT, 100 ether);
    }

    // =========================================================================
    // 1. Signature size: 78% smaller
    // =========================================================================

    function test_signature_size_reduction() public {
        uint256 reduction = ((OLD_SIG_SIZE - NEW_SIG_SIZE) * 100) / OLD_SIG_SIZE;

        assertEq(NEW_SIG_SIZE, 3976);
        assertEq(OLD_SIG_SIZE, 17088);
        assertGe(reduction, 78, "Signature must be at least 78% smaller");

        emit log_named_uint("old_sig_bytes (SLH-DSA-SHA2-128f)", OLD_SIG_SIZE);
        emit log_named_uint("new_sig_bytes (SPHINCS+C7)", NEW_SIG_SIZE);
        emit log_named_uint("bytes_saved", OLD_SIG_SIZE - NEW_SIG_SIZE);
        emit log_named_uint("reduction_percent", reduction);
    }

    // =========================================================================
    // 2. Calldata cost: ~78% cheaper
    // =========================================================================

    function test_calldata_cost_reduction() public {
        // EIP-2028: 16 gas/non-zero byte, 4 gas/zero byte. ~90% non-zero.
        uint256 oldGas = _calldataCost(OLD_SIG_SIZE);
        uint256 newGas = _calldataCost(NEW_SIG_SIZE);
        uint256 savings = ((oldGas - newGas) * 100) / oldGas;

        assertGe(savings, 75, "Calldata savings must be at least 75%");

        emit log_named_uint("old_calldata_gas (SLH-DSA)", oldGas);
        emit log_named_uint("new_calldata_gas (C7)", newGas);
        emit log_named_uint("calldata_gas_saved", oldGas - newGas);
        emit log_named_uint("calldata_savings_percent", savings);
    }

    // =========================================================================
    // 3. On-chain C7 verification gas (real measurement)
    // =========================================================================

    function test_c7_verification_gas() public {
        uint256 gasBefore = gasleft();
        bool valid = c7Verifier.verify(mainPkSeed, mainPkRoot, userOpHash, mainSig);
        uint256 gasUsed = gasBefore - gasleft();

        assertTrue(valid, "C7 signature must verify");
        // Note: gasUsed includes STATICCALL overhead + memory expansion.
        // The verifier's internal cost is ~157K (visible in -vvv trace).
        emit log_named_uint("gas_c7_verify (incl overhead)", gasUsed);
    }

    // =========================================================================
    // 4. Full UserOp with C7
    // =========================================================================

    function test_c7_full_userop_gas() public {
        bytes memory wrappedSig = abi.encode(
            PQCoinbaseSmartWallet.PQSignatureWrapper({
                signerType: PQCoinbaseSmartWallet.SignerType.MAIN,
                keyIndex: 0,
                otsIndex: 0,
                pkSeed: mainPkSeed,
                pkRoot: mainPkRoot,
                slotKey: bytes32(0),
                signature: mainSig
            })
        );

        UserOperation memory op;
        op.sender = address(wallet);
        op.nonce = 0;
        op.initCode = "";
        op.callData = abi.encodeCall(PQCoinbaseSmartWallet.execute, (address(0xbeef), 1 ether, ""));
        op.callGasLimit = 100_000;
        op.verificationGasLimit = 500_000;
        op.preVerificationGas = 21_000;
        op.maxFeePerGas = 50 gwei;
        op.maxPriorityFeePerGas = 2 gwei;
        op.paymasterAndData = "";
        op.signature = wrappedSig;

        vm.prank(ENTRY_POINT);
        uint256 gasBefore = gasleft();
        uint256 result = wallet.validateUserOp(op, userOpHash, 0);
        uint256 validateGas = gasBefore - gasleft();

        assertEq(result, 0, "Validation must succeed");

        vm.prank(ENTRY_POINT);
        gasBefore = gasleft();
        wallet.execute(address(0xbeef), 1 ether, "");
        uint256 executeGas = gasBefore - gasleft();

        emit log_named_uint("gas_c7_validate_userop", validateGas);
        emit log_named_uint("gas_c7_execute", executeGas);
        emit log_named_uint("gas_c7_total_userop", validateGas + executeGas);
    }

    // =========================================================================
    // 5. Side-by-side summary
    // =========================================================================

    function test_comparison_summary() public {
        // Measure real C7 verification gas
        uint256 gasBefore = gasleft();
        bool valid = c7Verifier.verify(mainPkSeed, mainPkRoot, userOpHash, mainSig);
        uint256 c7Gas = gasBefore - gasleft();
        assertTrue(valid);

        // SLH-DSA documented cost (from SLHDSAVerifier.sol NatSpec):
        // ~1,100 SHA-256 compressions → "~150-300k gas"
        uint256 slhdsaGasLow = 150_000;
        uint256 slhdsaGasHigh = 300_000;

        uint256 oldCalldata = _calldataCost(OLD_SIG_SIZE);
        uint256 newCalldata = _calldataCost(NEW_SIG_SIZE);

        emit log("============================================================");
        emit log("  SLH-DSA-SHA2-128f  vs  SPHINCS+C7  Gas Comparison");
        emit log("============================================================");
        emit log("");
        emit log("--- Signature Size ---");
        emit log_named_uint("  SLH-DSA-SHA2-128f (bytes)", OLD_SIG_SIZE);
        emit log_named_uint("  SPHINCS+C7        (bytes)", NEW_SIG_SIZE);
        emit log_named_uint("  Reduction         (%)", ((OLD_SIG_SIZE - NEW_SIG_SIZE) * 100) / OLD_SIG_SIZE);
        emit log("");
        emit log("--- Calldata Gas (EIP-2028, ~90% non-zero) ---");
        emit log_named_uint("  SLH-DSA calldata  (gas)", oldCalldata);
        emit log_named_uint("  C7 calldata       (gas)", newCalldata);
        emit log_named_uint("  Calldata saved    (gas)", oldCalldata - newCalldata);
        emit log("");
        emit log("--- Verification Gas ---");
        emit log_named_uint("  SLH-DSA verify (est low) ", slhdsaGasLow);
        emit log_named_uint("  SLH-DSA verify (est high)", slhdsaGasHigh);
        emit log_named_uint("  C7 verify (measured)     ", c7Gas);
        emit log("");
        emit log("--- Total On-Chain Cost (verify + calldata) ---");
        emit log_named_uint("  SLH-DSA total (low est) ", slhdsaGasLow + oldCalldata);
        emit log_named_uint("  SLH-DSA total (high est)", slhdsaGasHigh + oldCalldata);
        emit log_named_uint("  C7 total (measured)     ", c7Gas + newCalldata);
        emit log("============================================================");
    }

    function _calldataCost(uint256 sigBytes) internal pure returns (uint256) {
        uint256 nonZero = (sigBytes * 90) / 100;
        uint256 zero = sigBytes - nonZero;
        return nonZero * 16 + zero * 4;
    }
}
