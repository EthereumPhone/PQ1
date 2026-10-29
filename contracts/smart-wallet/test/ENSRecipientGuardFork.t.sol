// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {UserOperation06} from "account-abstraction/legacy/v06/UserOperation06.sol";
import {Test, console2} from "forge-std/Test.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {BlockHashAnchor} from "../src/ens/BlockHashAnchor.sol";
import {ENSRecipientGuard} from "../src/ens/ENSRecipientGuard.sol";
import {ENSRecipientGuardPacked} from "../src/ens/ENSRecipientGuardPacked.sol";

import {MockEntryPoint06} from "./mocks/MockEntryPoint06.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

interface IERC20Min {
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address a) external view returns (uint256);
}

/// @notice Gas cost and behaviour of three ways to make "pay alice.eth"
///         enforceable, against REAL mainnet state. Needs `ETH_RPC_URL`;
///         skipped without it, so plain `forge test` and CI are unaffected.
///
///   1. `ENSRecipientGuard`       reads ENS at execution (Solidity MVP)
///   2. `ENSRecipientGuardPacked` the same reads, packed calldata, assembly
///   3. `BlockHashAnchor`         the device verifies an ENS storage proof;
///                                the chain only checks the block hash
///
///   ETH_RPC_URL=https://ethereum-rpc.publicnode.com \
///     forge test --match-contract ENSRecipientGuardFork -vv
///
/// Every scenario is its own test function, so each runs in a fresh
/// transaction with cold accounts and storage (EIP-2929) — the realistic
/// case for a UserOp, and the reason the numbers are not taken in a loop.
/// The C10 verifier is mocked; validation gas is identical across scenarios,
/// so the deltas below are the guard's cost.
contract ENSRecipientGuardForkTest is Test {
    address internal constant VITALIK = 0xd8dA6BF26964aF9D7eEd9e03E53415D37aA96045;
    address internal constant USDC = 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48;
    uint256 internal constant COIN_ETH = 60;

    bool internal forked;
    MockEntryPoint06 internal ep;
    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal w;
    ENSRecipientGuard internal guard;
    ENSRecipientGuardPacked internal packed;
    BlockHashAnchor internal anchor;
    /// A real recent block and its hash, as the device would take them from
    /// the header it verified the ENS proof against.
    uint256 internal anchorBlock;
    bytes32 internal anchorHash;
    /// Read in setUp, not in the measured test: a read in the same
    /// transaction would warm the slot and understate the transfer's cost.
    uint256 internal usdcBefore;

    function setUp() public {
        string memory rpc = vm.envOr("ETH_RPC_URL", string(""));
        if (bytes(rpc).length == 0) return;
        vm.createSelectFork(rpc);
        forked = true;

        ep = new MockEntryPoint06();
        // The mock refuses to deploy on a real chain id (a deliberate guard
        // against shipping it); lift it only for the constructor.
        vm.chainId(31337);
        c10 = new MockSPHINCSVerifier();
        vm.chainId(1);
        c10.setValid(true);
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(address(ep)), c10);
        PQSmartWalletFactory factory = new PQSmartWalletFactory(address(impl), c10);
        w = factory.createAccount(
            bytes32(uint256(0xaaaa) << 240),
            bytes32(uint256(0xbbbb) << 240),
            bytes32(uint256(0xcccc) << 240),
            bytes32(uint256(0xdddd) << 240),
            uint64(block.chainid),
            hex"aaaa"
        );
        guard = new ENSRecipientGuard();
        packed = new ENSRecipientGuardPacked();
        anchor = new BlockHashAnchor();
        anchorBlock = block.number - 2;
        anchorHash = blockhash(anchorBlock);
        require(anchorHash != bytes32(0), "fork serves no block hashes");
        vm.deal(address(w), 10 ether);
        deal(USDC, address(w), 1_000e6);
        usdcBefore = IERC20Min(USDC).balanceOf(VITALIK);
    }

    modifier onlyForked() {
        if (!forked) vm.skip(true);
        _;
    }

    // ── helpers ─────────────────────────────────────────────────────

    /// ENS namehash for a two-label name `label.tld`.
    function _namehash2(string memory label, string memory tld) internal pure returns (bytes32 n) {
        n = keccak256(abi.encodePacked(bytes32(0), keccak256(bytes(tld))));
        n = keccak256(abi.encodePacked(n, keccak256(bytes(label))));
    }

    function _vitalikNode() internal pure returns (bytes32) {
        return _namehash2("vitalik", "eth");
    }

    function _single(address to, uint256 value, bytes memory data) internal view returns (bytes memory) {
        return abi.encodeCall(w.executeWithOffchainCount, (1, 0, to, value, data));
    }

    function _batch(address[] memory tos, uint256[] memory vals, bytes[] memory ds)
        internal
        view
        returns (bytes memory)
    {
        return abi.encodeCall(w.executeBatchWithOffchainCount, (1, 0, tos, vals, ds));
    }

    /// [check, call(to, value, data)] — the shape the device would sign.
    function _checkThen(address checker, bytes memory checkData, address to, uint256 value, bytes memory data)
        internal
        view
        returns (bytes memory)
    {
        address[] memory tos = new address[](2);
        uint256[] memory vals = new uint256[](2);
        bytes[] memory ds = new bytes[](2);
        tos[0] = checker;
        ds[0] = checkData;
        tos[1] = to;
        vals[1] = value;
        ds[1] = data;
        return _batch(tos, vals, ds);
    }

    /// [guard.check(node, coin, expected), call(to, value, data)]
    function _guarded(bytes32 node, address expected, address to, uint256 value, bytes memory data)
        internal
        view
        returns (bytes memory)
    {
        return _checkThen(
            address(guard), abi.encodeCall(ENSRecipientGuard.check, (node, COIN_ETH, expected)), to, value, data
        );
    }

    /// Packed guard calldata: node (32) || expected (20).
    function _packedArgs(bytes32 node, address expected) internal pure returns (bytes memory) {
        return abi.encodePacked(node, expected);
    }

    /// Anchor calldata: uint32 block number (4) || block hash (32).
    function _anchorArgs(uint256 number, bytes32 hash) internal pure returns (bytes memory) {
        return abi.encodePacked(uint32(number), hash);
    }

    function _op(bytes memory callData) internal view returns (UserOperation06 memory op) {
        op.sender = address(w);
        op.callData = callData;
        op.signature = abi.encode(uint256(1), new bytes(4008));
    }

    /// Validate + execute in one call, as EntryPoint v0.6 does; returns the
    /// gas that call used.
    function _run(string memory label, bytes memory callData) internal returns (uint256 used) {
        ep.validateThenExecute(address(w), _op(callData), bytes32(0), 0, callData);
        used = vm.lastCallGas().gasTotalUsed;
        console2.log(label);
        console2.log("  exec+validate gas :", used);
        console2.log("  callData bytes    :", callData.length);
        console2.log("  callData L1 gas   :", _calldataGas(callData));
    }

    /// EIP-2028 intrinsic cost of bytes carried in an L1 transaction
    /// (the part a bundler recovers through preVerificationGas).
    function _calldataGas(bytes memory b) internal pure returns (uint256 g) {
        for (uint256 i; i < b.length; ++i) {
            g += b[i] == 0 ? 4 : 16;
        }
    }

    // ── gas scenarios (read the -vv log) ────────────────────────────

    function test_gas_eth_single() public onlyForked {
        _run("ETH 0.1 -> vitalik, executeWithOffchainCount (today)", _single(VITALIK, 0.1 ether, ""));
    }

    function test_gas_eth_batch_unguarded() public onlyForked {
        address[] memory tos = new address[](1);
        uint256[] memory vals = new uint256[](1);
        bytes[] memory ds = new bytes[](1);
        tos[0] = VITALIK;
        vals[0] = 0.1 ether;
        _run("ETH 0.1 -> vitalik, batch of 1 (no guard)", _batch(tos, vals, ds));
    }

    function test_gas_eth_guarded() public onlyForked {
        _run("ETH 0.1 -> vitalik.eth, batch [guard, send]", _guarded(_vitalikNode(), VITALIK, VITALIK, 0.1 ether, ""));
        assertEq(VITALIK.balance > 0.1 ether, true);
    }

    function test_gas_usdc_single() public onlyForked {
        bytes memory t = abi.encodeCall(IERC20Min.transfer, (VITALIK, 100e6));
        _run("USDC 100 -> vitalik, executeWithOffchainCount (today)", _single(USDC, 0, t));
    }

    function test_gas_usdc_batch_unguarded() public onlyForked {
        address[] memory tos = new address[](1);
        uint256[] memory vals = new uint256[](1);
        bytes[] memory ds = new bytes[](1);
        tos[0] = USDC;
        ds[0] = abi.encodeCall(IERC20Min.transfer, (VITALIK, 100e6));
        _run("USDC 100 -> vitalik, batch of 1 (no guard)", _batch(tos, vals, ds));
    }

    function test_gas_usdc_guarded() public onlyForked {
        bytes memory t = abi.encodeCall(IERC20Min.transfer, (VITALIK, 100e6));
        _run("USDC 100 -> vitalik.eth, batch [guard, transfer]", _guarded(_vitalikNode(), VITALIK, USDC, 0, t));
        assertEq(IERC20Min(USDC).balanceOf(VITALIK), usdcBefore + 100e6);
    }

    function test_gas_eth_packedGuard() public onlyForked {
        _run(
            "ETH 0.1 -> vitalik.eth, batch [packed guard, send]",
            _checkThen(address(packed), _packedArgs(_vitalikNode(), VITALIK), VITALIK, 0.1 ether, "")
        );
    }

    function test_gas_usdc_packedGuard() public onlyForked {
        bytes memory t = abi.encodeCall(IERC20Min.transfer, (VITALIK, 100e6));
        _run(
            "USDC 100 -> vitalik.eth, batch [packed guard, transfer]",
            _checkThen(address(packed), _packedArgs(_vitalikNode(), VITALIK), USDC, 0, t)
        );
        assertEq(IERC20Min(USDC).balanceOf(VITALIK), usdcBefore + 100e6);
    }

    function test_gas_eth_anchor() public onlyForked {
        _run(
            "ETH 0.1 -> vitalik.eth, batch [block-hash anchor, send]",
            _checkThen(address(anchor), _anchorArgs(anchorBlock, anchorHash), VITALIK, 0.1 ether, "")
        );
    }

    function test_gas_usdc_anchor() public onlyForked {
        bytes memory t = abi.encodeCall(IERC20Min.transfer, (VITALIK, 100e6));
        _run(
            "USDC 100 -> vitalik.eth, batch [block-hash anchor, transfer]",
            _checkThen(address(anchor), _anchorArgs(anchorBlock, anchorHash), USDC, 0, t)
        );
        assertEq(IERC20Min(USDC).balanceOf(VITALIK), usdcBefore + 100e6);
    }

    function test_gas_guard_alone_cold() public onlyForked {
        guard.check(_vitalikNode(), COIN_ETH, VITALIK);
        console2.log("guard.check alone, cold, called from an EOA-like context:");
        console2.log("  gas :", vm.lastCallGas().gasTotalUsed);
    }

    // ── behaviour ───────────────────────────────────────────────────

    /// A substituted recipient (what a malicious companion would do) must
    /// revert the whole batch: the transfer never happens.
    function test_wrongRecipient_revertsWholeBatch() public onlyForked {
        address attacker = address(0xBAD);
        bytes memory cd = _guarded(_vitalikNode(), attacker, attacker, 1 ether, "");
        vm.expectRevert();
        ep.validateThenExecute(address(w), _op(cd), bytes32(0), 0, cd);
        assertEq(attacker.balance, 0);
    }

    function test_check_matches_real_ens() public onlyForked {
        guard.check(_vitalikNode(), COIN_ETH, VITALIK);
    }

    function test_check_wrongAddress_reverts() public onlyForked {
        vm.expectRevert(
            abi.encodeWithSelector(ENSRecipientGuard.NameMismatch.selector, _vitalikNode(), abi.encodePacked(VITALIK))
        );
        guard.check(_vitalikNode(), COIN_ETH, address(0xBAD));
    }

    function test_check_unsetCoinType_reverts() public onlyForked {
        // vitalik.eth sets no address for this (Base) coin type.
        vm.expectRevert();
        guard.check(_vitalikNode(), 0x80000000 | 8453, VITALIK);
    }

    function test_check_unregisteredName_reverts() public onlyForked {
        bytes32 node = _namehash2("pq1-no-such-name-7f3a9c", "eth");
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NoResolver.selector, node));
        guard.check(node, COIN_ETH, VITALIK);
    }

    function test_check_zeroExpected_reverts() public onlyForked {
        vm.expectRevert(ENSRecipientGuard.ZeroExpected.selector);
        guard.check(_vitalikNode(), COIN_ETH, address(0));
    }

    // ── packed guard behaviour ──────────────────────────────────────

    function _callOk(address target, bytes memory data) internal returns (bool ok) {
        (ok,) = target.call(data);
    }

    function test_packed_matches_real_ens() public onlyForked {
        assertTrue(_callOk(address(packed), _packedArgs(_vitalikNode(), VITALIK)));
    }

    function test_packed_wrongAddress_reverts() public onlyForked {
        assertFalse(_callOk(address(packed), _packedArgs(_vitalikNode(), address(0xBAD))));
    }

    function test_packed_unregisteredName_reverts() public onlyForked {
        bytes32 node = _namehash2("pq1-no-such-name-7f3a9c", "eth");
        assertFalse(_callOk(address(packed), _packedArgs(node, VITALIK)));
    }

    function test_packed_zeroExpected_reverts() public onlyForked {
        assertFalse(_callOk(address(packed), _packedArgs(_vitalikNode(), address(0))));
    }

    function test_packed_wrongLength_reverts() public onlyForked {
        assertFalse(_callOk(address(packed), abi.encodePacked(_vitalikNode(), VITALIK, uint8(0))));
        assertFalse(_callOk(address(packed), abi.encodePacked(_vitalikNode())));
        assertFalse(_callOk(address(packed), ""));
    }

    function test_packed_wrongRecipient_revertsWholeBatch() public onlyForked {
        address attacker = address(0xBAD);
        bytes memory cd = _checkThen(address(packed), _packedArgs(_vitalikNode(), attacker), attacker, 1 ether, "");
        vm.expectRevert();
        ep.validateThenExecute(address(w), _op(cd), bytes32(0), 0, cd);
        assertEq(attacker.balance, 0);
    }

    // ── anchor behaviour ────────────────────────────────────────────

    function test_anchor_accepts_real_recent_block() public onlyForked {
        assertTrue(_callOk(address(anchor), _anchorArgs(anchorBlock, anchorHash)));
        assertTrue(_callOk(address(anchor), _anchorArgs(block.number - 256, blockhash(block.number - 256))));
    }

    /// A forged header has a hash no block has: what a companion faking the
    /// ENS proof (fake state root) would have to get past.
    function test_anchor_rejects_forged_hash() public onlyForked {
        assertFalse(_callOk(address(anchor), _anchorArgs(anchorBlock, keccak256("forged header"))));
        assertFalse(_callOk(address(anchor), _anchorArgs(anchorBlock - 1, anchorHash)));
    }

    /// BLOCKHASH is 0 for the current block and for anything older than
    /// 256 blocks: a stale proof (or a zero hash) can never pass.
    function test_anchor_rejects_stale_current_and_zero() public onlyForked {
        assertFalse(_callOk(address(anchor), _anchorArgs(block.number - 257, bytes32(0))));
        assertFalse(_callOk(address(anchor), _anchorArgs(block.number, bytes32(0))));
        assertFalse(_callOk(address(anchor), _anchorArgs(block.number + 1, bytes32(0))));
    }

    /// Closes the loop with `tools/ens_proof_check.py`: the 36 bytes it prints
    /// as `anchor calldata` (built from the header it verified the proof
    /// against) must pass the anchor on a fresh fork.
    ///   ENS_ANCHOR=0x... ETH_RPC_URL=... forge test --mt test_anchor_acceptsDeviceCalldata
    function test_anchor_acceptsDeviceCalldata() public onlyForked {
        bytes memory a = vm.envOr("ENS_ANCHOR", bytes(""));
        if (a.length == 0) vm.skip(true);
        assertTrue(_callOk(address(anchor), a));
    }

    function test_anchor_wrongLength_reverts() public onlyForked {
        assertFalse(_callOk(address(anchor), abi.encodePacked(uint32(anchorBlock), anchorHash, uint8(0))));
        assertFalse(_callOk(address(anchor), abi.encodePacked(uint32(anchorBlock))));
        assertFalse(_callOk(address(anchor), ""));
    }

    function test_anchor_refusesValue() public onlyForked {
        vm.deal(address(this), 1 ether);
        (bool ok,) = address(anchor).call{value: 1}(_anchorArgs(anchorBlock, anchorHash));
        assertFalse(ok);
    }

    function test_anchor_forgedHash_revertsWholeBatch() public onlyForked {
        address attacker = address(0xBAD);
        bytes memory cd =
            _checkThen(address(anchor), _anchorArgs(anchorBlock, keccak256("forged header")), attacker, 1 ether, "");
        vm.expectRevert();
        ep.validateThenExecute(address(w), _op(cd), bytes32(0), 0, cd);
        assertEq(attacker.balance, 0);
    }
}
