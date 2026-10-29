// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";

import {ENSRecipientGuard} from "../src/ens/ENSRecipientGuard.sol";

/// Offline checks of the resolver response boundary; no RPC or mainnet fork.
contract ENSRecipientGuardOfflineTest is Test {
    address internal constant RESOLVER = address(0xBEEF);
    address internal constant EXPECTED = address(0x1234);
    bytes32 internal constant NODE = keccak256("offline-guard-test");
    uint256 internal constant COIN = 60;
    ENSRecipientGuard internal guard;

    function setUp() public {
        guard = new ENSRecipientGuard();
        vm.etch(guard.ENS_REGISTRY(), hex"00");
        vm.etch(RESOLVER, hex"00");
        vm.mockCall(
            guard.ENS_REGISTRY(), abi.encodeWithSignature("resolver(bytes32)", NODE), abi.encode(RESOLVER)
        );
    }

    function query() internal pure returns (bytes memory) {
        return abi.encodeWithSignature("addr(bytes32,uint256)", NODE, COIN);
    }

    function test_acceptsMatchingTwentyByteAnswer() public {
        vm.mockCall(RESOLVER, query(), abi.encode(abi.encodePacked(EXPECTED)));
        guard.check(NODE, COIN, EXPECTED);
    }

    function test_resolverRevertRefusesWithEmptyAnswer() public {
        vm.mockCallRevert(RESOLVER, query(), hex"deadbeef");
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NameMismatch.selector, NODE, bytes("")));
        guard.check(NODE, COIN, EXPECTED);
    }

    function testFuzz_shortReturnRefusesWithEmptyAnswer(uint8 length) public {
        vm.mockCall(RESOLVER, query(), new bytes(uint256(length) % 64));
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NameMismatch.selector, NODE, bytes("")));
        guard.check(NODE, COIN, EXPECTED);
    }

    function test_malformedAbiRefuses() public {
        vm.mockCall(RESOLVER, query(), abi.encode(type(uint256).max, uint256(20)));
        vm.expectRevert();
        guard.check(NODE, COIN, EXPECTED);
    }

    function testFuzz_wrongAnswerLengthRefuses(uint8 length) public {
        vm.assume(length != 20);
        bytes memory answer = new bytes(length);
        vm.mockCall(RESOLVER, query(), abi.encode(answer));
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NameMismatch.selector, NODE, answer));
        guard.check(NODE, COIN, EXPECTED);
    }

    function testFuzz_otherTwentyByteAddressRefuses(address other) public {
        vm.assume(other != EXPECTED);
        bytes memory answer = abi.encodePacked(other);
        vm.mockCall(RESOLVER, query(), abi.encode(answer));
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NameMismatch.selector, NODE, answer));
        guard.check(NODE, COIN, EXPECTED);
    }

    function test_zeroExpectedRefuses() public {
        vm.expectRevert(ENSRecipientGuard.ZeroExpected.selector);
        guard.check(NODE, COIN, address(0));
    }

    function test_missingResolverRefuses() public {
        vm.etch(RESOLVER, bytes(""));
        vm.expectRevert(abi.encodeWithSelector(ENSRecipientGuard.NoResolver.selector, NODE));
        guard.check(NODE, COIN, EXPECTED);
    }
}
