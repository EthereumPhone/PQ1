// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";
import {ERC721} from "@openzeppelin/contracts/token/ERC721/ERC721.sol";
import {ERC1155} from "@openzeppelin/contracts/token/ERC1155/ERC1155.sol";
import {IERC721Receiver} from "@openzeppelin/contracts/token/ERC721/IERC721Receiver.sol";
import {IERC1155Receiver} from "@openzeppelin/contracts/token/ERC1155/IERC1155Receiver.sol";
import {IERC165} from "@openzeppelin/contracts/utils/introspection/IERC165.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";

contract TestNFT is ERC721 {
    constructor() ERC721("Test NFT", "TNFT") {}

    function safeMint(address to, uint256 id) external {
        _safeMint(to, id);
    }

    function mint(address to, uint256 id) external {
        _mint(to, id);
    }
}

contract TestMultiToken is ERC1155 {
    constructor() ERC1155("") {}

    function mint(address to, uint256 id, uint256 amount) external {
        _mint(to, id, amount, "");
    }

    function mintBatch(address to, uint256[] memory ids, uint256[] memory amounts) external {
        _mintBatch(to, ids, amounts, "");
    }
}

/// @notice The wallet can receive ERC-721 and ERC-1155 tokens.
///
///         Before the 2026-10 freeze the wallet had `receive()` but no token
///         hooks and no fallback, so every ERC-1155 transfer to it reverted,
///         and so did ERC-721 `safeTransferFrom` / `_safeMint` (both call
///         the hook on a contract recipient). The tests drive OpenZeppelin's
///         token implementations, whose acceptance checks are the ones real
///         tokens run.
contract TokenReceiverTest is Test {
    address constant ENTRY_POINT_ADDR = address(0x4337);

    bytes32 constant MASTER_PK_SEED = bytes32(uint256(0xaaaa) << 240);
    bytes32 constant MASTER_PK_ROOT = bytes32(uint256(0xbbbb) << 240);
    bytes32 constant SLOT0_PK_SEED = bytes32(uint256(0xcccc) << 240);
    bytes32 constant SLOT0_PK_ROOT = bytes32(uint256(0xdddd) << 240);

    PQSmartWallet internal wallet;
    TestNFT internal nft;
    TestMultiToken internal multi;

    function setUp() public {
        MockSPHINCSVerifier c10 = new MockSPHINCSVerifier();
        PQSmartWallet impl = new PQSmartWallet(IEntryPoint(ENTRY_POINT_ADDR), c10);
        PQSmartWalletFactory factory = new PQSmartWalletFactory(address(impl), c10);
        c10.setValid(true);
        wallet = factory.createAccount(
            MASTER_PK_SEED, MASTER_PK_ROOT, SLOT0_PK_SEED, SLOT0_PK_ROOT, uint64(block.chainid), hex"aaaa"
        );
        nft = new TestNFT();
        multi = new TestMultiToken();
    }

    function test_hookSelectorsMatchTheStandards() external view {
        assertEq(
            wallet.onERC721Received(address(1), address(2), 3, ""),
            IERC721Receiver.onERC721Received.selector,
            "ERC-721 hook"
        );
        assertEq(
            wallet.onERC1155Received(address(1), address(2), 3, 4, ""),
            IERC1155Receiver.onERC1155Received.selector,
            "ERC-1155 hook"
        );
        assertEq(
            wallet.onERC1155BatchReceived(address(1), address(2), new uint256[](0), new uint256[](0), ""),
            IERC1155Receiver.onERC1155BatchReceived.selector,
            "ERC-1155 batch hook"
        );
    }

    function test_erc721SafeMintToWallet() external {
        nft.safeMint(address(wallet), 1);
        assertEq(nft.ownerOf(1), address(wallet));
    }

    function test_erc721SafeTransferToWallet() external {
        address holder = makeAddr("holder");
        nft.mint(holder, 7);
        vm.prank(holder);
        nft.safeTransferFrom(holder, address(wallet), 7, "data");
        assertEq(nft.ownerOf(7), address(wallet));
    }

    function test_erc1155MintAndTransferToWallet() external {
        multi.mint(address(wallet), 1, 5);
        assertEq(multi.balanceOf(address(wallet), 1), 5);

        address holder = makeAddr("holder");
        multi.mint(holder, 2, 3);
        vm.prank(holder);
        multi.safeTransferFrom(holder, address(wallet), 2, 3, "");
        assertEq(multi.balanceOf(address(wallet), 2), 3);
    }

    function test_erc1155BatchToWallet() external {
        uint256[] memory ids = new uint256[](3);
        uint256[] memory amounts = new uint256[](3);
        for (uint256 i; i < 3; ++i) {
            ids[i] = i + 10;
            amounts[i] = i + 1;
        }
        multi.mintBatch(address(wallet), ids, amounts);
        for (uint256 i; i < 3; ++i) {
            assertEq(multi.balanceOf(address(wallet), ids[i]), amounts[i]);
        }
    }

    /// The hooks accept unconditionally and must not write state.
    function test_hooksTouchNoStorage() external {
        vm.record();
        wallet.onERC721Received(address(1), address(2), 3, "x");
        wallet.onERC1155Received(address(1), address(2), 3, 4, "x");
        wallet.onERC1155BatchReceived(address(1), address(2), new uint256[](1), new uint256[](1), "x");
        (, bytes32[] memory writes) = vm.accesses(address(wallet));
        assertEq(writes.length, 0, "receiver hooks wrote storage");
    }

    function test_supportsInterface() external view {
        assertTrue(wallet.supportsInterface(type(IERC165).interfaceId), "ERC-165");
        assertTrue(wallet.supportsInterface(type(IERC721Receiver).interfaceId), "ERC-721 receiver");
        assertTrue(wallet.supportsInterface(type(IERC1155Receiver).interfaceId), "ERC-1155 receiver");
        assertFalse(wallet.supportsInterface(0xffffffff), "ERC-165 forbids 0xffffffff");
        assertFalse(wallet.supportsInterface(0x1626ba7e), "not advertised");
    }

    /// Adding the hooks did not add a fallback: unknown selectors still
    /// revert, and plain ETH still arrives through `receive()`.
    function test_noFallbackButStillReceivesEth() external {
        (bool ok,) = address(wallet).call(abi.encodeWithSelector(bytes4(0xdeadbeef)));
        assertFalse(ok, "unknown selector must revert");

        vm.deal(address(this), 1 ether);
        (ok,) = address(wallet).call{value: 1 ether}("");
        assertTrue(ok, "plain ETH transfer");
        assertEq(address(wallet).balance, 1 ether);
    }
}
