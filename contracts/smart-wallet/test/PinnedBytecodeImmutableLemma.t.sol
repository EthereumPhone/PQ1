// SPDX-License-Identifier: MIT
pragma solidity 0.8.28;

import {Test} from "forge-std/Test.sol";
import {IEntryPoint} from "account-abstraction/legacy/v06/IEntryPoint06.sol";

import {PQSmartWallet} from "../src/PQSmartWallet.sol";
import {PQSmartWalletFactory} from "../src/PQSmartWalletFactory.sol";
// The verifier leg is the pinned (Base-deployed) reference, built from its frozen copy, like
// PinnedCodehashes.t.sol: since 2026-11-14 src/verifiers/SPHINCsC10Asm.sol holds the undeployed
// optimized v1.
import {RefSPHINCsC10Asm} from "./ref/RefSPHINCsC10Asm.sol";
import {ISPHINCSVerifier} from "../src/verifiers/ISPHINCSVerifier.sol";
import {MockSPHINCSVerifier} from "./mocks/MockSPHINCSVerifier.sol";
import {PinnedCodehashSelector} from "./PinnedCodehashSelector.sol";

/// @notice **Bytecode-identity-modulo-immutables lemma.**
///
///         The pinned codehashes (PinnedCodehashes.t.sol /
///         contracts/verification/docs/PINNED_CODEHASHES.md) freeze ONE
///         instantiation of the compiled runtime — the one whose two
///         immutables (`_entryPoint`, `c10Verifier`) hold the values from
///         that test's deployment sequence. Every other instance of the same
///         compiled artifact (the Halmos harness wallets, a production
///         deployment with the real EntryPoint and verifier) embeds
///         different immutable values, so `extcodehash` differs.
///
///         This test machine-checks the missing identity: two instances of
///         the compiled `PQSmartWallet` (resp. factory) runtime, constructed
///         with pairwise-distinct argument values, are **byte-identical
///         outside 32-byte windows that hold exactly the respective
///         constructor-argument values**. Consequently:
///
///           pinned-instance code  ≡  any-instance code
///             (modulo the certified immutable windows),
///
///         so a Halmos rule executed against a harness instance is a proof
///         about the pinned runtime with its two address constants
///         universally generalised — which is precisely what the harness
///         intends (the verifier is quantified over; the EntryPoint address
///         is the wallet's caller gate, also symbolic in the harness rules).
///
///         The check is exhaustive over every byte of all three pairwise
///         diffs, so it certifies BOTH directions: every difference lies in
///         an immutable window, and each matched window holds the exact
///         argument values of the two instances.
contract PinnedBytecodeImmutableLemmaTest is PinnedCodehashSelector {
    /// Must equal PinnedCodehashes.t.sol::PQ_SMART_WALLET_CODEHASH (the
    /// canonical pin record is docs/PINNED_CODEHASHES.md). Re-asserted here
    /// so this lemma is provably about the SAME compiled artifact the
    /// pinned-codehash certification (and therefore the Halmos session)
    /// names.
    RefSPHINCsC10Asm internal sphincs;
    MockSPHINCSVerifier internal c10;
    PQSmartWallet internal implA;
    PQSmartWalletFactory internal factoryA;

    function setUp() public {
        // EXACT deployment sequence of PinnedCodehashesTest.setUp() — same
        // test-contract deployer address, same nonces — so instance A's
        // immutables (and hence its codehash) reproduce the pin.
        sphincs = new RefSPHINCsC10Asm();
        c10 = new MockSPHINCSVerifier();
        implA = new PQSmartWallet(IEntryPoint(address(0x4337)), c10);
        factoryA = new PQSmartWalletFactory(address(implA), c10);
    }

    /// **Wallet: runtime differs from the pinned instance only at the two
    /// immutables.** Three instances, pairwise-distinct (entryPoint,
    /// verifier) values, all three pairwise diffs checked.
    function test_wallet_runtime_differs_only_at_immutables() external {
        assertEq(
            address(implA).codehash,
            _pinnedWallet(),
            "instance A must be the pinned instance (see PinnedCodehashes.t.sol)"
        );

        MockSPHINCSVerifier verB = new MockSPHINCSVerifier();
        MockSPHINCSVerifier verC = new MockSPHINCSVerifier();
        PQSmartWallet implB = new PQSmartWallet(IEntryPoint(address(0xB0B)), verB);
        PQSmartWallet implC = new PQSmartWallet(IEntryPoint(address(0xC0C)), verC);

        uint256 w1 = _assertDiffOnlyAtImmutables(
            address(implA).code,
            address(implB).code,
            _walletVals(address(0x4337), address(c10), address(implA)),
            _walletVals(address(0xB0B), address(verB), address(implB))
        );
        uint256 w2 = _assertDiffOnlyAtImmutables(
            address(implA).code,
            address(implC).code,
            _walletVals(address(0x4337), address(c10), address(implA)),
            _walletVals(address(0xC0C), address(verC), address(implC))
        );
        uint256 w3 = _assertDiffOnlyAtImmutables(
            address(implB).code,
            address(implC).code,
            _walletVals(address(0xB0B), address(verB), address(implB)),
            _walletVals(address(0xC0C), address(verC), address(implC))
        );
        // Each immutable is referenced at least once, so every pair must
        // have found at least four windows; pairs must agree on the count
        // (same compiled artifact ⇒ same reference sites).
        assertGe(w1, 4, "wallet: expected >=4 immutable windows");
        assertEq(w1, w2, "wallet: window count mismatch A/B vs A/C");
        assertEq(w1, w3, "wallet: window count mismatch A/B vs B/C");
    }

    /// **Factory: runtime differs from the pinned instance only at the two
    /// immutables (`implementation`, `c10Verifier`).**
    function test_factory_runtime_differs_only_at_immutables() external {
        assertEq(
            address(factoryA).codehash,
            _pinnedFactory(),
            "instance A must be the pinned factory instance"
        );

        MockSPHINCSVerifier verB = new MockSPHINCSVerifier();
        MockSPHINCSVerifier verC = new MockSPHINCSVerifier();
        PQSmartWallet implB = new PQSmartWallet(IEntryPoint(address(0xB0B)), verB);
        PQSmartWallet implC = new PQSmartWallet(IEntryPoint(address(0xC0C)), verC);
        PQSmartWalletFactory factoryB = new PQSmartWalletFactory(address(implB), verB);
        PQSmartWalletFactory factoryC = new PQSmartWalletFactory(address(implC), verC);

        uint256 w1 = _assertDiffOnlyAtImmutables(
            address(factoryA).code,
            address(factoryB).code,
            _vals(address(implA), address(c10)),
            _vals(address(implB), address(verB))
        );
        uint256 w2 = _assertDiffOnlyAtImmutables(
            address(factoryA).code,
            address(factoryC).code,
            _vals(address(implA), address(c10)),
            _vals(address(implC), address(verC))
        );
        uint256 w3 = _assertDiffOnlyAtImmutables(
            address(factoryB).code,
            address(factoryC).code,
            _vals(address(implB), address(verB)),
            _vals(address(implC), address(verC))
        );
        assertGe(w1, 2, "factory: expected >=2 immutable windows");
        assertEq(w1, w2, "factory: window count mismatch A/B vs A/C");
        assertEq(w1, w3, "factory: window count mismatch A/B vs B/C");
    }

    /// **The verifier has no constructor arguments**, so instance identity
    /// is plain codehash equality — two fresh deployments must hash
    /// identically (and to the pin, certified by PinnedCodehashes.t.sol).
    function test_verifier_runtime_has_no_immutables() external {
        RefSPHINCsC10Asm v2 = new RefSPHINCsC10Asm();
        assertEq(address(sphincs).codehash, address(v2).codehash, "verifier runtime not constant");
    }

    // ── helpers ────────────────────────────────────────────────────────

    /// Factory immutables: (implementation, c10Verifier).
    function _vals(address ep, address ver) private pure returns (bytes32[] memory v) {
        v = new bytes32[](2);
        v[0] = bytes32(uint256(uint160(ep)));
        v[1] = bytes32(uint256(uint160(ver)));
    }

    /// Wallet immutables: (_entryPoint, c10Verifier) declared in
    /// PQSmartWallet, plus Solady EIP-712's constructor-cached
    /// `_cachedThis` (the instance's own address) and
    /// `_cachedDomainSeparator` (a keccak over name/version/chainid/self —
    /// recomputed here from the public EIP-712 domain
    /// `("PQSmartWallet", "1", block.chainid, self)`).
    function _walletVals(address ep, address ver, address self)
        private
        view
        returns (bytes32[] memory v)
    {
        v = new bytes32[](4);
        v[0] = bytes32(uint256(uint160(ep)));
        v[1] = bytes32(uint256(uint160(ver)));
        v[2] = bytes32(uint256(uint160(self)));
        v[3] = keccak256(
            abi.encode(
                keccak256(
                    "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                ),
                keccak256("PQSmartWallet"),
                keccak256("1"),
                block.chainid,
                self
            )
        );
    }

    function _loadWord(bytes memory code, uint256 j) private pure returns (bytes32 w) {
        assembly ("memory-safe") {
            w := mload(add(add(code, 32), j))
        }
    }

    /// Walk both runtimes byte-by-byte. Every differing byte must fall
    /// inside some 32-byte window [j, j+32) such that A's word at j equals
    /// one immutable's A-value and B's word at j equals the SAME
    /// immutable's B-value. Returns the number of such windows consumed.
    function _assertDiffOnlyAtImmutables(
        bytes memory a,
        bytes memory b,
        bytes32[] memory valsA,
        bytes32[] memory valsB
    ) private pure returns (uint256 windows) {
        require(a.length == b.length, "lemma: runtime lengths differ");
        require(valsA.length == valsB.length, "lemma: vals arity");
        uint256 i = 0;
        while (i < a.length) {
            if (a[i] == b[i]) {
                i++;
                continue;
            }
            bool matched = false;
            uint256 jStart = i >= 31 ? i - 31 : 0;
            for (uint256 j = jStart; j <= i && j + 32 <= a.length; j++) {
                bytes32 wa = _loadWord(a, j);
                bytes32 wb = _loadWord(b, j);
                for (uint256 k = 0; k < valsA.length; k++) {
                    if (wa == valsA[k] && wb == valsB[k]) {
                        i = j + 32;
                        windows++;
                        matched = true;
                        break;
                    }
                }
                if (matched) break;
            }
            require(matched, "lemma: runtime diff outside an immutable window");
        }
    }
}
