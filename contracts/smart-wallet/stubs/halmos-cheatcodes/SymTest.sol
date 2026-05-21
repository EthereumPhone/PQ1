// SPDX-License-Identifier: MIT
pragma solidity >=0.8.0;

/// @notice Local stub for `halmos-cheatcodes/SymTest`. The real package
///         injects symbolic-value cheatcodes at the SVM level; when run
///         under plain Foundry (e.g. for compile-only sanity), this
///         stub returns concrete zero-filled placeholders so the test
///         files still compile.
///
///         Halmos itself replaces the `svm` interface at runtime, so
///         this stub is only exercised by `forge build` / `forge test`
///         in environments where Halmos is not installed.
contract SymTest {
    SvmStub internal constant svm = SvmStub(address(0));
}

/// @notice Stub of the Halmos `svm` cheatcode interface. Returns
///         concrete placeholders; real Halmos replaces these calls
///         with symbolic-value generation.
interface SvmStub {
    function createBytes(uint256 size, string calldata name) external pure returns (bytes memory);
    function createUint(uint256 bits, string calldata name) external pure returns (uint256);
    function createAddress(string calldata name) external pure returns (address);
    function createBool(string calldata name) external pure returns (bool);
}
