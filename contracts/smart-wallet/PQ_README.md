# PQ Coinbase Smart Wallet (post-quantum fork)

This directory is a fork of [coinbase/smart-wallet](https://github.com/coinbase/smart-wallet)
modified for [PQSigner OS](../../README.md). It is **not** a drop-in replacement for the
upstream wallet — every classical signer path has been removed.

## What changed vs. upstream

| File | Upstream | Here |
|------|----------|------|
| `src/MultiOwnable.sol` | bytes-tagged owners (EOA *or* P-256 pubkey) | **deleted** |
| `src/CoinbaseSmartWallet.sol` | dispatches on owner type → secp256k1 *or* WebAuthn | **deleted** |
| `src/CoinbaseSmartWalletFactory.sol` | salt = `(owners[], nonce)` | **deleted** |
| `src/PQOwnable.sol` | — | **new**: single owner = `sha256(slh-dsa pk)` |
| `src/PQCoinbaseSmartWallet.sol` | — | **new**: validates SLH-DSA-SHA2-128f only |
| `src/PQCoinbaseSmartWalletFactory.sol` | — | **new**: salt = `(ownerKeyHash, nonce)` |
| `src/verifiers/ISLHDSAVerifier.sol` | — | **new**: pluggable verifier interface |
| `src/verifiers/SLHDSAVerifier.sol` | — | **new**: reference Solidity FIPS-205 verifier |

`ERC1271.sol` is unchanged (it's already signer-agnostic) but the EIP-712
domain name is now `"PQ Coinbase Smart Wallet"` so off-chain message
recovery doesn't collide with upstream wallets at the same address.

## Why no EOA fallback

A wallet that accepts both `secp256k1` and SLH-DSA signatures is exactly
as secure as `min(secp256k1, SLH-DSA)`. The day a cryptographically
relevant quantum computer exists, every secp256k1 fallback path on every
PQ wallet on chain becomes a free-money faucet for whoever runs Shor's
algorithm. The only way to deploy a *real* PQ wallet is to remove the
fallback path entirely, which is what this fork does. There is no
"upgrade later, ship classical first" — there's no upgrade path that
prevents replay of a UserOp signed under a classical scheme on a chain
where it was already valid, so the only safe option is to never accept
one in the first place.

## Signature wire format

```solidity
struct PQSignatureWrapper {
    bytes pk;        // 32 bytes — SLH-DSA-SHA2-128f verifying key
    bytes signature; // 17,088 bytes — SLH-DSA signature
}
```

The `EntryPoint` calls `validateUserOp(userOp, userOpHash, …)`, which
ABI-decodes the wrapper, checks `sha256(pk) == ownerKeyHash`, and hands
the pair to the configured `ISLHDSAVerifier`. PQSigner OS produces the
17,088-byte signature directly inside the secure world (see
`secure/src/aa/userop.rs`); see `secure/src/nsc/cmd_sign_userop.rs` for
the trusted-UI flow.

## On-chain verifier gas profile

The reference `SLHDSAVerifier.sol` performs roughly 1,100 SHA-256
compressions per call (a FORS opening + 22 layers of XMSS opening +
WOTS+ chains in each layer). At 60 gas per `sha256` precompile call
plus calldata costs the verification fits comfortably in a single L2
block on Base, but is too expensive for L1 mainnet as a hot path.
Production deployments that need L1 verification can plug in a Groth16
verifier that proves an off-chain `slh_verify` invocation — the
`ISLHDSAVerifier` interface is the swap point.
