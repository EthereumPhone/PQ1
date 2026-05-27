# Pinned bytecode codehashes

Each `solidity*_compiles_correctly` axiom in `Bridge/Refinement.lean`
is bound to a specific runtime codehash. When that codehash changes,
the corresponding discharge artifact (Halmos session, Certora
rule-set, or differential test) must be re-run before the pin is
updated.

This file is the canonical pinning record. It is parity-tested at CI
by `contracts/smart-wallet/test/PinnedCodehashes.t.sol`, which
asserts that the deployed `address(<contract>).codehash` equals the
pinned value below. Any drift fails CI.

## Pinned values (re-pinned 2026-05-27)

> **Re-pinned 2026-05-27** after the EntryPoint-guard fix (`addOwnerBytes` /
> `removeOwnerAtIndex`) plus a clean rebuild that reconciled prior
> in-progress drift. The A3 bridge discharges (Halmos for the wallet/verifier,
> Certora for the factory) have **NOT** been re-run against these hashes yet —
> A3.1–A3.4 are marked `pending-rerun` in `AXIOM_STATUS.json`. Re-run the
> discharge artifacts before treating these pins as proof-backed.

```
PQSmartWallet         0xdc2aa6c4db5cc6ebec277d97ef6adada7c448d09a76749ddfa94edd4879a3680
PQSmartWalletFactory  0x604e4000bb7d3fef349d1f9b09e3f048c6baa7a37f10d1bdfebef9ce1ecf3e02
SPHINCsC10Asm         0x919cf8ef4b028b50f51de2e71aba7d08900d0e59833d003eed68102c7e9289c0
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

## EntryPoint v0.6 (cited-TCB)

```
EntryPoint v0.6 address (mainnet)  0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
```

Discharge for this is cited (OpenZeppelin / ChainSecurity / Spearbit
audits + 18+ months mainnet operation). The Lean axiom
`Bridge.EntryPoint.entrypoint_honest` (A2) is left as-is per user
decision.

## EVM SHA-256 precompile (cited universal Ethereum TCB)

```
EVM precompile address  0x0000000000000000000000000000000000000002
```

Discharge is cited universal Ethereum TCB (consensus-client
conformance: geth, reth, erigon, nethermind). Empirically backed by
`test/PinnedCodehashes.t.sol::test_sha256_precompile_{abc,empty}_kat`
which verifies the precompile against NIST CAVS KAT vectors.

## Compiler / optimiser pin

These codehashes are produced by:

```
solc 0.8.28
optimizer = true
optimizer_runs = 200
via_ir = true
evm_version = "prague"
```

The `[profile.deploy]` profile uses `optimizer_runs = 999999` which
produces different bytecode; production-pinned codehashes would be
captured under that profile (TODO when production deploys are cut).

## Re-pinning procedure

When a legitimate source change requires the bytecode to drift:

1. Run `forge test --match-test test_codehash_pinned_or_print -vv` to
   capture the new codehash(es) from the log output.
2. Update the constants in `test/PinnedCodehashes.t.sol`.
3. Update this file.
4. For each changed codehash, re-run the corresponding discharge
   artifact:
   - PQSmartWallet     → `halmos --contract HalmosValidateUserOp` and `halmos --contract HalmosExecute`
   - PQSmartWalletFactory → `certoraRun certora/confs/PQSmartWalletFactory.conf`
   - PQMultiOwnable    → `certoraRun certora/confs/PQMultiOwnable.conf`
   - SPHINCsC10Asm     → `cross_validation/` Lean ↔ Rust ↔ Solidity differential
5. Record the new discharge artifact ID (session hash / rule-set hash)
   in `AXIOM_STATUS.json`.
6. Re-run `lint_axioms.sh` and `make verify-audit` to confirm no
   regression.
