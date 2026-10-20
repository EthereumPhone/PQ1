# Pinned bytecode codehashes

> ## UPDATE 2026-10-20 — audit-freeze re-pin; nothing below is deployed yet
>
> The contracts were changed for the Trail of Bits audit freeze: owner removal
> deleted (#131, #213), legacy EIP-1271 `isValidSignature(bytes,bytes)` added
> (#995), Solady's raw-hash 1271 workflows dropped (#691), ERC-721/1155
> receiver hooks and ERC-165 added. The build also moved to
> `bytecode_hash = "none"`, so the **verifier pin moved too** although its
> source and instruction bytes are unchanged (only the CBOR metadata tail
> changed). From now on, comments, source paths and stray lib directories no
> longer move any pin.
>
> **What this does to the 2026-06-13 banner below:** the pins are now the
> freeze-set values in § "Pinned values", and the Base Mainnet contracts
> (`0xdDE4…` / `0x31e49D24…` / `0xe8CE78CD…`) are a **superseded** deployment
> that no pin, proof or firmware constant refers to any more. The freeze set is
> **not deployed on any chain yet**, so every byte-binding statement is
> "expected, deploy pending": the CREATE2 replay in
> `DeployedBytecodeReproCheck.t.sol` (deploy profile, chain 8453) now asserts
> the *predicted* addresses and codehashes, and ties them to the firmware's
> CREATE2 constants. It becomes a statement about live code only once the
> owner deploys the set and the on-chain codehashes are compared.
>
> Discharge on the new bytecode: Halmos 43/43 rules on both profiles
> (`halmos/sessions/halmos-session-2026-10-20.txt`) and Kontrol 31/31 proofs
> (`kontrol/sessions/kontrol-session-2026-10-20.txt`).

> ## ✅ Build-reproducibility repaired — deployed bytecode byte-bound (2026-06-13; historical since 2026-10-20, see above)
>
> `contracts/smart-wallet/foundry.lock` had pinned account-abstraction v0.7.0
> (`7af70c8`), which **did not compile** — the code imports
> `account-abstraction/legacy/v06/*`, a layout that only exists in v0.8.0+.
> The **deploy-time lib was recovered**: the lock now pins AA
> **`f54584e`** (the **ERC-4337 v0.9 release**), whose `contracts/legacy/v06/`
> differs from the v0.8.0 tag (`UserOperation06` blob `9277fdd` vs `1479bcc`)
> and drives `validateUserOp` calldata decoding. PQSigner's build had always
> tracked the v0.9 AA tree (the v0.9→v0.6 EntryPoint retarget, `074fcbb`);
> the lock had merely mis-named the tag. solady (`90db92ce`) is
> **bytecode-irrelevant** — its consumed files (LibClone/ERC1271/EIP712/
> SignatureCheckerLib) are byte-identical 2025-12-04→HEAD.
>
> With this lib the **original audited pins are reproduced exactly** under both
> profiles (wallet `0x43c654`/`0x551c4e`, factory `0xfa2922`/`0x5feb7955`,
> verifier `0xf1ef…`/`0xeb1e3fcd`) — so the pins below are the **original**
> values, not a re-pin — and the **full Halmos A3.2/A3.3/A3.4 discharge passes
> against them** (`make -C contracts/verification verify-bytecode`, 38/38 on
> both profiles).
>
> **The deployed Base Mainnet contracts ARE byte-reproducible.** A CREATE2
> replay of the production deploy (Arachnid `0x4e59…`, salt 0, chain id 8453,
> deploy profile) reproduces the live verifier `0xdDE4…`, wallet impl
> `0x31e49D24…`, and factory `0xe8CE78CD…` — both **addresses and full runtime
> codehashes** (`0xeb1e3fcd…`, `0xdc9a082f…`, `0x045bb5…`) — see
> `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol`
> (`FOUNDRY_PROFILE=deploy`). The Halmos discharges (pinned harness instances)
> transport to the live bytecode via `PinnedBytecodeImmutableLemma`; the only
> deployed-vs-rebuild deltas are the verified immutable windows (wallet:
> EIP-712 domain separator + `address(this)` + chainId 8453; factory:
> implementation address ×3), and identical metadata IPFS hashes prove same
> source + settings. The earlier "NOT byte-reproducible / lost libs / maintainer
> decision pending" note is **withdrawn** — it was an artifact of comparing at
> forge chainId 31337 vs Base 8453. See
> [`DEPLOYED_BYTECODE_PIN_CAVEAT.md`](DEPLOYED_BYTECODE_PIN_CAVEAT.md).

Each `solidity*_compiles_correctly` axiom in `Bridge/Refinement.lean`
is bound to a specific runtime codehash. When that codehash changes,
the corresponding discharge artifact (Halmos session, Certora
rule-set, or differential test) must be re-run before the pin is
updated.

This file is the canonical pinning record. It is parity-tested at CI
by `contracts/smart-wallet/test/PinnedCodehashes.t.sol`, which
asserts that the deployed `address(<contract>).codehash` equals the
pinned value below. Any drift fails CI.

## Pinned values (re-pinned 2026-10-20, audit freeze)

**default profile (`runs=200`)** — the build the test suite and the symbolic
suite run against by default:

```
PQSmartWallet         0xcebbd91dc5a2cd5869eacc84e2bd82dbd8702c504788017df78a2e1960119a0b
PQSmartWalletFactory  0x318afcbf264cd2f0fa0cc25efa1c26d9ad1799f916a2182ec9a320d4a94e8b46
SPHINCsC10Asm         0x8fa670d53df0fd63bc64505463f268256ffbb51e57f62d8a5a41f5bcec5cf2eb
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

**deploy profile (`runs=999999`)** — the production build:

```
PQSmartWallet         0x1bbd83ba0479a352197328f581b3ee473643996b04e07355ae8e3ebc49d91bea
PQSmartWalletFactory  0x44c3b4f70f5dc5406275cce87be814eda909ab0acab4aacdb9dc3ef24f0f7b21
SPHINCsC10Asm         0xfd55ec708737970f93a73cec1ce67de95391da4b673e24fa2516f9822bf92989
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

These are the harness-instance codehashes (test EntryPoint / mock-verifier
immutables). The production instances, deployed through the Arachnid CREATE2
deployer with salt 0, are predicted and asserted by
`DeployedBytecodeReproCheck.t.sol` (deploy profile, chain 8453):

| Contract | Predicted address | Predicted runtime codehash |
|---|---|---|
| `SPHINCsC10Asm` | `0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4` | `0xfd55ec708737970f93a73cec1ce67de95391da4b673e24fa2516f9822bf92989` (no immutables, so equal to the deploy pin) |
| `PQSmartWallet` | `0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011` | `0x4be66f1681776863f405c0bf6d5f412ffe7248873db7aa3ad6b38664f258b2b6` (chain 8453; the EIP-712 cache embeds the chain id) |
| `PQSmartWalletFactory` | `0xE3dbA404dCeC30093DE26764965a51689C1607BD` | `0x711dff4be17b368d25e5a24c35d12102f18209cd485392863f009e8a72712d5b` |

The factory address and the proxy init-code hash
(`0x17ca674095afe9dc82aa6f396ee01bd837449a127b6be59a0d947329f29b2570`) are the
firmware constants `PQ_SMART_WALLET_FACTORY` / `PROXY_INIT_CODE_HASH`
(`proto/src/lib.rs`, mirrored into
`contracts/smart-wallet/script/generated/PqsignerDeployment.sol`). CI runs the
deploy-profile pin tests, so a source or toolchain change that would move a
user's wallet address fails CI.

### History

| Date | default wallet / factory / verifier | deploy wallet / factory / verifier | Why |
|---|---|---|---|
| 2026-10-20 | `0xcebbd9…9a0b` / `0x318afc…8b46` / `0x8fa670…f2eb` | `0x1bbd83…1bea` / `0x44c3b4…7b21` / `0xfd55ec…2989` | audit freeze (above) |
| 2026-06-10 | `0x43c654…a06a` / `0xfa2922…7c3c` / `0xf1ef4c…fef5` | `0x551c4e…4c22` / `0x5feb79…a4b9` / `0xeb1e3f…2cc5` | bootstrap cap counted in validation; deployed to Base Mainnet 2026-06-12, now superseded |

The 2026-06-10 notes below are kept for history.

## Pinned values as of 2026-06-10 (historical)

> **Re-pinned 2026-06-10** after the bootstrap few-time-cap fix:
> `PQSmartWallet._validateSignature` now bumps `bootstrapUses` in the
> VALIDATION phase (mirroring the slot path) instead of the deferred,
> credit-gated bump in `addOwnerBytes`. Every accepted Type-1 signature is
> therefore counted revert-proof under ERC-4337 v0.6, closing the
> `PQBootstrapCapEvasion` under-count (CLAUDE.md invariant #7). The Lean
> model (`Wallet/ValidateUserOp.lean::bumpForOwner`) already encoded this
> behaviour, so the model-level proof is faithful; only the deployed
> bytecode moved. The verifier `SPHINCsC10Asm` hash is the 2026-05-31
> fcee705a FORS-htIdx value (unchanged by this edit); the factory moved
> only because it imports the edited wallet into its compilation unit.
>
> **Discharge status (updated 2026-06-10, strengthened).** The A3.*
> bytecode discharges are **run** with a patched Halmos (`halmos/` — see its
> README; stock 0.3.x has a SHA-256 precompile sort bug, fixed by a one-line
> uninterpreted-function-sort patch). The full symbolic suite PASSES over all
> inputs against these exact codehashes, certified in the same flow by
> `PinnedCodehashes.t.sol`, on BOTH profiles:
>   * **A3.2 (wallet validate)** — `discharged-bytecode`: pointwise
>     equivalence to the Lean model (`HalmosValidateUserOpEquiv`) + 8
>     per-property rules (`HalmosValidateUserOp`) on `0x43c654…a06a`, incl.
>     non-bypass (I-1 analogue) and the validation-phase cap bump.
>   * **A3.2-exec (wallet execute)** — `discharged-bytecode`: pointwise
>     equivalence of `executeWithOffchainCount` /
>     `executeBatchWithOffchainCount` to the Lean `Execute` model over a
>     **symbolic ownerIndex** (`HalmosExecuteEquiv`, 6 rules) + the 6
>     per-property rules (`HalmosExecute`). The emitted external CALL's
>     delivery is A4, not A3.2 (see the harness header).
>   * **A3.3 (factory)** — `discharged-bytecode`: 5 rules (createAccount ⟺
>     precondition iff + postconditions, already-deployed early-return, 3
>     install-gate rejects) on `0xfa2922…7c3c`.
>   * **A3.4 (owner table)** — `discharged-bytecode`: `HalmosMultiOwnable`
>     (7 rules) — `addOwnerBytes`/`removeOwnerAtIndex`/`initialize` pointwise
>     vs the Lean `Storage` model + `ownerAtIndex` read parity, on the
>     current embedding wallet codehash. (Replaces the prior stale Certora
>     artifact, which had not been re-run after the codehash moved.)
>   * **A3.1 (verifier)** — `discharged-bytecode-partial`: 3 input-gate rules
>     (length/N-mask) on `0xf1ef…fef5` by Halmos; an executable
>     Lean↔FIPS↔bytecode differential on digest, htIdx AND the full
>     functional verify (`lake exe verify-test-vectors`, each 10/10, all
>     HARD CHECKS since 2026-06-12); bytecode-side 10-vector KAT +
>     ~250-mutant screen. The Lean refinement (`verifyRefined_eq_spec`,
>     `rfl`) now sits over an executably-faithful spec; the remaining
>     residual is the ∀-signature symbolic equivalence (GAP-2) — see the
>     postmortem in `docs/A3_1_VERIFIER_GAP.md`.
> Reproduce: `make -C contracts/verification verify-bytecode`. SHA-256 is an
> uninterpreted function in every Halmos run (the named A1 boundary).

**default profile (`runs=200`)** — the dev/test build the symbolic suite runs against (the **original audited pins**, reproduced byte-for-byte by the recovered `foundry.lock` build — AA `f54584e` + solady `90db92ce`):

```
PQSmartWallet         0x43c65420691792d7f0f63dab95f47ab7adb649df4c83f432bd3cf2c95db3a06a
PQSmartWalletFactory  0xfa2922b4fadb81b4475307504890d68f2e3d9be97c7e5e9aeeba6e84110d7c3c
SPHINCsC10Asm         0xf1ef4ccee22e6b39446723232fe39761f089c7195941b2c12576956b38fcfef5
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

**deploy profile (`runs=999999`)** — the production build (the **original audited pins**, reproduced by the recovered lib; the deployed Base Mainnet impl/factory/verifier are reproduced ADDRESS **and** codehash by `DeployedBytecodeReproCheck.t.sol`):

```
PQSmartWallet         0x551c4e03bbd433a5929828ab19caac13a94ca9e2be6074cf3e18c7d926034c22
PQSmartWalletFactory  0x5feb7955252e54bcbbf44062295bdeb45f3dea13c4ef7fb1ba579196d84da4b9
SPHINCsC10Asm         0xeb1e3fcd38c7cd5f7b08352c298b34bd114d83f7dbd755b122c41eda2aab2cc5
PQMultiOwnable        (embedded in PQSmartWallet; no independent deploy)
```

Both profile sets live in `contracts/smart-wallet/test/PinnedCodehashSelector.sol`
(picked by `$FOUNDRY_PROFILE`) and are certified by `PinnedCodehashes.t.sol`
under each profile. **The symbolic suite is executed against BOTH profiles'
bytecode** (`run_halmos.sh` runs `default` then `deploy`, with no authoritative
skip mode) — so the production `runs=999999` bytecode is symbolically
discharged directly, not by a "control flow is identical across profiles"
argument.

Within a single profile, an **immutable-window lemma**
(`PinnedBytecodeImmutableLemma.t.sol`) additionally proves, exhaustively over
every byte, that each contract's runtime differs from its pinned instance
**only inside 32-byte windows holding the two constructor immutables**
(`_entryPoint`/`implementation` and `c10Verifier`, plus the wallet's Solady
EIP-712 `_cachedThis`/`_cachedDomainSeparator`). So a symbolic rule proved
against one instance transports to every OTHER instance of that same compiled
artifact — e.g. the harness's mock-verifier/test-EntryPoint instance to a real
deployment with the production verifier + EntryPoint addresses — modulo those
certified-located immutables. (This lemma is an intra-profile instance bridge;
the cross-profile coverage comes from actually running both profiles, above.)

## External dependency — EntryPoint v0.6 codehash (`T-EP-NONCE` receipt)

The wallet's same-nonce Type-2 replay protection is cited-TCB on the deployed
EntryPoint v0.6 `NonceManager` (see `THREAT_CLAIM_MAP.md` `S-USEROP-REPLAY` [^10]).
Unlike the project contracts above (reproduced from source), the EntryPoint is an
EXTERNAL canonical singleton; its receipt is the deployed `extcodehash`, pinned and
**cross-chain-verified 2026-07-17**:

```
EntryPoint v0.6  address   0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789
                 codehash  0xc93c806e738300b5357ecdc2e971d6438d34d8e4e17b99b758b1f9cac91c8e70
```

`keccak256(eth_getCode(0x5FF1…789))` is IDENTICAL on Ethereum (1), Base (8453),
Optimism (10), and Arbitrum (42161) — the same 23,690-byte singleton — so the pin
binds the cited-TCB assumption to one specific verified deployment (a substitution
or wrong-version EntryPoint at that address is caught). Provenance:
`cast code 0x5FF1…789 --rpc-url <chain> | cast keccak`. Fork-gated tripwire:
`contracts/smart-wallet/test/EntryPointCodehashReceipt.t.sol` — set
`ENTRYPOINT_RPC_URL` to re-verify against a live node; self-skips (no false green)
when unset, so the pinned constant is the durable receipt. This pins the DEPLOYMENT;
it does not discharge NonceManager correctness (that stays cited-TCB / defeater D2).

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
bytecode_hash = "none"      # since 2026-10-20
```

The `[profile.deploy]` profile uses `optimizer_runs = 999999`, which
produces different bytecode; those production codehashes are the
**deploy profile** block above. `make verify-bytecode` certifies both
profiles and runs the full symbolic suite on both (UPDATE 2026-10-20: the
older `PQ1_HALMOS_BOTH_PROFILES=1` switch this paragraph used to describe no
longer exists; both profiles always run). Build with Foundry v1.8.3, the CI
pin, and the exact `foundry.lock` lib set.

## Re-pinning procedure

UPDATE 2026-10-20: rewritten. The old procedure named the wrong file and
skipped the deploy profile and the firmware constants.

When a legitimate source change moves the bytecode:

1. Capture both profiles:
   `forge test --match-test test_codehash_pinned_or_print -vv` and the same
   under `FOUNDRY_PROFILE=deploy`. Put the values in
   `contracts/smart-wallet/test/PinnedCodehashSelector.sol` (both pin sets
   live there) and update the history comment in `PinnedCodehashes.t.sol`.
2. If the deploy profile moved, the production addresses moved:
   - run `FOUNDRY_PROFILE=deploy forge script script/PrintProductionAddresses.s.sol`;
   - put the new factory address and proxy init-code hash into
     `proto/src/lib.rs` and its pins (`proto/tests/negative_frozen_constants.rs`,
     `secure/src/nsc_small_cmds_pure_tests.rs`);
   - regenerate `script/generated/PqsignerDeployment.sol` with
     `cargo run -p pqsigner-xtask -- gen-solidity-constants`;
   - update the expected addresses and codehashes in
     `test/DeployedBytecodeReproCheck.t.sol`;
   - follow the receipt cascades an edit to `proto/` triggers (ERC-7730
     curation manifest, extraction freshness).
   A deploy-profile move changes every user's wallet address. Before launch
   that is a re-flash; after launch it is a migration.
3. Update this file.
4. Re-run the discharges on the new bytecode:
   - `make -C contracts/verification verify-bytecode` (Halmos, both
     profiles; archive the log under `halmos/sessions/`);
   - `make -C contracts/verification verify-kontrol` (archive under
     `kontrol/sessions/`).
   Per contract:
   - PQSmartWallet → `HalmosValidateUserOpEquiv`, `HalmosValidateUserOp`,
     `HalmosExecuteEquiv`, `HalmosExecute`, `HalmosMultiOwnable`,
     `HalmosIsValidSignature`, and the wallet Kontrol proofs;
   - PQSmartWalletFactory → `HalmosFactory`, `KontrolFactory`;
   - SPHINCsC10Asm → `HalmosVerifier`, the `cross_validation/`
     Lean ↔ Rust ↔ Solidity differential, `SPHINCsC10AsmAdversarial`.
5. Record the new codehashes and receipts in `AXIOM_STATUS.json`, then
   re-pin the ledger digests (`scripts/check_ledger_consistency.py`).
6. Run `make -C contracts/verification verify-audit verify-ledger-consistency`.
