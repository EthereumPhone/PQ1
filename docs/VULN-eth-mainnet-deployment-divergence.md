# VULN — Ethereum Mainnet carries an orphaned, stale, unpinned deployment

**Found:** 2026-08-03 · **Severity:** HIGH (funds-unavailable + off-perimeter bytecode)
**Status:** ROOT CAUSE FIXED 2026-10-20; deployment pending · **Surface:** contracts / deploy operations / firmware constants

> **UPDATE 2026-10-20 (Trail of Bits audit freeze).**
> - **Root cause fixed.** `contracts/smart-wallet/script/ProductionDeploy.sol`
>   (used by every `Deploy*.s.sol`) refuses to broadcast unless the predicted
>   factory address and proxy init-code hash equal the firmware constants,
>   which xtask renders from `proto/src/lib.rs` into
>   `script/generated/PqsignerDeployment.sol` (`make check-solidity-constants`
>   fails on drift). After deploying it checks that each contract landed at its
>   predicted address with code. CI runs `DeployedBytecodeReproCheck` under the
>   deploy profile, which ties the production build to the same constants.
> - **Firmware constants moved to the audit-freeze set** (factory
>   `0xE3dbA404dCeC30093DE26764965a51689C1607BD`), which is **not deployed on
>   any chain yet**, Base included. Until the owner deploys it, impact 1 below
>   applies on every chain; it is a pre-launch state, with no devices shipped.
>   Deploying the freeze set on Ethereum Mainnet (and the other target chains)
>   after the audit is tracked as a follow-up issue.
> - **Recommended fix 1** is done in the generalised form above. **Fix 2** is
>   superseded by the freeze set. **Fix 3** is done:
>   `contracts/smart-wallet/deployments/eth-mainnet.json` records the orphaned
>   2026-05-13 set as `DO NOT USE`, with on-chain codehashes. **Fix 4** is
>   done: `docs/companion/companion-app-integration.md` lists the freeze set as
>   not deployed and the chain table no longer implies support. **Fix 5**:
>   `deployments/base-sepolia.json` now records both Base Sepolia sets as
>   superseded.
> - The orphaned contracts stay on chain. No firmware has ever targeted their
>   factory.
> - The sections below describe the state found on 2026-08-03 (factory
>   constant, line numbers and test behaviour as of then).

## Summary

There is a **live, undocumented PQSigner deployment on Ethereum Mainnet (chain 1)**
that does not match the firmware-baked constants and is not covered by any pin,
audit, or FV artifact. Simultaneously, the factory address the firmware *does* bake
in has **no code on Ethereum Mainnet**.

Verified on-chain 2026-08-03 (`cast`, `https://ethereum-rpc.publicnode.com` /
`https://base-rpc.publicnode.com`):

| Contract | Base Mainnet (8453) | Ethereum Mainnet (1) |
|---|---|---|
| Verifier `SPHINCsC10Asm` | `0xdDE4D290…89cbB` | `0xb32e32a5…81fc7` |
| Impl `PQSmartWallet` | `0x31e49D24…83590` | `0xe178d7a4…d501d1` |
| Factory `PQSmartWalletFactory` | `0xe8CE78CD…0d452` | `0x62b73434…03db8b` |
| Verifier runtime codehash | `0xeb1e3fcd…2cc5` (**pinned**) | `0x92913b0b…0b75b` (**unpinned**) |

* `cast code 0xe8CE78CD…0d452 --rpc-url <eth mainnet>` → `0x` (**empty**).
* `cast codehash 0x62b73434…03db8b --rpc-url <eth mainnet>` → 4941 bytes of live code.

Evidence of provenance: `contracts/smart-wallet/broadcast/DeployImplAndFactoryEthMainnet.s.sol/1/run-latest.json`
— three CREATE2 txs through the Arachnid deployer, all `status 0x1`, blocks
25086009–25086011, timestamp `1778672847` = **2026-05-13**, source commit `6484370`
(no longer resolvable — history was rewritten 2026-07-22).

## Why the addresses diverged

The three `Deploy*` scripts all use `salt = bytes32(0)` through Arachnid
`0x4e59…4956C`, so the addresses are chain-independent *for a fixed initcode*.
They are not identical here because the deployments were made from **different
source trees**:

| Deploy | Date | verifier initcode | impl initcode | factory initcode |
|---|---|---|---|---|
| Base Sepolia | 2026-04-29 | 1828 B | 12480 B | 2774 B |
| **Eth Mainnet** | **2026-05-13** | **1828 B** | **12480 B** | **2774 B** |
| Base Mainnet | 2026-06-12 | 1989 B | 13108 B | 2667 B |

Ethereum Mainnet was deployed from the **same pre-fix era as the Base Sepolia
deployment that `deployments/base-sepolia.json` already documents as stale**, and
predates the `bootstrapUses` cap-evasion fix (landed in-tree 2026-06-10, redeployed
to Base Mainnet 2026-06-12 — see `PQBootstrapCapEvasion.t.sol`).

## Impact

**1. Firmware/companion address prediction is wrong on chain 1 (availability / stuck funds).**
`PQ_SMART_WALLET_FACTORY` (`proto/src/lib.rs:1245`) is `0xe8CE78CD…0d452`,
Base-Mainnet-only. The firmware is chain-independent by design (invariant #6) and
applies it to *every* chain — `aa/src/eip1271.rs:85`, `aa/src/eip6492.rs:180`,
`cmd_get_wallet_address`, `cmd_get_init_code`. There is **no chain-id allowlist
anywhere in the NSC dispatch**. Consequences on Ethereum Mainnet:

* `CMD_GET_WALLET_ADDRESS` returns an address that no deployed factory can ever
  reach. ETH/ERC-20 sent there is inaccessible until someone CREATE2-deploys the
  *exact* Base-Mainnet factory initcode on mainnet (permissionless, and
  reproducible per `DeployedBytecodeReproCheck.t.sol` — so **recoverable, not
  destroyed**, but only while that initcode is preserved).
* `CMD_GET_INIT_CODE` / Type-1 UserOps emit `initCode` whose first 20 bytes are a
  codeless address → `AA13 initCode failed`.
* Counterfactual EIP-6492 blobs (`account_deployed = 0`) name the same codeless
  factory → the deploy-then-verify `eth_call` fails → `isValidSignature` invalid.

**2. If the live mainnet set is used instead, it is outside the security perimeter.**
The impl at `0xe178d7a4…` predates the 2026-06-10 fix, so it carries the
**bootstrap cap-evasion bug** (`bootstrapUses` bumped in `addOwnerBytes` gated on
`_addOwner` succeeding; v0.6 `innerHandleOp` swallows the revert, so a
duplicate-owner add lets accepted Type-1 sigs count zero → the master C10 key can
be driven past its 65,536 few-time budget, invariant #7). The verifier at
`0xb32e32a5…` has codehash `0x92913b0b…`, which appears in **no** pin file — not
`PINNED_CODEHASHES.md`, not `TRUST_ASSUMPTIONS.md`, not `AXIOM_STATUS.json`. Every
Halmos/Lean/Kontrol claim is byte-bound to Base Mainnet only.

**3. Documentation actively points users at the broken configuration.**
`docs/companion/companion-app-integration.md:1215` heads the address table
"**deterministic CREATE2 — same on every chain**" and its Chain-IDs table lists
`Ethereum | 1` as supported. `deployments/` has `base-mainnet.json` and
`base-sepolia.json` but **no `eth-mainnet.json`** — the mainnet deployment is
recorded nowhere except the untracked broadcast artifact.

## Root cause

No deploy-time assertion binds a broadcast to the firmware constant. Every
`Deploy*.s.sol` deploys and prints; none of them checks the result. The
`PrintProductionAddresses.s.sol` header even spells out the hazard ("stale firmware
constants make the device predict an address the factory will never deploy to")
but nothing enforces it.

## Recommended fixes

1. **Cheap, permanent, do first** — add to every `Deploy*.s.sol`, after the
   broadcast:
   ```solidity
   require(address(factory) == 0xe8CE78CD976497447FF8B76c71b59aE42Af0d452,
           "factory != PQ_SMART_WALLET_FACTORY (firmware constant drift)");
   ```
   plus the impl/verifier equivalents. Any future profile/lib/source drift then
   fails loudly *before* the tx is signed under `--slow`.
2. Redeploy Ethereum Mainnet from the current pinned tree under
   `FOUNDRY_PROFILE=deploy` (must land `0xdDE4D290…` / `0x31e49D24…` /
   `0xe8CE78CD…`). Note the `--slow` gotcha: the deployer EOA `0x3a4e6e…798c` is
   EIP-7702-delegated.
3. Add `deployments/eth-mainnet.json` recording **both** sets, with the
   `0x62b73434…` set explicitly marked `DO NOT USE — pre-2026-06-10 bootstrap cap
   evasion, verifier outside the pinned codehash set`. The stale contracts cannot
   be removed from chain; only documented.
4. Fix `companion-app-integration.md:1215` — the addresses are "same on every
   chain *where deployed from the pinned tree*"; list actual per-chain status.
5. Re-verify Base Sepolia at the same time (already known stale).

## Not a fix

Adding a firmware-side chain allowlist would be tempting but conflicts with
invariant #6/#8 (chain-independent bootstrap key, stateless slot selection) and
would need a firmware update for every new chain. The correct enforcement point is
the deploy script plus per-chain deployment records.
