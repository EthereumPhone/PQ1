# Deployed-bytecode ↔ pinned-codehash: RESOLVED

> **UPDATE 2026-10-21 — deployed and compared; resolved again.** The freeze
> set is live at the predicted addresses on Ethereum Mainnet (blocks
> 26242705–07), Base Mainnet (52908513–15) and Base Sepolia (48422830/42/53),
> deployed from `685a3498` with `contracts/smart-wallet/deploy.sh`. On-chain
> `extcodehash`, read 2026-10-21: verifier `0xfd55ec70…2989` and factory
> `0x711dff4b…2d5b` on all three chains, equal to the table below; the
> implementation is `0x4be66f16…b2b6` on Base Mainnet (equal to the pin) and
> differs on the other chains only in Solady's cached EIP-712 domain
> separator and chain id, as expected. Wiring (`implementation`,
> `c10Verifier`, `entryPoint` v0.6) checked on all three. Transactions:
> `contracts/smart-wallet/deployments/*.json`.

> **UPDATE 2026-10-20 — reopened as "deploy pending".** The audit freeze
> changed the contracts and set `bytecode_hash = "none"`, so every pin and
> every production address moved (`PINNED_CODEHASHES.md`). The freeze set is
> **not deployed on any chain**. `DeployedBytecodeReproCheck.t.sol` (deploy
> profile, CI) now asserts the *predicted* production result instead of chain
> state:
>
> | Contract | Predicted address (Arachnid, salt 0) | Predicted runtime codehash |
> |---|---|---|
> | `SPHINCsC10Asm` | `0x7Ab9Abd09ef8A5D2ca06d9509BB295e637FA6aB4` | `0xfd55ec70…2989` |
> | `PQSmartWallet` | `0xEb64deaD5Ca0C433365EABC1AB6eBdeb28f53011` | `0x4be66f16…b2b6` (chain 8453) |
> | `PQSmartWalletFactory` | `0xE3dbA404dCeC30093DE26764965a51689C1607BD` | `0x711dff4b…2d5b` |
>
> It also asserts that the factory address and the proxy init-code hash equal
> the firmware constants (`proto/src/lib.rs`, via
> `script/generated/PqsignerDeployment.sol`), and that `factory.getAddress`
> equals the address the firmware computes. Status: **expected, deploy
> pending.** After the owner deploys the set, compare each on-chain
> `extcodehash` with this table; only then is the byte-binding a statement
> about live code again. The verifier's instruction bytes are unchanged from
> the superseded `0xdDE4D290…`; only its metadata tail moved.
>
> The rest of this file describes the 2026-06-13 resolution for the
> superseded 2026-06-12 Base Mainnet set and is kept for history. The
> `foundry.lock` lesson in §1 still applies. The Basescan note in
> `deployments/base-mainnet.json` (build without `lib/kontrol-cheatcodes`)
> does not apply to the freeze set: with `bytecode_hash = "none"`, which lib
> directories are present no longer reaches the bytecode (checked
> 2026-10-20 by building with the extra directory and a comment edit; the
> predicted addresses did not move).

**Status (historical, see the 2026-10-20 update above):** ✅ **RESOLVED 2026-06-13.** The deployed Base Mainnet **wallet,
factory, and verifier are byte-for-byte reproducible** from this repo's
pinned source + `foundry.lock`. The earlier "not reproducible / deploy-time
libs lost" finding was an **artifact of comparing builds at the wrong chain
id + address** (forge default 31337 vs Base 8453, and a local test address vs
the deployed address). Reproducing at the real address + chain id yields the
on-chain codehashes exactly. **No maintainer decision is required** — Option A
(byte-level discharge of the live contracts) is achieved.

This file documents how it was resolved so the result is auditable; the
permanent proof is `contracts/smart-wallet/test/DeployedBytecodeReproCheck.t.sol`.

---

## 1. The one thing that was actually wrong: the `foundry.lock` AA pin

`contracts/smart-wallet/foundry.lock` had pinned **account-abstraction
v0.7.0** (`7af70c8`), which **does not compile** — the code imports
`account-abstraction/legacy/v06/{IAccount06,IEntryPoint06,UserOperation06}.sol`,
a path that only exists in **v0.8.0+**. A first repair to **v0.8.0**
(`4cbc060`) compiled (`forge test` 108/108) but produced a **different**
wallet/factory codehash than the audited pins — which set off the
investigation below.

**Root cause:** the AA `legacy/v06` interfaces are **not** frozen across
releases. `UserOperation06.sol`'s git blob differs between the v0.8.0 tag
(`1479bcc…`) and the **ERC-4337 v0.9 release** commit `f54584e` (`9277fdd…`),
and that struct drives calldata decoding in `validateUserOp`, so the wallet
runtime bytecode differs between the two. PQSigner's "retarget from EntryPoint
v0.9 to v0.6" history (`074fcbb`) meant the build had always tracked the
**v0.9** AA tree (using its `legacy/v06` to target the v0.6 EntryPoint), not
the v0.8.0 tag the lock happened to name.

**Fix (committed):** `foundry.lock` now pins account-abstraction
`f54584edd4c627e084d04c315dcabda48a6b9ea9` (ERC-4337 v0.9 release). A clean
checkout compiles, `forge test` is 108/108, and the wallet/factory codehashes
match the original audited pins exactly under both profiles:

| | default (runs=200) | deploy (runs=999999) |
|---|---|---|
| wallet | `0x43c654…a06a` ✓ | `0x551c4e…34c22` ✓ |
| factory | `0xfa2922…7c3c` ✓ | `0x5feb7955…a4b9` ✓ |
| verifier | `0xf1ef4cce…fef5` ✓ | `0xeb1e3fcd…2cc5` ✓ |

solady (`90db92ce`) is **bytecode-irrelevant** here: the only solady files the
wallet/factory consume — `utils/LibClone.sol`, `accounts/ERC1271.sol`, and
their transitive `EIP712.sol` / `SignatureCheckerLib.sol` — are byte-identical
(same git blob) from 2025-12-04 through HEAD, so any solady from that window
yields the same bytecode.

## 2. The deployed contracts ARE the audited build

`test/DeployedBytecodeReproCheck.t.sol` (deploy profile) **replays the exact
production deploy** — the Arachnid deterministic CREATE2 deployer
(`0x4e59b448…`, salt = 0) on the real Base chain id (8453), under
`[profile.deploy]` (runs=999999) — and asserts the result against chain:

| Contract | On-chain (Base Mainnet) | CREATE2 replay (this repo) | Match? |
|----------|-------------------------|-----------------------------|--------|
| verifier `0xdDE4D290…` | `0xeb1e3fcd…2cc5` | `0xeb1e3fcd…2cc5` | ✅ |
| wallet impl `0x31e49D24…` | `0xdc9a082f…6994` | addr **and** `0xdc9a082f…6994` | ✅ |
| factory `0xe8CE78CD…` | `0x045bb5e4…ba9a` | addr **and** `0x045bb5e4…ba9a` | ✅ |

Both deployed **addresses** and full runtime **codehashes** reproduce. This is
the strongest possible binding: the live contracts are this source, this lib
set, this profile.

## 3. Why the first comparison looked like a mismatch (and what it proved)

The original §3 rebuilt the impl with the deployed immutables but on forge's
**default** environment, getting `0x1333ed8a` (v0.8.0) / `0x012994ef`
(f54584e) ≠ on-chain `0xdc9a082f`. A byte diff of the on-chain impl vs the
`f54584e` rebuild explains it completely:

* **Same length** (11541 B) and **identical trailing CBOR metadata** (same
  IPFS hash, same `solc 0.8.28`) ⇒ **same source + same compiler settings**.
* The **only** 54 differing bytes are three Solady EIP-712 immutable-cache
  windows:
  * 32 B = the **cached domain separator**, verified to equal
    `keccak256(EIP712Domain("PQSmartWallet","1", 8453, 0x31e49D24…))`;
  * 20 B = **`address(this)`** (`0x31e49D24…`, the deployed address);
  * 2 B = the **cached chain id** (`0x2105` = 8453 Base, vs `0x7a69` = 31337
    forge default).

The factory diff is analogous: same length (2362 B), identical metadata, and
the only 60 differing bytes are the **implementation-address immutable**
embedded 3× (`0x31e49D24…` on-chain vs the local impl address). The
verifier has no immutables and is byte-identical outright.

So the "mismatch" was entirely (deploy address, Base chain id)-derived
immutables. Reproducing at the real address + chain id (the CREATE2 replay in
§2) makes them coincide and yields the on-chain codehash. The
broadcast-recorded deploy commit `dd71578a` not existing in git
(a deploy from an uncommitted tree) is a **red herring** for reproducibility —
the identical metadata IPFS hash proves the deployed source equals the
committed source regardless.

## 4. What this means for the formal-verification claims

The Halmos `solidity*_compiles_correctly` axioms (A3.2 wallet validate,
A3.2-exec execute, A3.3 factory, A3.4 owner-table) are discharged on the
**pinned test-harness instances** (wallet `0x43c654`/`0x551c4e`, factory
`0xfa2922`/`0x5feb7955`) and transported to the deployed contracts by
`PinnedBytecodeImmutableLemma` (runtime differs only in immutable windows).

* **Verifier (A3.1 gates):** byte-identical to chain. ✅
* **Wallet / factory (A3.2 / A3.3 / A3.4):** byte-bound to the deployed
  bytecode. The lemma's "differs only in immutable windows" premise is now
  **grounded against the actual on-chain bytecode** (§3): the on-chain
  windows are exactly the EIP-712 cache (wallet) and the implementation
  address (factory), and the CREATE2 replay (§2) closes the transport by
  reproducing the on-chain codehash at the real address + chain id. ✅

The earlier conservative language ("discharged on a reproducible re-build, not
the deployed bytecode" / "logic-level only for the live wallet/factory") is
**withdrawn** — the discharge is byte-bound to the live contracts. The
standing TCB is unchanged (Lean kernel; Halmos+z3 + transcription soundness;
SHA-256 uninterpreted = A1; the verifier's ∀-signature equivalence carried by
the executable-Lean KAT + mutant screen, not a symbolic ∀ proof).

## 5. Reproduce

```bash
cd contracts/smart-wallet
# clean checkout: clone libs at foundry.lock revs (lib/ is gitignored), then:
FOUNDRY_PROFILE=deploy forge test --skip 'test/halmos/*' \
  --match-contract DeployedBytecodeReproCheck -vv          # addresses+codehashes == chain
forge test --skip 'test/halmos/*'                          # 108/108 (default profile)
make -C ../verification verify-bytecode                    # Halmos 38/38, both profiles
```

The on-chain constants in the test were captured from
`https://mainnet.base.org` via `cast code <addr> | cast keccak`
(`deployments/base-mainnet.json`).

## 6. Process follow-up (non-blocking)

The deploy ran from an uncommitted working tree (the broadcast's
`dd71578a` is not in git) and `foundry.lock` was left naming a non-compiling
AA tag. Neither affected the deployed bytecode (proven above), but to avoid a
recurrence: **commit before `forge script --broadcast`**, and treat
`DeployedBytecodeReproCheck` as the gate that the lock + source still
reproduce the chain.

See also: `PINNED_CODEHASHES.md`, `THE_CLAIM.md`, `AXIOM_STATUS.json`
(A3.2/A3.3/A3.4).
