# PQSigner Verity port — formal verification of the smart-wallet contracts

Lean 4 / [Verity](https://github.com/lfglabs-dev/verity) port of selected
Solidity contracts under `contracts/smart-wallet/src/`. The goal is to
lift the non-negotiable invariants from CLAUDE.md §"Non-Negotiable
Invariants" — specifically #6 (immutable bootstrap → same address on
every chain) and #7 (monotonic per-chain caps) — from "enforced by
Solidity `require` + Foundry unit tests" to "machine-checked Lean
theorem".

**Status**: initial skeleton (2026-05-11). Theorems are stated, proofs
are `sorry`-stubbed where they depend on Verity primitives the Step 0
spike must validate. See §1 below.

**Scope**: this port covers `PQMultiOwnable` (storage + 5 writers),
`PQSmartWalletFactory` (salt + digest), and `PQSmartWallet`
(`validateUserOp` dispatch + `executeWithOffchainCount` +
`isValidSignature`). It does **not** cover
`verifiers/SPHINCsC10Asm.sol` — that gets a separate handoff at
`docs/handoff-verity-c10-verifier.md`.

The plan that this skeleton implements:
`/home/markus/.claude/plans/ok-implement-the-smart-cached-matsumoto.md`.

---

## 1. Step 0 — bring-up spike (do this first)

The plan calls for a 3–5-day time-boxed spike before committing to the
multi-week port. Three prerequisites must be confirmed against Verity
v0.1.0's EDSL:

| ID | Prerequisite | Where it bites if missing |
|----|--------------|---------------------------|
| **P1** | ERC-7201 namespaced storage at an explicit slot literal (`Verity.Storage.Namespaced`). | `PQMultiOwnable.lean` — without this, the deployed bytecode hash differs from the existing Solidity build, breaking invariant #6. |
| **P2** | Calldata-offset arithmetic over `ByteVec` (the SignatureWrapper `abi.decode((uint256, bytes))` shape). | `PQSmartWallet.lean` `decodeSignatureWrapper`. |
| **P3** | External `call` (`Verity.External.Call.extCall`) with a frame-separation axiom — `extCall` cannot read/write our ERC-7201 namespace. | `PQSmartWallet.lean` `executeWithOffchainCount`. **Most likely show-stopper.** |

Run:

```bash
cd contracts/verity
lake update                  # fetches Verity v0.1.0 from upstream
lake build                   # ~20 min first build
```

Then for each prerequisite, the failure mode is:

- **P1 fails** → `import Verity.Storage.Namespaced` errors. Raise an
  upstream issue. Pause the port.
- **P2 fails** → `decodeSignatureWrapper` errors out. Implement as an
  EDSL extension in a fork of Verity. ~80-line proof obligation.
- **P3 fails** → `External.extCall` errors. **Execute the hybrid
  pivot**: drop `executeWithOffchainCount` and theorems #10/#11/#12
  from this port, ship Verity-verified storage + factory only. The
  remaining theorems (#1–#9, #13) still cover invariants #6 and #7 in
  full.

---

## 2. Layout

```
contracts/verity/
├── README.md                 (this file)
├── TRUST_ASSUMPTIONS.md      what is verified vs. what is trusted
├── lakefile.lean             Lake build config (pinned to Verity v0.1.0)
├── lean-toolchain            Lean 4.22.0
├── Makefile                  lake build + differential helpers
└── PQSigner/
    ├── Common.lean           protocol constants + shared types
    ├── PQMultiOwnable.lean   storage struct + 5 writers
    ├── PQSmartWalletFactory.lean   salt + digest + createAccount
    ├── PQSmartWallet.lean    dispatch + execute + EIP-1271
    └── Theorems.lean         13 invariant theorems (proofs)
```

The Lean source files are kept **flat and small** — each contract is
one file, theorems are aggregated in `Theorems.lean`. This matches
Verity's own convention (cf. the 11 verified contracts in
`lfglabs-dev/verity`).

---

## 3. The 13 theorems

Numbered to match the plan. Status reflects what's stated vs. proved
in this initial skeleton (proofs will close incrementally as Step 0
prerequisites land).

| # | Theorem | File | Status |
|---|---------|------|--------|
| 1 | `bumpBootstrapUses_monotonic_capped` | `Theorems.lean` | sorry — provable now |
| 2 | `bumpSlotUses_monotonic_capped` | `Theorems.lean` | sorry — provable now |
| 3 | `setOffchainSigCount_monotonic_combined_cap` | `Theorems.lean` | sorry — provable now |
| 4 | `removeOwnerAtIndex_zero_reverts` | `Theorems.lean` | **proved (by `rfl`)** |
| 5 | `ownerAtIndex_zero_immutable` | `Theorems.lean` | sorry — needs trace induction |
| 6 | `nMask_enforced` | `Theorems.lean` | sorry — provable now |
| 7 | `salt_chain_independent` + strong form | `Theorems.lean` | **proved (by `rfl`/`rw`)** |
| 8 | `createAccount_idempotent` | `Theorems.lean` | **proved (by `rfl`)** |
| 9 | `addSlot0Digest_binds_chain_id` | `Theorems.lean` | sorry — needs SHA-256 axiom |
| 10 | `validateUserOp_dispatch_bootstrap` | `Theorems.lean` | sorry — gated on P2/P3 |
| 11 | `validateUserOp_dispatch_slot` | `Theorems.lean` | sorry — gated on P2/P3 |
| 12 | `eip1271_rejects_bootstrap` | `Theorems.lean` | sorry — gated on P2 |
| 13 | `combined_cap_preserved` (global inductive invariant) | `Theorems.lean` | sorry — uses #2, #3 |

Run `make verify-stats` to regenerate this table from the source.

---

## 4. Differential testing

The Verity build emits Yul that gets fed to `solc 0.8.33`. The
resulting bytecode is **not** byte-identical to the existing Solidity
build — Verity's storage-access patterns differ. The differential
harness at `contracts/smart-wallet/test/Differential.t.sol` (added in
the same PR as this port) parameterises every existing test over
`(implementation, factory)` and runs it twice. We compare:

- Return data byte-equal.
- Event topics + data byte-equal (event signatures must be selector-stable).
- ERC-7201 storage slot diff via `vm.load` at the named base, post-call.
- Revert reasons (string or 4-byte selector) byte-equal.

We **do not** gate on gas — Verity's Yul has different access patterns
and gas will legitimately diverge. The load-bearing claim across the
two builds is that `_salt(masterPkSeed, masterPkRoot)` produces the
**same bytes** in both, not that the resulting CREATE2 address is the
same (the deployed-bytecode hashes will differ, so the factories
deploy at different addresses with different `INIT_CODE_HASH`).

---

## 5. Single-source-of-truth: `proto/`

Protocol constants (cap values, signature lengths, owner bytes
length, domain tags) live in `proto/src/lib.rs` and are propagated
to other languages by the `xtask` tool:

```bash
# Existing — generates contracts/smart-wallet/src/generated/PqsignerProto.sol
cargo run -p pqsigner-xtask -- gen-solidity-constants

# TODO (Step 0 follow-up) — generate contracts/verity/PQSigner/Common.lean header
cargo run -p pqsigner-xtask -- gen-lean-constants
```

The Lean side currently has the constants inlined in `Common.lean`.
Add the `gen-lean-constants` subcommand to `xtask/` before the
differential harness lands so future cap changes propagate to both
sides automatically.

---

## 6. Build commands

```bash
cd contracts/verity

# First-time setup (or after toolchain bump):
curl https://raw.githubusercontent.com/leanprover/elan/master/elan-init.sh -sSf | sh
source ~/.elan/env
lake update

# Build + verify all theorems:
lake build                        # ~20 min first build, ~10s incremental

# Stats (matches Verity's own VERIFICATION_STATUS.md format):
make verify-stats

# Compile + emit Yul (for differential testing):
make emit-yul

# Differential test against the existing Solidity build:
cd ../smart-wallet && forge test --match-contract Differential -vv
```

---

## 7. What this port does NOT prove

See `TRUST_ASSUMPTIONS.md` for the full list. The highlights:

1. **SPHINCS+C10 verifier correctness** — `SPHINCsC10Asm.sol` is
   modelled as an opaque oracle. See `docs/handoff-verity-c10-verifier.md`
   for the multi-quarter plan to lift this.
2. **`solc 0.8.33` Yul → bytecode correctness** — pinned but trusted
   (Verity's own README acknowledges this; we inherit the trust).
3. **Firmware-side wire format** — the SHA-256 preimage built by
   `cmd_sign_userop.rs` is *input* to our spec (`sphincsDigest`),
   not verified by it. A firmware bug that builds the wrong preimage
   produces sigs that the on-chain verifier rejects — fail-safe, but
   not fail-soft.
4. **Side-channel resistance** — Lean proves *functional* equivalence,
   not constant-time. Side-channel mitigations live in the firmware
   (`secure/src/fi.rs`, `hw/consumption_mask.rs`, `tamp.rs`).

---

## 8. Why this matters

Without the Verity port, the only thing preventing a future regression
that adds `chainId` to the salt preimage — silently breaking the
"same 24 words → same address on every chain" promise — is a careful
code reviewer. After Step 0 lands and the port stabilises, the same
regression fails `lake build` and never merges.

The same logic applies to:
- accidental cap reset paths,
- accidental EIP-1271 acceptance of `ownerIndex == 0`,
- dispatch role-split regressions where Type 2 traffic bumps
  `bootstrapUses`.

These are not hypothetical — the early versions of MultiOwnable
(pre-Coinbase port) had a draft where the dispatch role split was
loose; the only thing that caught it was a careful PR review.
Machine-checked theorems convert "careful review" into "compiler
error".
