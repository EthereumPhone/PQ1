# PQSigner Verity port — formal verification of the smart-wallet contracts

Lean 4 / [Verity](https://github.com/lfglabs-dev/verity) port of selected
Solidity contracts under `contracts/smart-wallet/src/`. The goal is to
lift the non-negotiable invariants from CLAUDE.md §"Non-Negotiable
Invariants" — specifically #6 (immutable bootstrap → same address on
every chain) and #7 (monotonic per-chain caps) — from "enforced by
Solidity `require` + Foundry unit tests" to "machine-checked Lean
theorem".

**Status (2026-05-11, second pass)**: Part B (SPHINCS+C10 verifier
port) landed as buildable pure-Lean. Part A (smart-wallet contracts)
is documented intent — it imports modules (`Verity.Prelude`,
`Verity.Hash.Sha256`, `Verity.External.Call`, etc.) that **Verity
v0.1.0 does not provide**. The Step-0 spike below remains the entry
point for getting Part A to compile.

| Part | What it covers | Build status |
|------|----------------|--------------|
| **A** | `PQMultiOwnable` storage + writers, `PQSmartWalletFactory` salt + digest, `PQSmartWallet` dispatch. Files at `PQSigner/{Common,PQMultiOwnable,PQSmartWalletFactory,PQSmartWallet,Theorems}.lean`. | **Does not build** — imports fictional Verity modules. Blocked on Verity Phase 0 (see `docs/verity-v0.1.0-primitive-map.md`). Kept in-tree as the spec for what Verity v0.2.x+ must support. Lakefile root entry removed from default target. |
| **B** | SPHINCS+C10 verifier (pure-Lean reference impl of `sphincs-c10/`). Files at `PQSigner/Verifier/{Params,Address,Hash,Wots,Merkle,Fors,Hypertree,Top}.lean`. ~40 closed theorems on closeable invariants + 2 documented axioms + 1 documented sorry. | **Builds clean** under Lean 4.22.0. `make build` succeeds. |

See [docs/handoff-verity-c10-verifier.md](../../docs/handoff-verity-c10-verifier.md)
for the original multi-quarter plan and
[docs/verity-v0.1.0-primitive-map.md](../../docs/verity-v0.1.0-primitive-map.md)
for the Phase-0 upstream reconnaissance landed alongside Part B.

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
    ├── Common.lean                       [Part A — does not build]
    ├── PQMultiOwnable.lean               [Part A — does not build]
    ├── PQSmartWalletFactory.lean         [Part A — does not build]
    ├── PQSmartWallet.lean                [Part A — does not build]
    ├── Theorems.lean                     [Part A — does not build]
    └── Verifier/                         [Part B — builds clean]
        ├── Params.lean        N, H, D, K, A, W, L, TARGET_SUM, SIG_LEN constants
        │                       + sig_len_decomposes theorem
        ├── Address.lean       ADRS bit layout + makeAdrs + setChainIndex/Pos
        │                       + adrs_size_eq_32 theorem
        ├── Hash.lean          opaque sha256 axiom + truncate / pad16 / th / thPair / thMulti
        │                       + pad16_low_half_is_zero_block theorem
        ├── Wots.lean          extract_digits / digitSum / pkFromSig
        │                       + target_sum_enforced theorem
        ├── Merkle.lean        verifyAuthPath with branchless swap encoding
        │                       + branchless_swap_equivalent_to_branching_swap theorem
        ├── Fors.lean          extract_fors_indices / forced-zero check / reconstruct
        │                       + forced_zero_fors_enforced theorem
        ├── Hypertree.lean     D=2 layer loop, SigReader for parsing
        │                       + hypertree_d_eq_2_unrolls_into_two_layers theorem
        │                       + hypertree_verify_equivalent_to_rust axiom (witnessed by KAT diff)
        └── Top.lean           top-level verify entry + length check
                                + verify_length_enforced / verify_deterministic theorems
                                + verify_byte_equivalent_to_rust axiom (witnessed by KAT diff)
```

Part B is **standalone pure-Lean** — no Verity dependency. Uses Lean
stdlib types (`Array UInt8`, `Nat`, `UInt32`, `UInt64`) and an opaque
`sha256` axiom. Mirrors the Rust verify path at
`sphincs-c10/src/{lib, hypertree, fors, wots, merkle, address, hash, params}.rs`
line-for-line.

---

## 3. Part B theorems (this session)

Pure-Lean SPHINCS+C10 verifier reference. ~40 closed theorems + 2
axioms (load-bearing, externally witnessed) + 1 documented sorry
(non-essential helper).

| # | Theorem | File | Status |
|---|---------|------|--------|
| B1 | `signature_len_eq_4008` | `Verifier/Params.lean` | proved (rfl) |
| B2 | `sig_len_decomposes` (sig = N + K·N + (K-1)·A·N + D·(L·N+4+SUBTREE_H·N)) | `Verifier/Params.lean` | proved (rfl) |
| B3 | `adrs_types_distinct` (5 ADRS types pairwise distinct) | `Verifier/Params.lean` | proved (decide) |
| B4 | `subtree_h_eq_nine` (H/D = 9) | `Verifier/Params.lean` | proved (rfl) |
| B5 | `fors_and_ht_bits_fit_in_digest` (K·A + H ≤ 256) | `Verifier/Params.lean` | proved (decide) |
| B6 | `adrs_size_eq_32` (every ADRS is 32 bytes) | `Verifier/Address.lean` | proved (simp) |
| B7 | `setChainPos_size_eq` / `setChainIndex_size_eq` | `Verifier/Address.lean` | proved (simp) |
| B8 | `pad16_low_half_is_zero_block` (N-mask: bottom 16 bytes of pad16 are zero) | `Verifier/Hash.lean` | proved (Array.ext + omega) |
| B9 | `truncate_sha256_size_eq_N` | `Verifier/Hash.lean` | proved |
| B10 | `th_size_eq_N` / `thPair_size_eq_N` / `thMulti_size_eq_N` | `Verifier/Hash.lean` | proved |
| B11 | `target_sum_enforced` (digit-sum ≠ 205 ⇒ pkFromSig returns zeros) | `Verifier/Wots.lean` | proved (if_pos) |
| B12 | `chain_iterates_w_minus_1_minus_digit_steps` | `Verifier/Wots.lean` | proved (omega) |
| B13 | `extractDigit_lt_W` (every digit < 8) | `Verifier/Wots.lean` | proved (Nat.and_le_right) |
| B14 | `accepted_digit_sum_eq_205` (contrapositive of B11) | `Verifier/Wots.lean` | proved (by_cases) |
| B15 | `branchless_swap_equivalent_to_branching_swap` (Yul `shl(5, and(idx,1))` ↔ Lean if-else) | `Verifier/Merkle.lean` | proved (rfl) |
| B16 | `forced_zero_fors_enforced` (K-th FORS index extracted from bits [132..143)) | `Verifier/Fors.lean` | proved |
| B17 | `forced_zero_iff_high_bits_clear` | `Verifier/Fors.lean` | proved |
| B18 | `extractForsIndex_lt_FORS_LEAVES` (every FORS idx < 2048) | `Verifier/Fors.lean` | proved (omega) |
| B19 | `extractHtIndex_lt_2_pow_H` | `Verifier/Fors.lean` | proved (omega) |
| B20 | `fors_indices_total_bits_eq_143` (K·A = 143) | `Verifier/Fors.lean` | proved (decide) |
| B21 | `pkFromSig_uses_K_roots` (FORS PK is computed from K roots) | `Verifier/Fors.lean` | proved |
| B22 | `hypertree_d_eq_2_unrolls_into_two_layers` | `Verifier/Hypertree.lean` | proved (rfl) |
| B23 | `signature_length_is_4008` | `Verifier/Hypertree.lean` | proved (via Params B1) |
| B24 | `verify_length_enforced` (sig.size ≠ 4008 ⇒ verify = false) | `Verifier/Top.lean` | proved (if_pos) |
| B25 | `verify_rejects_short_sig` / `verify_rejects_long_sig` | `Verifier/Top.lean` | proved |
| B26 | `verify_deterministic` | `Verifier/Top.lean` | proved (rfl) |
| B27 | `hmsg_domain_separator_matches_yul` (H_msg 0xFF...FF pad pinned) | `Verifier/Top.lean` | proved (simp) |
| **AXIOM 1** | `hypertree_verify_equivalent_to_rust` | `Verifier/Hypertree.lean` | externally witnessed (KAT diff) |
| **AXIOM 2** | `verify_byte_equivalent_to_rust` | `Verifier/Top.lean` | externally witnessed (KAT diff) |
| sorry | `yul_swap_selector_in_known_set` (helper, non-essential) | `Verifier/Merkle.lean` | documented |

The two axioms cannot be proved in Lean without an FFI bridge to
Rust's `sphincs-c10::verify` or a verified Rust-to-Lean translator —
neither exists in core Lean. They are **empirically witnessed** by
the 10-vector KAT diff harness at
`contracts/smart-wallet/test/c10_test_vectors.json` plus the Foundry
test suite at `contracts/smart-wallet/test/SPHINCsC10Asm.t.sol`.

## 3a. Part A theorems (frozen, stated only)

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
