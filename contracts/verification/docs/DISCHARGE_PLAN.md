# Make `verify-theft-free` a True Signal

## Context

Today, `make verify-theft-free` builds Lean and prints "theft_free: PROVED",
but the kernel-checked theorem rests on placeholders that make the headline
claim — "money cannot be stolen without a valid signature" — materially
overstated:

1. Three of the five bridge axioms have type `True` (no semantic content):
   `Bridge.solidityVerifier_compiles_correctly`,
   `Bridge.evm_bytecode_executes_correctly`,
   `Bridge.precompile_0x02_is_FIPS_180_4`. Their named presence in the
   dependency closure is documentation, not constraint.
2. The three cryptographic "shape" axioms also reduce to `True`. Only
   `EUF_CMA_SPHINCSplusC` carries content (a direct non-forgery postulate).
3. `Wallet/ValidateUserOp.lean::sphincsDigest` is a stub: it discards
   `op`, `entryPoint`, `chainId` and returns `sha256 []`. The Solidity
   counterpart is a 12-field `abi.encodePacked → sha256`.
4. Solidity selectors in the Lean model are placeholders (`0x00000000`,
   `0x00000001`, `0x00000002`), not `bytes4(keccak256(sig))`.
5. `Spec/Signer.lean::forsAuthPaths` fills auth paths with zeros.
6. `Verifier/Equivalence.lean` has three section lemmas closed with
   `True := trivial`. `Wallet/Invariants.lean` has placeholder theorems
   of type `True` (`no_reset_path`, `userop_acceptance_implies_signed_or_break`).
7. The Lean ↔ deployed-bytecode bridge is informal: `verifyYulModel` is a
   Lean function, not a model of the on-chain bytecode at the codehash
   `0x919cf8ef4b028b50f51de2e71aba7d08900d0e59833d003eed68102c7e9289c0`.
8. `Bridge.EntryPoint.entrypoint_honest` is an axiom about the Lean
   `handleOp` definition, not the deployed EntryPoint v0.6 at
   `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`.

Target outcome: every axiom in `#print axioms theft_free` is either
(a) a Lean theorem with real content, (b) a cited Kontrol / KEVM /
Certora discharge session by ID, or (c) a stated universal-Ethereum TCB
item. No `True`-typed propositions in the dependency closure. The
headline statement is then defensible as a mathematical claim about the
deployed bytecode, not about a Lean toy.

User constraints: in-house single engineer (no audits, no external
consultancies); cryptographic A5 stays as a cited TCB axiom with a
tightened shape; the success bar is "discharged-or-cited per axiom"
across A1–A5.

## Strategy

Five tiers. Each tier ends at a shippable milestone that strictly
improves the credibility of `make verify-theft-free`. Tier-0 and
Tier-1.5 together deliver ~70% of the credibility uplift in the first
two months because they convert the proof's dependency closure from
vacuous to load-bearing; the rest is filling in actual content under
that structure.

| Tier | Scope | Elapsed | Headline output |
|------|-------|---------|-----------------|
| 0 | Honest messaging + axiom-shape lints | 1 wk | Output stops overclaiming |
| 1 | Real Lean model + bridge-axiom refactor | 6–8 wks | Axioms are load-bearing, content-bearing |
| 2 | Mechanized bytecode equivalence (Kontrol + Certora) on the four PQSmartWallet contracts | 6–8 mo | A3 discharged per contract by session ID |
| 3 | EntryPoint v0.6 Kontrol against mainnet bytecode | 8–12 mo (concurrent w/ T2) | A2 discharged by session ID |
| 4 | Tighten A5 (crypto) shape + A1 empirical | 1–2 wks (parallel) | Shapes carry real bounds; A1 has Foundry cross-check |

Total elapsed: ~12 months for the core proof; +6 months for EntryPoint v0.6.

## Tier 0 — Stop misrepresenting (1 week)

Goal: the current build pipeline stops claiming more than it proves;
new claims that would silently re-introduce the failure mode are
blocked at lint.

Changes:

1. `Makefile` (target `verify-theft-free`, lines 1588–1651) — rewrite
   the success block. Replace the unconditional "An adversary ... cannot
   cause a deployed PQSmartWallet proxy's balance to decrease" with a
   structured printout enumerating each axiom in the closure with its
   *current* discharge state (Lean theorem ↔ Kontrol session ID ↔ cited
   TCB ↔ placeholder). Source the table from a single file
   `contracts/verification/docs/AXIOM_STATUS.json` so future tier
   landings only update one place.
2. New script `contracts/verification/scripts/lint_axioms.sh` invoked
   from `make verify-theft-free` after the existing axiom-diff:
   - Fails if any axiom in the project has type `True` or
     `∀ ..., True` (parses `lake env lean scripts/dump_axiom_types.lean`).
   - Fails if any `theorem … : True := trivial` exists outside an
     explicit allowlist file `scripts/known_trivial_theorems.txt`.
   - Fails if any `def … : … := …` in `SphincsCVerify/` ignores all
     non-`Unit` arguments via the `let _ := arg; …` pattern (a stub
     marker). Allowlist-based.
3. New Lean script `contracts/verification/lean/scripts/dump_axiom_types.lean`
   that prints every `axiom`'s elaborated type. Wire into `verify-theft-free`.
4. `contracts/verification/README.md` and
   `contracts/verification/lean/README.md` — replace the "What this
   proves on completion" paragraph with the current state plus a one-
   line link to `AXIOM_STATUS.json`. Stop using the future-tense
   "proves" verb where the present tense is overclaiming.
5. CI: add the lint script to `.github/workflows/test.yml` (gates merges).
6. `BLOCKERS.md` — append a "What still needs to be discharged" section
   pointing to this plan.

Done when: `make verify-theft-free` prints a status table; CI fails
any new `True`-typed axiom or `True := trivial` theorem; documentation
no longer uses unqualified "proves money cannot be stolen" language.

## Tier 1 — Real Lean model + bridge-axiom refactor (6–8 weeks)

Goal: every Lean function the theorem mentions computes the byte-level
result the deployed contract does, *and* the bridge axioms are
restructured so they carry real semantic content (rather than `True`).
After this tier the proof has integrity: the only remaining hand-wave
is the bridge from the Lean model to the deployed EVM bytecode, and
that hand-wave is named in the axiom statement.

### 1.1 Concrete `sphincsDigest` in Lean (5 days)

`contracts/verification/lean/SphincsCVerify/Wallet/ValidateUserOp.lean`
lines 213–227: replace the stub with the 12-field
`abi.encodePacked → sha256` chain matching `PQSmartWallet.sol:326–343`.
Use `Spec/Sha256Impl.lean::sha256` (already kernel-computable). Reuse
`Spec/Bytes.lean::ofU32BE` and the `loadValue16`/`loadU32BE` helpers
that `Verifier/Refined.lean` already exports.

Define the field encoding as `def sphincsDigest_preimage : UserOperation
→ ByteVec 20 → Nat → ByteVec N` and prove a layout lemma
`sphincsDigest_preimage_len : … = 20+32+32+32+5*32+32+20+32` (`= 240` B).

### 1.2 Real Solidity selectors in Lean (3 days)

`Wallet/ValidateUserOp.lean:48–65`: replace the placeholder constants
with the actual `bytes4(keccak256(sig))` values. Two-step:
- Hard-code the four-byte values directly in Lean (sourced from
  `forge inspect PQSmartWallet methodIdentifiers`).
- Add Foundry test `contracts/smart-wallet/test/LeanSelectorParity.t.sol`
  asserting each Lean constant equals the Solidity-side
  `this.<fn>.selector`. CI gate. This sidesteps mechanizing Keccak-256
  in Lean while keeping the constants checked against the source of
  truth.

### 1.3 Real FORS auth-path signer (1 week)

`Spec/Signer.lean:137–151`: replace `forsAuthPaths` stub with a real
declarative treehash using `Spec/Fors.lean` and `Spec/Hash.lean`.
The Rust reference at `sphincs-c10/src/fors.rs` is the byte-level
witness; mirror its structure. Mark `findCount` and `grindR` as
`noncomputable` is acceptable for the spec layer (they are
probabilistic), but the auth-path construction is deterministic and
must be `def`.

### 1.4 Close `Verifier/Equivalence.lean` section lemmas (1–2 weeks)

Replace the three placeholder `True := trivial` lemmas
(`fors_section_consistent`, `ht_layer0_consistent`, `ht_layer1_consistent`)
with real propositional statements about the offset arithmetic in
`Verifier/Refined.lean::reconstructForsTreeRoot`,
`reconstructForsPkRefined`, `hypertreeLayerStep`. After the concrete
`deserialise` from 2026-05-18, each lemma reduces to `simp` over
explicit offsets; the work is statement-writing, not deep reasoning.

### 1.5 Prove `consistent sk` for honestly-keygen'd `sk` (3–4 weeks)

`Spec/Theorems.lean:103–107`: today `consistent` is a precondition
quoted into `verify_signs`. Discharge it as a theorem
`keygen_produces_consistent` taking any `(sk_seed, pk_seed)` such that
`pk_root = hypertree::compute_pk_root sk_seed pk_seed` and concluding
`consistent ⟨sk_seed, pk_seed, pk_root⟩`. Four sub-lemmas under a
new `Spec/Lemmas/`:
- `MerkleRoundtrip.lean`: `reconstructRoot (authPath t i) i leaves[i] = root t`
- `WotsRoundtrip.lean`: `chain seed adrs (W-1-d) (chain seed adrs d x) = chain seed adrs (W-1) x`
- `ForsRoundtrip.lean`: composes Merkle round-trip over the K subtrees
- `ChainHash.lean`: per-layer hypertree composition

Each is a ~200-line induction. The composition unrolls `D = 2`.

Note: `verify_signs` is *not* in the dep closure of `theft_free` today.
This work is for usability/auditability of the spec, and to remove
documentation-mode placeholders. If we keep `consistent` as a
precondition (defensible), reorder to ship 1.6/1.7/1.8 first.

### 1.6 Storage-collision freedom + no-upgrade-path (1 week)

`Wallet/Storage.lean`: model ERC-7201 slot derivation as a `def slotOf`
keyed on the namespace string. Prove
`ownerTableSlot ≠ proxyImplementationSlot` (ERC-1967 slot
`0x360894...bbc`) and `bootstrapUsesSlot`, `slotUsesSlot`,
`offchainSigCountSlot` all disjoint from the proxy slot and from each
other (by injectivity of `keccak256 ∘ encode`). Used by Tier-2 Kontrol
side as the precondition for the storage-slot disjointness obligation.

### 1.7 EntryPoint v0.6 Lean model — narrow and accurate (3 days)

`Bridge/EntryPoint.lean`: the current `handleOp` is a Lean fiction
whose `entrypoint_honest` axiom is trivially provable from the def.
Rename: `LeanEntryPointModel.handleOp` makes the abstraction explicit.
Keep the axiom but document that *the real* discharge is Tier-3 (Kontrol
against deployed EntryPoint v0.6 bytecode). Don't pretend the current
shape is load-bearing about the real contract.

### 1.8 Convert placeholder `True` theorems to real statements (3 days)

`Wallet/Invariants.lean`:
- `no_reset_path : True := trivial` → state the meta-conjunction
  explicitly: `bumpBootstrap_no_decrease ∧ bumpSlot_no_decrease ∧
  setOffchain_no_decrease_offchain ∧ addOwner_preserves_counters ∧
  removeOwner_preserves_counters`.
- `userop_acceptance_implies_signed_or_break : True := trivial` →
  state as `∃ signer ∈ ownerTable, signer signed digest` ∨ EUF-CMA breaks;
  close via the existing `cannot_forge_without_breaking_SHA256` + I-1.

`Bridge/Refinement.lean::deployed_verifier_refines_spec : True := by trivial`
→ delete (it's superseded by Tier 1.9 axiom refactor).

### 1.9 Bridge-axiom refactor: `opaque + axiom-equality` shape (5 days, KEY)

This is the load-bearing structural change. The current vacuous shape

```lean
axiom solidityVerifier_compiles_correctly : ∀ ..., True
axiom evm_bytecode_executes_correctly : True
axiom precompile_0x02_is_FIPS_180_4 : ∀ ..., True
```

becomes:

```lean
-- Deployed-bytecode result functions are opaque; their behaviour is
-- pinned by the per-contract axiom below.
opaque DeployedBytecode.SPHINCsC10Asm_verify :
    ByteVec 32 → ByteVec 32 → ByteVec 32 → ByteVec SignatureLen → Bool
opaque DeployedBytecode.PQSmartWallet_validateUserOp :
    Storage → UserOperation → Address → Nat → Result × Storage
opaque DeployedBytecode.PQSmartWalletFactory_createAccount :
    ... → Option Address
opaque DeployedBytecode.PQMultiOwnable_ownerAt :
    Storage → Nat → Option OwnerBytes
opaque DeployedBytecode.SHA256_precompile :
    List UInt8 → ByteVec 32

axiom solidityVerifier_compiles_correctly :
    ∀ pkSeed pkRoot msg sig,
      DeployedBytecode.SPHINCsC10Asm_verify pkSeed pkRoot msg sig
        = Bridge.SolidityVerifier.verifyYulModel pkSeed pkRoot msg sig

axiom solidityWallet_compiles_correctly :
    ∀ s op ep cid,
      DeployedBytecode.PQSmartWallet_validateUserOp s op ep cid
        = Wallet.ValidateUserOp.validateSignature s op ep cid
            DeployedBytecode.SPHINCsC10Asm_verify

axiom solidityFactory_compiles_correctly :
    ∀ ms mr s0s s0r ch sig,
      DeployedBytecode.PQSmartWalletFactory_createAccount ms mr s0s s0r ch sig
        = Wallet.Factory.createAccount ms mr s0s s0r ch sig
            DeployedBytecode.SPHINCsC10Asm_verify

axiom precompile_0x02_is_FIPS_180_4 :
    ∀ input, DeployedBytecode.SHA256_precompile input = Spec.Hash.sha256 [⟨input⟩]

-- A4 stays as a universal Ethereum TCB statement; the opaque +
-- equality shape makes the dependency visible without an artificial
-- propositional statement.
```

Rewrite `Spec/Theorems.lean::theft_free` to quantify over the
`DeployedBytecode.*` opaque names rather than the Lean Yul model.
Now `#print axioms theft_free` is non-vacuously load-bearing on each
named bridge axiom: hypothetically removing it produces a hole the
proof cannot close.

Tier-2 then discharges each `solidity*_compiles_correctly` axiom by
citing a Kontrol session that establishes the propositional equality
for the deployed runtime bytecode at the pinned codehash. The axiom
stays as an `axiom` in Lean (Kontrol output isn't a Lean proof term)
but its statement now has real content and the discharge has a
machine-checkable artifact off-Lean.

Updates to existing call sites: every Lean theorem that previously
called `Bridge.SolidityVerifier.verifyYulModel` directly now calls
`DeployedBytecode.SPHINCsC10Asm_verify`; the equality axiom is used
in the one place it's needed. This is mechanical (the model functions
keep their definitions, the references are rewired).

## Tier 2 — Mechanized bytecode equivalence (6–8 months)

Goal: each `solidity*_compiles_correctly` axiom from Tier 1.9 is
discharged by a Kontrol or Certora session whose ID is checked into
`AXIOM_STATUS.json` and re-verified in CI.

Sequencing: easiest-to-hardest, by isolation.

### 2.1 Kontrol: SPHINCsC10Asm.verify (2–3 months)

The cryptographic core. Pure Yul, 0 storage, 0 external calls except
`staticcall(0x02)`. Deliverable: a Kontrol claim
`kevm[runtimeCode(SPHINCsC10Asm)](pkSeed, pkRoot, msg, sig) =
 lean_verifyYulModel_smt(pkSeed, pkRoot, msg, sig)` proved against
the pinned runtime codehash `0x919cf8ef4b028b50f51de2e71aba7d08900d0e59833d003eed68102c7e9289c0`.

Concrete steps:
1. Install Kontrol; pin a Kontrol version in `flake.nix` /
   `contracts/verification/kontrol/.tool-versions`.
2. Author `contracts/verification/kontrol/sphincs_verify.k` — KEVM
   spec translating `Verifier/Refined.lean::verifyRefined` to SMT.
3. Author `contracts/verification/kontrol/sphincs_verify_harness.sol`
   — Foundry-shape harness with symbolic `pkSeed`, `pkRoot`, `msg`
   (constrained by N_MASK) and symbolic-valued 4008-byte `sig`.
4. Axiomatise `staticcall(0x02, ...)` in K → `keccak256 → sha256`
   (Kontrol cannot symbolically execute the SHA-256 precompile). This
   bottoms out at A1 (precompile correctness), which Kontrol does not
   discharge; that's expected.
5. Run; capture session artifacts under
   `contracts/verification/kontrol/sessions/sphincs_verify/`.
6. Cite the session hash in `AXIOM_STATUS.json` as the discharge for
   `solidityVerifier_compiles_correctly`.
7. CI: gate on Kontrol re-run (it's deterministic given the pinned
   bytecode + Kontrol version).

Gotchas (from technical critique):
- Memory range 0x00..0x600 is touched; constrain in the harness.
- `solc 0.8.28` optimizer settings must be pinned beyond just the
  version: lock optimizer runs + via_ir in `foundry.toml` and
  re-pin the runtime codehash.

### 2.2 Certora: PQMultiOwnable (3 weeks)

Owner table monotonicity, counter monotonicity, bootstrap
unremovability. CVL is the right tool. Extend the existing
`contracts/smart-wallet/reference/certora/` rules to the PQ-specific
contract. Spec file: `contracts/smart-wallet/certora/PQMultiOwnable.spec`.

Rules to land (mirroring the Lean invariants):
- `nextOwnerIndex_only_increases`
- `bootstrapUses_only_increases`
- `slotUses_only_increases_per_index`
- `offchainSigCount_only_increases_per_index`
- `cannot_remove_index_zero`
- `combined_cap_inductive`

Discharge: cite Certora rule-set hash in `AXIOM_STATUS.json` against
`solidityWallet_compiles_correctly`'s owner-table component.

### 2.3 Certora: PQSmartWalletFactory (3 weeks)

CREATE2 determinism + squat-defence. CVL handles `computeAddress`
natively. Spec file: `contracts/smart-wallet/certora/PQSmartWalletFactory.spec`.

Rules:
- `salt_depends_only_on_master_pk` (I-7)
- `createAccount_requires_bootstrap_sig` (I-8)
- `same_inputs_same_address`
- `no_redeployment_at_same_address`

Discharge: cite Certora rule-set hash in `AXIOM_STATUS.json` against
`solidityFactory_compiles_correctly`.

### 2.4 Kontrol: PQSmartWallet (4–6 months)

The hardest tier-2 work. The wallet has ERC-7201 storage, EIP-1153
transient storage (`_TS_VALIDATED_OWNER_INDEX_PLUS_ONE`,
`_TS_PENDING_BOOTSTRAP_BUMP`), manual ABI-decode assembly, try/catch
on the verifier external call, and five distinct control-flow branches
in `_validateSignature`.

Pre-pay with a Kontrol lemma library:
1. `lemma_abi_decode_equivalence`: the assembly block in
   `_validateSignature` (lines 366–379 of `PQSmartWallet.sol`) is
   equivalent to a Solidity `abi.decode((uint256,bytes), sig)` plus a
   tail-pad zero check.
2. `lemma_tstore_tload_single_tx`: within one transaction,
   `tload(slot)` after `tstore(slot, v)` returns `v`.
3. `lemma_trycatch_returns_false_on_revert`: if the external call
   reverts, `_validateSignature`'s catch branch sets the verifier
   result to `false`.
4. `lemma_storage_slot_disjoint`: composes Tier 1.6 storage-collision
   freedom with the deployed bytecode's `sload`/`sstore` slot set.

Main proof — per function:
- `validateUserOp(op, hash, missingFunds)` ≡ Lean `validateSignature`
  (modulo missingFunds payment, which is a separate EntryPoint concern
  covered by A2).
- `executeWithOffchainCount(...)` — the ONLY money-moving function.
  Prove: bytecode behaviour ≡ "msg.sender must be `address(this)` (set
  via prior `validateUserOp`-set transient owner-index) AND
  `offchainSigCount[i] := newCount` is monotonic" → in particular,
  no path debits balance without `validateUserOp` having returned
  success in the same transaction.
- `addOwnerBytes(bytes)` ≡ owner-table append; only callable in
  bootstrap selector path.
- `removeOwnerAtIndex(uint256, bytes)` ≡ owner-table delete with the
  invariant that index 0 cannot be removed.
- `isValidSignature(hash, sig)` ≡ Lean
  `IsValidSignature.erc1271IsValidSignature`; bootstrap rejected.

Deliverable: Kontrol sessions cited in `AXIOM_STATUS.json` for each
function; the union discharges `solidityWallet_compiles_correctly`.

Risk: path explosion. Mitigation: tighten symbolic inputs in the
harness; use Kontrol's lemma compilation; budget for an additional
month of harness tuning.

## Tier 3 — EntryPoint v0.6 mainnet bytecode (8–12 months, concurrent w/ T2)

Goal: convert `Bridge.EntryPoint.entrypoint_honest` from an axiom about
the Lean `handleOp` fiction to an axiom about the *deployed* EntryPoint
v0.6 contract at `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789`, with the
discharge being a Kontrol session against the deployed runtime bytecode.

This is the largest single tier. The user picked "mathematical proofs,
not audits", so the OpenZeppelin/ChainSecurity/Spearbit audit citation
is not acceptable as discharge.

Sub-tiers:

### 3.1 Source the deployed bytecode + verify equivalence to v0.6 source (2 weeks)

Pull the runtime bytecode from mainnet at the canonical address. Pin
its codehash. Verify the bytecode matches `solc` compilation of the
ERC-4337 v0.6 source repository at
`github.com/eth-infinitism/account-abstraction` tag `v0.6.0`.

### 3.2 Author Kontrol spec for the EntryPoint properties we need (2 months)

We only need three properties for `theft_free`:
1. `wallet_executed_only_after_validate_success`: in `handleOp(op)`,
   `wallet.executeUserOp(...)` (or equivalent calldata execution) is
   `CALL`-ed iff `wallet.validateUserOp(...)` returned the success
   sentinel.
2. `entrypoint_never_directly_debits_wallet`: every balance debit on
   `op.sender` flows through a `CALL` whose caller is the EntryPoint
   itself executing the wallet's authorised calldata.
3. `userOpHash_per_v0.6_spec`: the EntryPoint computes
   `userOpHash = keccak256(abi.encode(userOpHash(op), entryPoint, chainId))`
   per the v0.6 spec.

Author each as a Kontrol claim against the deployed bytecode.

### 3.3 Discharge + cite (3–6 months execution)

Kontrol on EntryPoint v0.6 is hard because: (a) the contract has
~600 LOC including the staking/deposit accounting we don't need to
verify, (b) it uses `transferFrom`-style external calls into the
paymaster path that require careful precondition modelling, (c) the
`opInfo` struct + transient storage interactions are dense.

Mitigation: model the paymaster path as a symbolic external function
(we don't need to verify the paymaster's behaviour to prove "balance
debits flow only via wallet-authorised paths"). Focus on the three
properties above; everything else stays under-specified.

Deliverable: three Kontrol sessions cited in `AXIOM_STATUS.json`
discharging `entrypoint_honest`.

Fallback if path explosion makes Kontrol intractable: state the
axiom against the deployed bytecode (so it's load-bearing) but cite
the ERC-4337 v0.6 reference implementation source plus the codehash
pin. This is weaker but still a step up from the current state. Decide
at month 10 of Tier 3 based on Kontrol progress.

## Tier 4 — Tighten A5 (1–2 weeks, parallel)

Goal: replace the `True`-typed crypto shape axioms with content-bearing
statements. Per user choice, do NOT mechanize EUF-CMA in Lean.

Changes to `contracts/verification/lean/SphincsCVerify/Crypto/Assumptions.lean`:

```lean
-- Was: SM_DT_TCR_F_Shape : Prop := ∀ _ _ _, True
-- New: a real advantage statement.
def SM_DT_TCR_F_Advantage (q : Nat) : Nat := q * (2^N_BITS) + q^2 / (2^N_BITS)
-- Cited from Barbosa et al. 2024 §§ 4-5 Theorem 1.

structure SM_DT_TCR_F_Statement where
  -- For any PPT adversary making at most q distinct-tweak target
  -- queries against the chain-step F, the probability of a target
  -- collision is bounded by SM_DT_TCR_F_Advantage q.
  bound : Unit

axiom SM_DT_TCR_F : SM_DT_TCR_F_Statement
```

The `bound : Unit` field is a marker that the assumption is stated
abstractly (Lean has no probability theory backbone in scope). The
*advantage function* `SM_DT_TCR_F_Advantage` is a concrete `Nat → Nat`;
the statement form is parametric.

Same treatment for `ITSR_F_Advantage`, `hMsg_RO_Advantage`,
`EUF_CMA_SPHINCSplusC_Advantage q t`.

Add citations to the axiom docstrings: Barbosa/Dupressoir/Hülsing/
Meijers/Strub ASIACRYPT 2024 (ePrint 2024/910); Hülsing PQC2022 (WOTS+C
/ FORS+C); Hülsing/Kudinov ASIACRYPT 2022 (tight bound recovery).

Note the asymmetric trust: SPHINCS+ (NOT SPHINCS+C) has the Barbosa
mechanization; SPHINCS+C is +Hülsing PQC2022, a peer-reviewed
construction without a separate full mechanization. This is the right
place to record that gap.

## Tier 5 — Differential testing + A1 empirical (1 month, concurrent)

Goal: byte-level Rust ↔ Lean ↔ Solidity parity becomes a CI gate.

### 5.1 Lean ↔ Rust byte-level (5 days)

Now possible because `Spec/Sha256Impl.lean::sha256` is kernel-computable.

- New Lean executable
  `contracts/verification/lean/scripts/verify_test_vectors.lean`
  that reads `c10_test_vectors.json` (the existing 10 KAT vectors used
  by `SPHINCsC10Asm.t.sol`) and `#eval`s `Spec.Signature.verify` on
  each. Asserts agreement with the Rust-produced "expected" boolean.
- `make lean-vectors` invokes it; CI gate.

### 5.2 Lean selector parity Foundry test (1 day; subset of Tier 1.2)

Already specified in Tier 1.2; mentioned here as the CI gate that
ensures the Lean pinned selectors keep matching the Solidity
`bytes4(keccak256(sig))`.

### 5.3 A1 strengthening: Foundry SHA-256 cross-check (3 days)

`contracts/smart-wallet/test/Sha256PrecompileParity.t.sol`: assert that
the EVM SHA-256 precompile at `0x02` matches `Spec.Hash.sha256` for
each of the 10 KAT vectors' computed digests. Not a formal discharge
of A1 but the strongest empirical evidence the project can produce on
its own bytecode. Cited in `AXIOM_STATUS.json` against A1.

### 5.4 Bytecode-freeze gate hardening (1 day)

Existing `EXPECTED_RUNTIME_CODEHASH` test in `SPHINCsC10Asm.t.sol` —
extend to the wallet, factory, and PQMultiOwnable runtime bytecodes.
Pin in `contracts/verification/docs/PINNED_CODEHASHES.md`. Without this
pin, the Tier-2 Kontrol sessions are voided by any silent compiler
change.

## CI gates added across tiers

After Tier 0:
- `lint_axioms.sh` — no new `True`-typed axioms or theorems
- `make verify-theft-free` runs and prints `AXIOM_STATUS.json` table

After Tier 1:
- `make verify-build` passes with the refactored bridge axioms
- `make lean-vectors` passes (Tier 5.1 wired early)
- `forge test --match-contract LeanSelectorParity` passes
- `forge test --match-contract Sha256PrecompileParity` passes

After Tier 2:
- Kontrol session re-runs (deterministic given pinned versions) pass
- `forge test` continues to pass at pinned codehashes

After Tier 3:
- EntryPoint v0.6 Kontrol sessions re-run pass

After Tier 4:
- `lint_axioms.sh` fails on any axiom whose statement type contains
  `True` as a conclusion (the only allowed `True`s are pure-structural
  marker fields like `SM_DT_TCR_F_Statement.bound`)

## Critical files to modify

Lean side (`contracts/verification/lean/SphincsCVerify/`):
- `Bridge/Refinement.lean:63–96` — Tier 1.9 axiom refactor
- `Bridge/EntryPoint.lean:104–155` — Tier 1.7 rename + Tier 3 connect to deployed bytecode
- `Crypto/Assumptions.lean:87–136` — Tier 4 shape refactor
- `Crypto/EUFCMA.lean:135–141` — Tier 4 advantage-bound restatement
- `Spec/Theorems.lean:275–331` — Tier 1.9 rewire to `DeployedBytecode.*`
- `Spec/Signer.lean:137–151` — Tier 1.3 FORS auth paths
- `Verifier/Equivalence.lean` (the three placeholders) — Tier 1.4
- `Wallet/ValidateUserOp.lean:48–65, 213–227` — Tier 1.1 + 1.2 (selectors + sphincsDigest)
- `Wallet/Storage.lean` — Tier 1.6 ERC-7201 slot derivation
- `Wallet/Invariants.lean:259, 435–440` — Tier 1.8 placeholder conversions
- `Spec/Lemmas/{MerkleRoundtrip,WotsRoundtrip,ForsRoundtrip,ChainHash}.lean` (new) — Tier 1.5

Tooling + CI:
- `Makefile:1588–1651` — Tier 0 honest output
- `contracts/verification/scripts/lint_axioms.sh` (new) — Tier 0
- `contracts/verification/lean/scripts/dump_axiom_types.lean` (new) — Tier 0
- `contracts/verification/docs/AXIOM_STATUS.json` (new) — single source of truth
- `contracts/verification/docs/PINNED_CODEHASHES.md` (new) — Tier 5.4
- `contracts/verification/kontrol/` (new tree) — Tier 2.1, 2.4, 3
- `contracts/smart-wallet/certora/{PQMultiOwnable,PQSmartWalletFactory}.spec` (new) — Tier 2.2, 2.3
- `contracts/smart-wallet/test/{LeanSelectorParity,Sha256PrecompileParity}.t.sol` (new) — Tier 1.2, 5.3
- `.github/workflows/test.yml` — wire lint + Kontrol + new Foundry tests
- `flake.nix` (or equivalent) — pin Kontrol/Certora versions
- `foundry.toml` — pin solc optimizer settings (Tier 2.1 gotcha)

Reused existing utilities (do not reinvent):
- `Spec/Sha256Impl.lean::sha256_impl` — Tier 1.1 sphincsDigest
- `Spec/Bytes.lean::loadValue16, loadU32BE, ofU32BE, u32ToB32` — Tier 1.1, 1.4
- `Verifier/Refined.lean::verifyRefined, reconstructForsTreeRoot, hypertreeLayerStep` — Tier 1.4
- `Wallet/MultiOwnable.lean::bumpBootstrap_monotonic, bumpSlot_monotonic, bootstrap_unremovable` — Tier 2.2 Certora rule mirroring
- `contracts/smart-wallet/test/c10_test_vectors.json` (100.8 KB, 10 KAT vectors) — Tier 5.1
- `contracts/smart-wallet/test/SPHINCsC10Asm.t.sol::EXPECTED_RUNTIME_CODEHASH` — Tier 5.4
- `sphincs-c10/src/` Rust reference — Tier 1.3 byte-level witness
- Existing Certora scaffolding at `contracts/smart-wallet/reference/certora/` — Tier 2.2, 2.3 starting point

## Verification — how to test end-to-end

Per-tier acceptance:

Tier 0: `make verify-theft-free` exits 0; prints the
`AXIOM_STATUS.json` table; CI rejects a PR that introduces a
`True`-typed axiom in a sandboxed branch.

Tier 1: `make verify-build` passes; `lake env lean scripts/dump_axioms.lean`
shows `theft_free`'s axiom closure with no `True`-typed entries;
`make lean-vectors` passes on the 10 KAT vectors; `forge test
--match-contract LeanSelectorParity` passes.

Tier 2.1: A clean Kontrol re-run from a fresh checkout reproduces the
session ID cited in `AXIOM_STATUS.json` for SPHINCsC10Asm.verify.

Tier 2.2, 2.3: `certora-cli` re-runs reproduce the rule-set hashes.

Tier 2.4: Kontrol sessions for each PQSmartWallet function pass; the
union covers every wallet `validateUserOp` / `execute*` / `isValidSignature`
code path.

Tier 3: Kontrol sessions for the three EntryPoint properties pass
against the mainnet runtime codehash.

Tier 4: `lint_axioms.sh` passes with the stricter "no `True` conclusion"
rule; the advantage functions are referenced in the `Crypto/` axiom
docstrings.

Final headline test: `make verify-theft-free` prints

```
theft_free: PROVED
  A1 (SHA-256 precompile): cited Ethereum consensus (geth/reth) +
       Foundry parity test 10/10 vectors pass + Lean Spec.Hash.sha256
       FIPS 180-4 kernel-computable
  A2 (EntryPoint v0.6): Kontrol session <hash> against mainnet
       codehash <pin>
  A3-verifier: Kontrol session <hash> against pinned runtime
       codehash 0x94a6...50e9
  A3-wallet: Kontrol session <hash> against pinned runtime
       codehash <pin>
  A3-factory: Certora rule-set <hash>
  A3-multiownable: Certora rule-set <hash>
  A4 (EVM executes per spec): universal Ethereum TCB (cited KEVM)
  A5 (SPHINCS+C EUF-CMA): Barbosa et al. 2024 (SPHINCS+) +
       Hülsing PQC2022 (+C variant); advantage bound
       Advantage_EUF_CMA(t, q) = ...
  Lean kernel built-ins: propext, Classical.choice, Quot.sound
No True-typed axioms in the dependency closure.
```

That is the production-ready signal.

## Risks and gotchas (from technical review)

1. **Kontrol cannot symbolically execute the SHA-256 precompile.**
   Every Kontrol claim against SPHINCsC10Asm.verify bottoms out at A1
   (precompile correctness). Mitigation: Tier 5.3 Foundry parity test
   strengthens A1 empirically; the axiom is preserved with a citation
   to the parity test session.

2. **`try/catch` modelling in Kontrol.** `_validateSignature` has a
   `try/catch` around `c10Verifier.verify`. Validate Kontrol handles
   the catch-block return implicitly before committing Tier 2.4 to a
   Kontrol-only strategy.

3. **EIP-1153 transient storage** is supported in Kontrol but newer.
   Tier 2.4 toy harness must verify tstore/tload semantics before scale.

4. **solc 0.8.28 optimizer settings** must be pinned beyond version
   number — optimizer runs, via_ir on/off, optimizer details. Tier 2.1
   gotcha; addressed in `foundry.toml`.

5. **Kontrol output is not a Lean-importable proof.** Each Tier-2/3
   discharge is a *cited session ID*, not a closed Lean proof term.
   The TCB expansion is named in `AXIOM_STATUS.json` (Kontrol
   soundness + K backend + Z3/CVC5 soundness + the human translation
   between Lean model and Kontrol claim). This is honest and bounded.

6. **`consistent sk` is not in the dep closure of `theft_free`.**
   Tier 1.5 is for spec-layer integrity and to remove
   documentation-mode placeholders, not because the headline theorem
   depends on it. If schedule pressure mounts, defer Tier 1.5 to
   post-Tier-3.

7. **Single-engineer estimate**: 18–24 months for Tiers 0–3 + parallel
   Tier 4–5. Tier 3 is the swing variable; if EntryPoint v0.6 Kontrol
   blows up, fall back to the codehash-pinned cited-source position
   stated in Tier 3.3.

8. **SPHINCS+C vs SPHINCS+ gap (A5).** Barbosa 2024 mechanized
   SPHINCS+, not SPHINCS+C. The +C variant is published peer-reviewed
   (Hülsing PQC2022) but without separate mechanization. Tier 4 records
   this asymmetry explicitly in the axiom docstring.
