/-
Audit script: prints every axiom used by the headline theorems.

Run via `lake env lean scripts/dump_axioms.lean`.

This is the mechanical equivalent of Verity's `--trust-report`: every
axiom transitively used by the project's claimed theorems appears here.
-/

import SphincsCVerify

-- (Run as `lake env lean scripts/dump_axioms.lean` so the `#print axioms`
-- commands are elaborated and their output appears.)

#print axioms SphincsCVerify.Spec.signatureLen_eq_4008
#print axioms SphincsCVerify.Spec.maxUses_lt_positions

-- Quantitative security-margin layer (Crypto/Quantitative.lean): the on-chain
-- usage cap turned into kernel-checked bit-security floors. All axiom-free
-- (pure `decide`) except the antitone lemma ({propext, Quot.sound}).
#print axioms SphincsCVerify.Crypto.Quantitative.advantage_floors_within_slot_cap
#print axioms SphincsCVerify.Crypto.Quantitative.c10_security_floor_at_slot_cap
#print axioms SphincsCVerify.Crypto.Quantitative.c10_cap_is_load_bearing
#print axioms SphincsCVerify.Crypto.Quantitative.securityFloor_antitone_in_qBits

-- Dual-SE XOR split-secrecy (Crypto/SplitSecrecy.lean): the SOUND combinatorial
-- core of CLAUDE.md invariant #1 ("neither chip alone reveals any bit") — the
-- one-time-pad exactly-one-mask/bijection structure, plus the FAITHFUL deployed
-- (nonzero-mask) statement (halfE_deployed_*: leak = exactly one excluded
-- entropy, Δ ≤ 2⁻²⁵⁶). KERNEL-ONLY {propext, Quot.sound} (NO Classical.choice,
-- NO native/ofReduceBool — the one `decide` is kernel reduction on literals).
-- The security reading additionally needs a uniform+independent mask (TRNG), NOT
-- proven here — see the Scope block in SplitSecrecy.lean. Pin EVERY load-bearing
-- lemma (the distributional bijections do NOT ride dual_split_2of2_structure).
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_unique_mask
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_equiconsistent
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_pushforward_bijective
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfO_pushforward_bijective
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_deployed_consistent
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_deployed_excludes_self
#print axioms SphincsCVerify.Crypto.SplitSecrecy.dual_split_2of2_structure
#print axioms SphincsCVerify.Crypto.SplitSecrecy.joint_determines_entropy
#print axioms SphincsCVerify.Crypto.SplitSecrecy.halfE_nondegenerate

-- A3.1 deductive-closure track (Interpreter/Memory.lean): byte-addressed memory
-- frame/disjointness lemmas (residual R2). Kernel-only, mathlib-free, NO new
-- content axiom (the precompile hash is a parameter). See A3_1_CLOSURE_PATH.md.
#print axioms SphincsCVerify.Interpreter.writeRegion_comm
#print axioms SphincsCVerify.Interpreter.mstore32_get
#print axioms SphincsCVerify.Interpreter.staticcallSha256_frame
#print axioms SphincsCVerify.Interpreter.hashPair_assembled
#print axioms SphincsCVerify.Interpreter.hashPairStep_frame
#print axioms SphincsCVerify.Interpreter.mload32_mstore32_self
#print axioms SphincsCVerify.Interpreter.mload32_hashPairStep
#print axioms SphincsCVerify.Interpreter.climbMem_eq_specClimb

-- A3.1 Sha256Bridge (Interpreter/Sha256Bridge.lean): the byte-array ↔
-- big-endian-word isomorphism connecting interpreter words to spec ByteVecs.
-- beByte_mload32 (load-then-extract recovers the stored byte) needs only
-- [propext, Quot.sound]; beByte_wordOf is the round-trip to Spec.ByteVec.
#print axioms SphincsCVerify.Interpreter.beByte_mload32
#print axioms SphincsCVerify.Interpreter.beByte_wordOf

-- A3.1 proof-phase foundations: phase-split composition (Yul.lean) + the reusable
-- input-assembly bridge (Sha256Bridge.lean) — when memory holds the segments at
-- consecutive 32-byte windows, the precompile input slice = the spec's ByteSeg.flatten.
#print axioms SphincsCVerify.Interpreter.execList_append
#print axioms SphincsCVerify.Interpreter.execFor_invariant
-- Bounded loop-induction engine: `hstep` may assume `cur < N`, so a per-iteration
-- obligation bounded by the index (e.g. the FORS climb's `h < A` `H_adrs`/`H_sib`) is
-- dischargeable — the fix that makes `fors_climb`/`fors_tree_body` non-vacuous.
#print axioms SphincsCVerify.Interpreter.execFor_invariant_lt
#print axioms SphincsCVerify.Interpreter.slice_toArray_eq_flatten
#print axioms SphincsCVerify.Interpreter.C10.c10Oracle_holdsSegs

-- A3.1 first PHASE proof (Interpreter/Phases.lean): running the transcribed H_msg
-- fragment yields env "digest" = wordOf (Spec.hMsg …) — the deductive refinement
-- of the verifier's first phase, the template for FORS/WOTS/hypertree.
#print axioms SphincsCVerify.Interpreter.C10.hmsg_digest

-- A3.1 FORS Merkle climb refinement (the canonical climb, reused by the hypertree):
-- the interpreter's A=11-level inner forRange refines Spec.Fors.reconstructRoot
-- (env "node" = wordOf (pad16 (reconstructRoot …))), via execFor_invariant + the
-- masked-oracle helper + the forIn→foldl bridge.
#print axioms SphincsCVerify.Interpreter.C10.fors_climb
#print axioms SphincsCVerify.Interpreter.C10.mload_masked_eq_wordOf_pad16
#print axioms SphincsCVerify.Interpreter.C10.reconstructRoot_eq_foldl
#print axioms SphincsCVerify.Interpreter.C10.fors_tree_body
-- Non-vacuity guards: the bounded `H_adrs`/`H_sib` that `fors_tree_body` carries are
-- INHABITED (the regression that fences out re-introducing an unsatisfiable hyp).
#print axioms SphincsCVerify.Interpreter.C10.H_adrs_dischargeable
#print axioms SphincsCVerify.Interpreter.C10.H_sib_dischargeable
#print axioms SphincsCVerify.Interpreter.C10.wordOf_make
#print axioms SphincsCVerify.Interpreter.C10.wordOf_forsNode

-- A3.1 FORS phase (Interpreter/Phases.lean): the K-1 normal-tree i-loop, the forced-zero
-- last tree, the 13-root compression, and the capstone composing all three from the
-- post-H_msg VM (env "forsPk" = wordOf (pad16 (reconstructForsPk …)) / revert on the
-- forced-zero violation).  Plus the readBitsLe↔word-shift index bridge underpinning the
-- extractForsIndices/extractHtIndex alignment.  All kernel-only.
#print axioms SphincsCVerify.Interpreter.C10.readBitsLe_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.extractForsIndices_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.extractHtIndex_eq_wordShift
#print axioms SphincsCVerify.Interpreter.C10.fors_normal_trees
#print axioms SphincsCVerify.Interpreter.C10.fors_last_tree
#print axioms SphincsCVerify.Interpreter.C10.fors_root_compress
#print axioms SphincsCVerify.Interpreter.C10.fors_phase

-- A3.1 WOTS+C phase capstone: the per-layer WOTS interp fragment refines
-- Spec.Wots.pkFromSig (digit-sum≠205 → revert; else env "wotsPk" = wordOf (pad16 wpk)
-- with pkFromSig … = some wpk). Non-vacuity witnessed by wots_pkfromsig_nonvacuous.
#print axioms SphincsCVerify.Interpreter.C10.wots_pkfromsig

#print axioms SphincsCVerify.Spec.Theorems.verify_deterministic
#print axioms SphincsCVerify.Spec.Theorems.verify_rejects_wrong_length
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpBootstrap_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bumpSlot_monotonic
#print axioms SphincsCVerify.Wallet.MultiOwnable.bootstrap_unremovable
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_preserved_by_bumpSlot
#print axioms SphincsCVerify.Wallet.Invariants.create2_address_chain_independent
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_only_via_verify
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_unset_index_uniform
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_result_local
#print axioms SphincsCVerify.Wallet.Invariants.combinedCap_inductive
#print axioms SphincsCVerify.Wallet.Invariants.eip1271_forbids_bootstrap
#print axioms SphincsCVerify.Wallet.Invariants.factory_requires_bootstrap_sig
#print axioms SphincsCVerify.Crypto.cannot_forge_without_breaking_SHA256
-- P9 / conjunct-2 tie-in: EUF-CMA instantiated at the actual op's sphincsDigest
-- (answers the "detached ∀-rider, never instantiated" finding). Closure MUST be
-- exactly the A5 axioms + kernel (additive — adds NO new axiom; consumes only
-- what theft_free already carries). Conditionally non-vacuous; P9 irreducible.
#print axioms SphincsCVerify.Wallet.Invariants.unauthorized_userop_breaks_hash
#print axioms SphincsCVerify.Bridge.yul_eq_refined
-- Headline theorem — should depend on exactly:
--   propext, Classical.choice, Quot.sound  (Lean kernel)
--   SM_DT_TCR_F, ITSR_F, hMsg_random_oracle, EUF_CMA_SPHINCSplusC  (A5)
--   precompile_0x02_is_FIPS_180_4 (A1),
--   solidityVerifier_compiles_correctly (A3.1), evm_bytecode_executes_correctly (A4)
-- (A2 `entrypoint_honest` is a PROVED kernel-only theorem since 2026-08-20 —
-- no longer an axiom, so it no longer appears in any closure.)
#print axioms SphincsCVerify.Spec.Theorems.theft_free

-- Bytecode-transported headline — theft_free's closure plus
-- solidityWallet_compiles_correctly (A3.2): the EntryPoint transition's
-- wallet step is the opaque deployed-bytecode symbol.
#print axioms SphincsCVerify.Spec.Theorems.theft_free_bytecode

-- P1 (I-5) reachability discharge. `reachable_implies_combinedCap` is KERNEL-ONLY
-- ([propext, Quot.sound]) — the hInv conditioning is a kernel-proven inductive
-- invariant, not a fuzz-backed assumption. `theft_free_bytecode_reachable` takes
-- `Reachable σ.walletStorage` instead of the bald hInv and derives the cap; its
-- closure MUST equal theft_free_bytecode's (the discharge adds no axiom). The
-- Reachable hypothesis is NON-VACUOUS: `Reachable.genesis : Reachable Storage.empty`.
#print axioms SphincsCVerify.Wallet.Invariants.reachable_implies_combinedCap
#print axioms SphincsCVerify.Spec.Theorems.theft_free_bytecode_reachable

-- Bytecode-transported squat-defence (I-8) — exactly
-- solidityFactory_compiles_correctly (A3.3) + kernel.
#print axioms SphincsCVerify.Spec.Theorems.factory_squat_defence_bytecode

-- Claim 1 corollary — adds sha256_collision_resistance to the closure.
#print axioms SphincsCVerify.Spec.Theorems.theft_free_with_calldata_binding

-- Claim 3 corollary — composes the 6 Wallet.Execute theorems.
#print axioms SphincsCVerify.Spec.Theorems.executeBatch_faithful

-- Claim 2 corollaries — owner-set integrity + initialization atomicity
-- (covered by I-4 + initialize_called_exactly_once + owner_set_nonempty_after_init).
#print axioms SphincsCVerify.Wallet.Invariants.initialize_called_exactly_once
#print axioms SphincsCVerify.Wallet.Invariants.owner_set_nonempty_after_init
#print axioms SphincsCVerify.Wallet.Invariants.storage_mutations_preserve_impl_slot_disjointness

-- Claim 4 — execution-gate non-bypass: no wallet-initiated external call
-- in σ'.callStack without a successful verifier-true validate earlier in
-- the trace. Closure: propext + I-1 (validateSignature_only_via_verify
-- via validateSignature_success_iff) + E-8 (execute_only_validateSig_authorises)
-- composed with the applyStep token-write lemma. No new axioms.
#print axioms SphincsCVerify.Spec.Theorems.every_call_gated_by_verifier
#print axioms SphincsCVerify.Spec.Theorems.no_call_without_prior_verifier_acceptance
#print axioms SphincsCVerify.Wallet.TxFlow.callstack_grew_implies_some_verify_true

-- Claim 4 / Gap-2 (credits model) — per-index exactly-once anti-replay:
-- every money-moving external-call step consumes its OWN per-index credit,
-- which only a verifier-true validate can have stamped. Closure: kernel-only
-- {propext, Classical.choice, Quot.sound} — same as the existential gate.
#print axioms SphincsCVerify.Spec.Theorems.every_call_consumes_its_own_validated_credit
#print axioms SphincsCVerify.Spec.Theorems.credit_lift_implies_verified_validate

-- Claim 4 / Gap-2 (credits model) — GLOBAL aggregate completeness complement
-- (work-todo FV-#5): in any successful trace from a clean transient, the number
-- of money-moving execute/executeBatch steps is ≤ the number of validate steps,
-- via a genuine mathlib-free finite-support credit sum (`sumOver`). The tight
-- content is the credit-reserve conservation; the count bound is its S=[] corollary.
-- Closure MUST be kernel-only {propext, Classical.choice, Quot.sound} — NO project
-- axiom (this is a pure operational/arithmetic conservation over the model).
#print axioms SphincsCVerify.Wallet.CreditLedger.creditConservation
#print axioms SphincsCVerify.Wallet.CreditLedger.exec_count_le_validate_count
#print axioms SphincsCVerify.Spec.Theorems.exec_count_le_validate_count
-- Non-vacuity (decode-free): a live credit funds one successful execute — rules out
-- the degenerate "executeWithOffchainCount unsatisfiable for all inputs" vacuity.
#print axioms SphincsCVerify.Wallet.CreditLedger.execute_step_satisfiable

-- Claim 4, transported to the deployed EXECUTE bytecode (A3.2-exec): a
-- successful deployed executeWithOffchainCount / executeBatchWithOffchainCount
-- required the matching validated-owner token on entry. Closure adds
-- solidityWalletExecute_compiles_correctly (resp. ...Batch...) — the
-- execute bridge axioms discharged by test/halmos/HalmosExecuteEquiv.t.sol.
#print axioms SphincsCVerify.Spec.Theorems.deployed_execute_requires_prior_token
#print axioms SphincsCVerify.Spec.Theorems.deployed_executeBatch_requires_prior_token

-- (I-7 bootstrap) Bootstrap few-time cap enforced at the validation gate —
-- the faithfulness-audit (2026-06-14) P1 fix that makes capOk's bootstrap
-- strictness proof-load-bearing (two-gate parity with the slot path). Closure
-- = {propext, Quot.sound} only (kernel-clean, no new axiom).
#print axioms SphincsCVerify.Wallet.Invariants.validateSignature_bootstrap_cap_strict

-- (Gap-3) Off-chain/on-chain domain separation — the RAW32 forgery-oracle
-- defense: an off-chain replaySafeHash-nested value is never equal to any
-- UserOp sphincsDigest. Closure adds exactly ONE new cited axiom,
-- keccak_sha256_cross_separation (cross-hash separation, same `… ∨ BreaksHash`
-- reduction shape as sha256_collision_resistance); keccak256 is `opaque`
-- (Classical.choice), not a named axiom. Never concludes False.
#print axioms SphincsCVerify.Wallet.OffchainBinding.offchain_nested_disjoint_from_userop_digest

-- (Gap-4) UUPS upgrade-path unreachable — the named end-to-end assembly.
-- COMPOSES the two already-proven pieces (Execute self-target rejection +
-- StorageLayout impl-slot disjointness). No new proof, no new axiom.
-- Closure: kernel-only {propext, Classical.choice, Quot.sound}.
#print axioms SphincsCVerify.Wallet.UpgradeSafety.upgrade_path_unreachable

-- A3.1 hypertree phase (Interpreter/HypertreePhase.lean): verifyAuthPath as a foldl.
#print axioms SphincsCVerify.Interpreter.C10.verifyAuthPath_eq_foldl
#print axioms SphincsCVerify.Interpreter.C10.ht_climb
#print axioms SphincsCVerify.Interpreter.C10.forIn_yield_eq_foldl_pointwise
#print axioms SphincsCVerify.Interpreter.C10.verifyHypertree_eq_foldl

-- A3.1 GRAND COMPOSITION + faithful-form bridge composite (directly gated per the
-- 2026-06-18 adversarial review, H-3). `execC10Asm_eq` is the kernel keystone — the
-- transcribed deployed Yul equals the declarative spec modulo the two N-mask guards;
-- it MUST stay kernel-only {propext, Classical.choice, Quot.sound} (a sorry/native_decide
-- regression here was previously caught only by the full rebuild). `deployed_verifier_refines_spec`
-- composes A3.1 (`solidityVerifier_compiles_correctly`) with `execC10Asm_eq`; its closure
-- must be exactly {kernel triple, solidityVerifier_compiles_correctly}.
#print axioms SphincsCVerify.Interpreter.C10.execC10Asm_eq
#print axioms SphincsCVerify.Bridge.deployed_verifier_refines_spec
-- A3.1 generic env-frame (Interpreter/EnvFrame.lean): a var assigned nowhere is preserved.
#print axioms SphincsCVerify.Interpreter.execStmt_env_frame
#print axioms SphincsCVerify.Interpreter.execList_env_frame
#print axioms SphincsCVerify.Interpreter.execFor_env_frame

-- (FV-#4) verify_signs COMPLETENESS — honest_consistent : WellFormed sk → consistent sk.
-- The completed reference signer round-trips with the spec verifier. Closure kernel-only
-- {propext, Classical.choice, Quot.sound} (no new axiom). SCOPE: this is a COMPLETENESS
-- (usability) result, NOT in theft_free's closure. Meaningful as "firmware sigs accepted
-- on-chain" only via spec-verify = on-chain verifier (A3.1) PLUS spec-Signer.sign = firmware
-- signer (ASSUMED — `sign` is hand-written/noncomputable and verifier-derived; see the
-- trust-base note in Verifier/HonestConsistent.lean). Bridge (b) is a follow-up to anchor.
#print axioms SphincsCVerify.Interpreter.C10.honest_consistent

-- NON-VACUITY WITNESS COVERAGE (verify-ledger-consistency C9). A `K` (kernel)
-- proof is only meaningful if the hypothesis it conditions on is SATISFIABLE —
-- `#print axioms` is green on a vacuously-true conditional too. These ∃-style
-- witnesses prove the headline hypotheses are inhabited on the operational input
-- space, so the discharge is not vacuous. The ledger's `witness_coverage` block
-- pins each (construct -> witness); C9 fails CI if a witness drops from this dump
-- or its closure leaves the allowed set (a witness proven via a vacuous/false
-- axiom would be circular). Adapted from LeanLoop's `vet` HYP probe, but
-- mathlib-free (PQSigner's lean/ carries no Plausible) — hand-witnesses, enforced.
-- `combinedCapInvariant_empty` witnesses theft_free_bytecode's `hInv` (the empty
-- store satisfies the combined cap); `..._initialised` the post-deploy state.
-- (H_adrs/H_sib_dischargeable + execute_step_satisfiable above are the rest.)
#print axioms SphincsCVerify.Wallet.Invariants.combinedCapInvariant_empty
#print axioms SphincsCVerify.Wallet.Invariants.combinedCapInvariant_initialised

-- (2026-07-02, finding exec-lean-F3) `cannot_remove_bootstrap` is a Claim-2 headline
-- corollary listed in AXIOM_STATUS.json claim_corollaries but was the ONLY one absent
-- from this dump + the closures block — so verify-audit/verify-ledger-consistency could
-- not see it. Enrolled here + in `closures` so a rewrite onto an existing documented
-- axiom (which the by-name closure diff would otherwise miss) reddens.
#print axioms SphincsCVerify.Wallet.Invariants.cannot_remove_bootstrap

-- (2026-07-02, finding exec-lean-F4) the EUF-CMA KeyHistory consistency FENCE. These two
-- guard lemmas keep the empty-transcript valid-KAT detonator unformable (so BreaksHash is
-- not constructively provable). They were pinned by NO gate — a two-part edit (drop the
-- `signed_recorded` field + delete both guards) would slip through. Enrolling them here means
-- DELETING either guard breaks this dump build (a hard CI redden), and `closures` pins their
-- kernel-only closure so a weakening that pulled in a project axiom also reddens.
#print axioms SphincsCVerify.Crypto.keyHistory_empty_signs_nothing
#print axioms SphincsCVerify.Crypto.honest_sig_not_forgery
