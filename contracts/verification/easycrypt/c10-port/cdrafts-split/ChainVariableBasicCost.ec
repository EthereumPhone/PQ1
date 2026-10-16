(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List Distr IntDiv RadixEncoding.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RoleGrind RoleGrindCost RawShuffle RawWots RedactedChainOracle ChainValueView.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_derive_count q :
  hoare[RedactedChainPrefix.derive : leaf_variable_count Independent.queries<=q ==> leaf_variable_count Independent.queries<=q].
proof. proc; if; auto; call (leaf_variable_derive_bound q); auto. qed.

lemma chain_variable_role_grind_public_cost q0 :
  hoare[RoleGrind(ChainPrefix(RedactedCachedChain)).run : leaf_variable_count Independent.queries<=q0 ==>
    leaf_variable_count Independent.queries<=q0].
proof.
  proc; while (leaf_variable_count Independent.queries<=q0).
  + wp; call (leaf_variable_hash_fixed q0).
    wp; call (chain_variable_derive_count q0); auto; smt(leaf_hmsg_candidate_fixed).
  auto.
qed.

lemma chain_variable_shuffle_derive_public_cost q :
  hoare[RawShuffle(PreparationView(ChainPrefix(RedactedCachedChain))).derive : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+1].
proof. proc; sp 1; if.
  + wp; call (leaf_variable_hash_bound q); auto; smt().
  auto; smt(). qed.

lemma chain_variable_shuffle_permutation_public_cost q :
  hoare[RawShuffle(PreparationView(ChainPrefix(RedactedCachedChain))).permutation : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+4].
proof.
  proc; sp 1; if; last by auto; smt().
  while (leaf_variable_count Independent.queries<=q+4); first by auto.
  wp; while (0 <= blk <= 4 /\ leaf_variable_count Independent.queries<=q+blk).
  + exists* blk; elim* => b; wp; call (leaf_variable_hash_bound (q+b)); auto; smt().
  auto; smt().
qed.

lemma chain_variable_count_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).count : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q].
proof.
  proc; while (0<=i<=signing_budget /\ leaf_variable_count Independent.queries<=q).
  + wp; call (leaf_variable_hash_fixed q); auto; smt(leaf_wots_trial_fixed).
  auto; smt().
qed.

lemma chain_variable_chain_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).chain :
    leaf_variable_count Independent.queries<=q /\ 0 <= start <= stop <= 7 ==>
    leaf_variable_count Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ leaf_variable_count Independent.queries<=q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (leaf_variable_hash_bound (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma chain_variable_wots_recover_public_cost q :
  hoare[RawWots(PreparationView(ChainPrefix(RedactedCachedChain))).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+303 /\ size res = 16].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries<=q+1).
  + call (leaf_variable_hash_bound q); auto.
  sp 1; if; last by auto; smt(size_nseq).
  seq 3 : (leaf_variable_count Independent.queries <= q+302).
  + while (0 <= i <= 43 /\ leaf_variable_count Independent.queries <= q+1+7*i).
    - wp; exists* Independent.queries; elim* => qs1; call (chain_variable_chain_public_cost (leaf_variable_count qs1)); auto; smt(raw_digit_bounds).
    auto; smt().
  wp; exists* Independent.queries; elim* => qs; call (leaf_variable_hash_bound (leaf_variable_count qs)); auto; smt(node_width).
qed.

lemma chain_variable_raw_chain_public_cost q :
  hoare[RawWots(PreparationView(RedactedChainPrefix)).chain :
    leaf_variable_count Independent.queries<=q /\ 0 <= start <= stop <= 7 ==>
    leaf_variable_count Independent.queries <= q+7].
proof.
  proc; while (0 <= start <= j <= stop <= 7 /\ leaf_variable_count Independent.queries<=q+j-start).
  + exists* j, start; elim* => j0 s; wp; call (leaf_variable_hash_bound (q+j0-s)); auto; smt().
  auto; smt().
qed.

lemma chain_variable_concrete_value_cost q :
  hoare[ConcreteChain(RedactedChainPrefix).value :
    leaf_variable_count Independent.queries<=q /\ 0<=stop<=7 ==>
    leaf_variable_count Independent.queries<=q+7].
proof.
  proc; call (chain_variable_raw_chain_public_cost q).
  wp; inline PreparationView(RedactedChainPrefix).wots.
  wp; call (chain_variable_derive_count q); auto.
qed.
lemma chain_variable_cached_value_cost q :
  hoare[RedactedCachedChain.value :
    leaf_variable_count Independent.queries<=q /\ 0<=stop<=7 ==>
    leaf_variable_count Independent.queries<=q+7].
proof.
  proc; if.
  + if; auto; smt().
  call (chain_variable_concrete_value_cost q); auto.
qed.
