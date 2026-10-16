(* Variable-candidate accounting for the actual opening-redacted chain backend. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RawFors RawForsCost RawShuffle RawForest PhysicalKeygenCost RoleGrindCost.

require import ChainValueView RedactedChainOracle ChainVariableBasicCost ChainVariableForsCost.

require import LeafCandidateCount LeafGrindingCandidates.

lemma chain_variable_forest_one_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).one : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+4107].
proof.
  proc; seq 1 : (leaf_variable_count Independent.queries <= q+4095).
  + call (chain_variable_fors_sign_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (chain_variable_fors_recover_public_cost (leaf_variable_count zs)); auto; smt().
qed.

lemma chain_variable_forest_sign_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).sign : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries <= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (leaf_variable_count Independent.queries <= q+5).
  + seq 4 : (leaf_variable_count Independent.queries <= q+1).
    - call (chain_variable_shuffle_derive_public_cost q); auto.
    exists* Independent.queries; elim* => zs; call (chain_variable_shuffle_permutation_public_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries <= q+49289).
  + while (0 <= step <= 12 /\ leaf_variable_count Independent.queries <= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (chain_variable_forest_one_public_cost (leaf_variable_count zs)); auto; smt().
    auto; smt().
  seq 1 : (leaf_variable_count Independent.queries <= q+53384).
  + exists* Independent.queries; elim* => zs; call (chain_variable_fors_root_public_cost (leaf_variable_count zs)); auto; smt().
  seq 2 : (leaf_variable_count Independent.queries <= q+53385).
  + exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (leaf_variable_hash_bound (leaf_variable_count zs)); auto; smt(node_width).
qed.

lemma chain_variable_forest_recover_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).recover : leaf_variable_count Independent.queries<=q ==>
    leaf_variable_count Independent.queries<=q+146 /\ size res = 16].
proof.
  proc; call (leaf_variable_hash_bound (q+145)); wp; call (leaf_variable_hash_bound (q+144)).
  while (0 <= t <= 12 /\ leaf_variable_count Independent.queries<=q+12*t).
  + exists* t; elim* => t0; wp; call (chain_variable_fors_recover_public_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

