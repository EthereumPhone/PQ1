(* Query accounting under the opening-redacted private oracle. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import RawFors RawForsCost RawShuffle RawForest PhysicalKeygenCost RoleGrindCost.

require import ChainValueView RedactedChainOracle RedactedBasicCost RedactedForsCost.

lemma redacted_forest_one_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).one : size Independent.queries = q ==>
    q <= size Independent.queries <= q+4107].
proof.
  proc; seq 1 : (q <= size Independent.queries <= q+4095).
  + call (redacted_fors_sign_public_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (redacted_fors_recover_public_cost (size zs)); auto; smt().
qed.

lemma redacted_forest_sign_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+53386 /\ size res.`3 = 16].
proof.
  proc; seq 5 : (q <= size Independent.queries <= q+5).
  + seq 4 : (q <= size Independent.queries <= q+1).
    - call (redacted_shuffle_derive_public_cost q); auto.
    exists* Independent.queries; elim* => zs; call (redacted_shuffle_permutation_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+49289).
  + while (0 <= step <= 12 /\ q <= size Independent.queries <= q+5+4107*step).
    - wp; exists* Independent.queries; elim* => zs; call (redacted_forest_one_public_cost (size zs)); auto; smt().
    auto; smt().
  seq 1 : (q <= size Independent.queries <= q+53384).
  + exists* Independent.queries; elim* => zs; call (redacted_fors_root_public_cost (size zs)); auto; smt().
  seq 2 : (q <= size Independent.queries <= q+53385).
  + exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt(node_width).
qed.

lemma redacted_forest_recover_public_cost q :
  hoare[RawForest(PreparationView(ChainPrefix(RedactedCachedChain))).recover : size Independent.queries = q ==>
    size Independent.queries = q+146 /\ size res = 16].
proof.
  proc; call (independent_hash_count (q+145)); wp; call (independent_hash_count (q+144)).
  while (0 <= t <= 12 /\ size Independent.queries = q+12*t).
  + exists* t; elim* => t0; wp; call (redacted_fors_recover_public_cost (q+12*t0)); auto; smt().
  auto; smt(node_width).
qed.

