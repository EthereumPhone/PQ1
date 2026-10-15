(* Domain-filtered layer costs retain tree construction and all reconstruction calls. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import RawWots RawMerkle RawShuffle DomainQueryCount DomainWotsCost DomainMerkleCost DomainShuffleCost.

lemma domain_layer_recover_cost q :
  hoare[RawLayer(PreparationView(Independent)).recover : node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+312 /\ size res = 16].
proof.
  proc; seq 1 : (node_query_count Independent.queries <= q+303).
  + call (domain_wots_recover_cost q); auto; smt().
  exists* Independent.queries; elim* => zs; call (domain_merkle_recover_cost (node_query_count zs)); auto; smt().
qed.
lemma domain_layer_sign_cost q :
  hoare[RawLayer(PreparationView(Independent)).sign : size seed=32 /\ size message=16 /\ node_query_count Independent.queries <= q ==>
    node_query_count Independent.queries <= q+155753 /\ (res<>None => size (oget res).`2=16)].
proof.
  proc; seq 1 : (size seed=32 /\ size message=16 /\ node_query_count Independent.queries <= q+155135).
  + call (domain_merkle_build_cost q); auto; smt().
  seq 1 : (size seed=32 /\ size message=16 /\ node_query_count Independent.queries <= q+155136).
  + exists* Independent.queries; elim* => zs; call (domain_shuffle_derive_cost (node_query_count zs)); auto; smt().
  seq 1 : (size seed=32 /\ size message=16 /\ node_query_count Independent.queries <= q+155441).
  + exists* Independent.queries; elim* => zs; call (domain_wots_sign_cost (node_query_count zs)); auto; smt().
  sp 1; if; last by auto; smt().
  wp; exists* Independent.queries; elim* => zs; call (domain_layer_recover_cost (node_query_count zs)); auto; smt().
qed.
