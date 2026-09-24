(* The complete chain/reference witness belongs to the actual raw keygen leaf. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost.
require import RawLeafChains WotsReference WotsLeafReference BuilderTotality.

lemma raw_leaf_recorded seed0 layer0 tree0 kp0 :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    exists d, Independent.rawhistory.[wots_leaf_input Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 kp0] = Some d /\ res=node d].
proof.
  conseq (raw_leaf_chain_projection (PreparationView(Independent)))
    (factored_leaf_recorded seed0 layer0 tree0 kp0).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},kp{m}); smt().
  smt().
qed.

lemma total_raw_leaf_recorded seed0 layer0 tree0 kp0 :
  phoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    exists d, Independent.rawhistory.[wots_leaf_input Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 kp0] = Some d /\ res=node d] = 1%r.
proof.
  conseq (leaf_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll)
    (raw_leaf_recorded seed0 layer0 tree0 kp0); smt().
qed.
