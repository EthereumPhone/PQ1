(* The existing exact-table plan projection removes only cached WOTS values
   and recovery calls. Actual query counts remain governed by actual procedures. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawShuffle RawLayer.
require import NodeQueryDomain IndependentWidths MerkleRootPersistence.
require import WrapperWotsPlan WrapperLayerPlan.
require import AddressedInputFields AddressedOrdinaryInputs AddressedOrdinaryHistory AddressedOrdinaryShuffle AddressedOrdinaryTrees.

lemma wots_count_ordinary_inputs old seed0 :
  hoare [RawWots(PreparationView(Independent)).count :
    size seed=32 /\ size message=16 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; while (size seed=32 /\ size message=16 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + wp; call (ordinary_hash_new_valid old seed0); auto; smt(node_query_no_count ordinary_public_nonnode).
  auto.
qed.

lemma wots_plan_ordinary_inputs old seed0 :
  hoare [WrapperWotsPlan(Independent).plan :
    size seed=32 /\ size message=16 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; seq 1 : (size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory).
  + call (wots_count_ordinary_inputs old seed0); auto.
  if; last auto.
  call (shuffle_permutation_ordinary_inputs old seed0); auto.
qed.

lemma ordinary_merkle_builder_valid (B <: MerkleBuilding {-Independent}) :
  hoare [B(PreparationView(Independent)).build :
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc (independent_tables_valid Independent.rawhistory Independent.secrethistory) => //.
  + conseq independent_hash_width; smt().
  exact preparation_wots_valid.
qed.

lemma merkle_build_ordinary_valid seed0 layer0 tree0 old :
  hoare [RawMerkle(PreparationView(Independent)).build :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  conseq (ordinary_merkle_build_new_inputs seed0 layer0 tree0 old)
    (ordinary_merkle_builder_valid RawMerkle); smt().
qed.

lemma layer_plan_ordinary_inputs seed0 layer0 tree0 old :
  hoare [WrapperLayerPlan(Independent).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ 0<=layer0<4294967296 /\ 0<=tree0<2^64 /\
    size seed0=32 /\ size message=16 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  proc; wp; call (wots_plan_ordinary_inputs old seed0).
  call (shuffle_derive_ordinary_inputs old seed0).
  call (merkle_build_ordinary_valid seed0 layer0 tree0 old).
  auto; smt(layer_shuffle_label_short).
qed.

lemma raw_layer_sign_ordinary_inputs seed0 layer0 tree0 leaf0 message0 old :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    0<=layer0<4294967296 /\ 0<=tree0<2^64 /\ 0<=leaf0<512 /\
    size seed0=32 /\ size message0=16 /\ size shuffle=32 /\
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    ordinary_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory].
proof.
  conseq (wrapper_layer_plan_projection seed0 layer0 tree0 leaf0 message0)
    (layer_plan_ordinary_inputs seed0 layer0 tree0 old).
  + move=> &m hm.
    exists Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},shuffle{m}); smt().
  smt().
qed.
