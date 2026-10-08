(* Existing exact reference witnesses remain valid under the passive chain observer. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer RawSigner RawForest.
require import PersistentGrind AcceptedContexts SignerComponentHistory ForestRootWitness ForestRootRecording MerkleRootWitness LayerMinimumCounts.
require import ChainValueView ChainLayerView ChainSignerView CachedChainOracle ObservedComponentProjection.

lemma observed_raw_layer_projection :
  equiv[ChainLayer(ObservedChain(Independent)).sign ~ RawLayer(PreparationView(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  transitivity ChainLayer(ConcreteChain(Independent)).sign
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + symmetry; conseq observed_layer_projection; smt().
  symmetry; conseq (chain_layer_sign_projection Independent); smt().
qed.
lemma observed_raw_finish_projection :
  equiv[ChainSigner(ObservedChain(Independent)).finish ~ RawSigner(Independent).finish :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  transitivity ChainSigner(ConcreteChain(Independent)).finish
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + symmetry; conseq ObservedComponentProjection.observed_finish_projection; smt().
  symmetry; conseq (chain_signer_finish_projection Independent); smt().
qed.
lemma observed_raw_sign_projection :
  equiv[ChainSigner(ObservedChain(Independent)).sign ~ RawSigner(Independent).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof.
  transitivity ChainSigner(ConcreteChain(Independent)).sign
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + symmetry; conseq observed_sign_projection; smt().
  symmetry; conseq (chain_signer_sign_projection Independent); smt().
qed.
lemma observed_raw_forest_projection :
  equiv[RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign ~
    RawForest(PreparationView(Independent)).sign :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. symmetry; conseq observed_forest_projection; smt(). qed.
lemma observed_raw_recover_projection :
  equiv[ChainLayer(ObservedChain(Independent)).recover ~ RawLayer(PreparationView(Independent)).recover :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. by sim. qed.

lemma observed_layer_root_history seed0 layer0 tree0 index0 message0 s0 h0 :
  hoare[ChainLayer(ObservedChain(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => minimal_layer_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget res).`1 /\
      merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 (oget res).`2)].
proof.
  conseq observed_raw_layer_projection (layer_sign_root_count seed0 layer0 tree0 index0 message0 s0 h0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},shuffle{m}); smt().
  smt().
qed.
lemma observed_forest_root seed0 ht0 digest0 :
  hoare[RawForest(PreparationView(ChainPrefix(ObservedChain(Independent)))).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 res.`3].
proof.
  conseq observed_raw_forest_projection (raw_forest_sign_root seed0 ht0 digest0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},ht{m},digest{m},shuffle{m}); smt().
  smt().
qed.
lemma observed_layer_recover_history s0 h0 :
  hoare[ChainLayer(ObservedChain(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq observed_raw_recover_projection (layer_recovery_extends RawLayer s0 h0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},sig{m}); smt().
  smt().
qed.
