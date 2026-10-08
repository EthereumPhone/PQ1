(* A layer can newly disclose a proper cut only through its returned WOTS signature. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer RawShuffle.
require import PersistentGrind AcceptedContexts MerkleRootWitness LayerMinimumCounts.
require import ChainValueView ChainStageSampling CachedChainOracle ChainLayerView.
require import ObservedValueOpening ObservedKeygenOpening ObservedWotsOpening ObservedReferenceTransfer.

lemma observed_layer_opening seed0 layer0 tree0 index0 message0 opened0 :
  hoare[ChainLayer(ObservedChain(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 index0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    ChainRevelation.opened => opened0 \/
      (res<>None /\ (layer0,tree0,index0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
       opened_wots_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget res).`1.`2
         ChainStage.index ChainCut.cut)].
proof.
  proc; seq 3 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\
    (ChainRevelation.opened => opened0 \/
      (signed<>None /\ (layer0,tree0,index0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
       opened_wots_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget signed).`2
         ChainStage.index ChainCut.cut))).
  + call (observed_wots_opening seed0 layer0 tree0 index0 message0 opened0).
    call (_ : true ==> true); first by trivial.
    call (observed_merkle_unopened seed0 layer0 tree0 opened0).
    auto; rewrite /valid_chain_address; smt().
  sp 1; if; last by auto; smt().
  exists* signed,Independent.rawhistory,Independent.secrethistory; elim* => signed0 h0 s0.
  wp; call (observed_layer_recover_history s0 h0).
  auto; smt(extends_refl opened_wots_count_extends).
qed.
lemma observed_layer_history_opening seed0 layer0 tree0 index0 message0 opened0 s0 h0 :
  hoare[ChainLayer(ObservedChain(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\
    ChainStage.seed=seed0 /\ valid_chain_address layer0 tree0 index0 0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 (oget res).`2) /\
    (ChainRevelation.opened => opened0 \/
      (res<>None /\ (layer0,tree0,index0)=(ChainStage.layer,ChainStage.tree,ChainStage.kp) /\
       opened_wots_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget res).`1.`2
         ChainStage.index ChainCut.cut))].
proof.
  conseq (observed_layer_root_history seed0 layer0 tree0 index0 message0 s0 h0)
    (observed_layer_opening seed0 layer0 tree0 index0 message0 opened0); rewrite /valid_chain_address; smt().
qed.
