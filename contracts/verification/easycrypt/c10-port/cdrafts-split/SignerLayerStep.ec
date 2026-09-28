(* Each successful actual layer call records its opening and retains history. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawLayer.
require import PersistentGrind MerkleRootWitness LayerSignOpening LayerPriorRoot SignerComponentHistory.

lemma layer_sign_history_opening seed0 layer0 tree0 index0 message0 s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res).`1 (oget res).`2)].
proof.
  conseq (raw_layer_sign_opening seed0 layer0 tree0 index0 message0)
    (layer_sign_extends RawLayer s0 h0); smt().
qed.

lemma layer_sign_terminal seed0 layer0 tree0 index0 message0 root0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    (layer0=1 => tree0=0) /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res<>None /\ layer0=1 => (oget res).`2=root0].
proof.
  case: (layer0=1) => hc.
  + conseq (raw_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0); smt().
  conseq (_ : true ==> true); trivial.
qed.

lemma layer_sign_step seed0 layer0 tree0 index0 message0 root0 s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    (layer0=1 => tree0=0) /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res).`1 (oget res).`2) /\
    (res<>None /\ layer0=1 => (oget res).`2=root0)].
proof.
  conseq (layer_sign_history_opening seed0 layer0 tree0 index0 message0 s0 h0)
    (layer_sign_terminal seed0 layer0 tree0 index0 message0 root0); smt().
qed.
