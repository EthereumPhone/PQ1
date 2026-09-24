(* Every accepted actual layer signature returns its actual builder root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawWots RawLayer RawShuffle RawSignature.
require import PersistentGrind WotsSignWitness LayerPath LayerWitness LayerWotsSign LayerRecoveryCorrect.
require import MerkleBuilderWots LayerSignWitness BuilderTotality.

require import LayerRecoveryHistory.

op layer_opening public private seed layer tree index message (signature : layer_signature) root =
  exists pk h s, wots_opening h s seed layer tree index message pk (signature.`1,signature.`2) /\
    extends s private /\ extends h public /\
    layer_path public seed layer tree index pk signature.`3 root.

lemma observed_layer_sign_opening seed0 layer0 tree0 index0 message0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res.`1<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res.`1).`1 (oget res.`1).`2].
proof.
  proc; seq 1 : (exists pk,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 pk built.`1 built.`2).
  + call (merkle_build_wots_path seed0 layer0 tree0 index0).
    auto; rewrite /layer_witness /layer_path /rows_width; smt().
  elim* => pk; exists* built; elim* => built0.
  seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ built=built0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 pk built0.`1 built0.`2).
  + call (shuffle_keeps_layer_witness seed0 layer0 tree0 index0 pk built0.`1 built0.`2); auto; smt().
  seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ built=built0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 pk built0.`1 built0.`2 /\
    (signed<>None => exists h s, wots_opening h s seed0 layer0 tree0 index0 message0 pk (oget signed) /\
      extends s Independent.secrethistory /\ extends h Independent.rawhistory)).
  + call (wots_sign_layer_witness seed0 layer0 tree0 index0 message0 pk built0.`1 built0.`2); auto; smt().
  sp 1; if; last by auto.
  conseq (_ : exists h s,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ built=built0 /\ signed<>None /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 pk built0.`1 built0.`2 /\
    wots_opening h s seed0 layer0 tree0 index0 message0 pk (oget signed) /\
    extends s Independent.secrethistory /\ extends h Independent.rawhistory ==> _); first smt().
  elim* => h s; exists* signed; elim* => signed0.
  wp; call (layer_recovers_opening_persistent seed0 layer0 tree0 index0 message0
    ((oget signed0).`1,(oget signed0).`2,built0.`1) pk built0.`2 h s).
  auto; rewrite /layer_opening; smt().
qed.

lemma raw_layer_sign_opening seed0 layer0 tree0 index0 message0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res).`1 (oget res).`2].
proof.
  conseq (layer_sign_witness_projection (PreparationView(Independent)))
    (observed_layer_sign_opening seed0 layer0 tree0 index0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},shuffle{m}); smt().
  smt().
qed.
