(* Every accepted actual layer signature returns its actual builder root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawWots RawLayer RawShuffle RawSignature.
require import PersistentGrind WotsSignWitness LayerPath LayerWitness LayerWotsSign LayerRecoveryCorrect.
require import MerkleBuilderWots LayerSignWitness BuilderTotality.

lemma layer_sign_matches_builder seed0 layer0 tree0 index0 message0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res.`1<>None => (oget res.`1).`2=res.`2].
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
  wp; call (layer_recovers_opening seed0 layer0 tree0 index0 message0
    ((oget signed0).`1,(oget signed0).`2,built0.`1) pk built0.`2 h s).
  auto; smt().
qed.

lemma observed_layer_sign_lossless : islossless LayerSignWitness(PreparationView(Independent)).sign.
proof.
  proc; seq 3 : true 1%r 1%r 0%r 0%r => //.
  + call (raw_sign_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll).
    call (shuffle_derive_lossless (PreparationView(Independent)) independent_hash_ll).
    call merkle_independent_build_ll; auto.
  sp 1; if; auto; wp.
  call (layer_recover_lossless (PreparationView(Independent)) independent_hash_ll); auto.
qed.

lemma total_layer_sign_matches_builder seed0 layer0 tree0 index0 message0 :
  phoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res.`1<>None => (oget res.`1).`2=res.`2] = 1%r.
proof. conseq observed_layer_sign_lossless (layer_sign_matches_builder seed0 layer0 tree0 index0 message0); smt(). qed.
