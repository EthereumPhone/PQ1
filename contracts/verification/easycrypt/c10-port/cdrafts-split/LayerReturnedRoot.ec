(* A successful actual layer call returns a completely recorded subtree root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawShuffle.
require import MerkleRootWitness RawMerkleRootWitness RootSessionHistory LayerPath LayerRecoveryHistory.
require import LayerSignWitness LayerSignCorrect SignerComponentHistory PersistentGrind.

lemma preparation_wots_keeps_root seed0 layer0 tree0 root0 :
  hoare [PreparationView(Independent).wots :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof. proc; call (root_derive_preserved seed0 layer0 tree0 root0); auto. qed.

lemma wots_sign_keeps_root (S <: WotsSigning {-Independent}) seed0 layer0 tree0 root0 :
  hoare [S(PreparationView(Independent)).sign :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  + exact (root_hash_preserved seed0 layer0 tree0 root0).
  exact (preparation_wots_keeps_root seed0 layer0 tree0 root0).
qed.

lemma shuffle_keeps_root seed0 layer0 tree0 root0 :
  hoare [RawShuffle(PreparationView(Independent)).derive :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc; sp 1; if; auto; wp; call (root_hash_preserved seed0 layer0 tree0 root0); auto.
qed.

lemma layer_recovery_keeps_root (R <: LayerRecovery {-Independent}) seed0 layer0 tree0 root0 :
  hoare [R(PreparationView(Independent)).recover :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  exact (root_hash_preserved seed0 layer0 tree0 root0).
qed.

lemma observed_layer_records_root seed0 layer0 tree0 index0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ 0<=index0<512 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 res.`2].
proof.
  proc; seq 1 : (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 built.`2).
  + call (merkle_build_records_root seed0 layer0 tree0 index0); auto.
  exists* built; elim* => built0.
  seq 2 : (built=built0 /\ merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 built0.`2).
  + call (wots_sign_keeps_root RawWots seed0 layer0 tree0 built0.`2).
    call (shuffle_keeps_root seed0 layer0 tree0 built0.`2); auto.
  sp 1; if; auto; wp.
  call (layer_recovery_keeps_root RawLayer seed0 layer0 tree0 built0.`2); auto.
qed.

lemma observed_layer_returns_recorded_root seed0 layer0 tree0 index0 message0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res.`1<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 (oget res.`1).`2].
proof.
  conseq (observed_layer_records_root seed0 layer0 tree0 index0)
    (layer_sign_matches_builder seed0 layer0 tree0 index0 message0); smt().
qed.

lemma raw_layer_returns_recorded_root seed0 layer0 tree0 index0 message0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    res<>None => merkle_root_witness Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 (oget res).`2].
proof.
  conseq (layer_sign_witness_projection (PreparationView(Independent)))
    (observed_layer_returns_recorded_root seed0 layer0 tree0 index0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},shuffle{m}); smt().
  smt().
qed.
