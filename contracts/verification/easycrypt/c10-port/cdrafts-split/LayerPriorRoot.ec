(* Accepted actual layer signatures agree with a separately generated root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawLayer RawMerkle RawWots RawShuffle.
require import MerkleRootWitness MerkleRootPersistence LayerSignWitness LayerSignCorrect.

lemma observed_layer_returns_prior_root seed0 layer0 tree0 index0 message0 root0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res.`2=root0].
proof.
  proc; seq 1 : (built.`2=root0).
  + call (merkle_build_matches_prior_root seed0 layer0 tree0 index0 root0); auto; smt().
  seq 2 : (built.`2=root0).
  + call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  sp 1; if; auto; wp.
  call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma observed_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0 :
  hoare [LayerSignWitness(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res.`1<>None => (oget res.`1).`2=root0].
proof.
  conseq (layer_sign_matches_builder seed0 layer0 tree0 index0 message0)
    (observed_layer_returns_prior_root seed0 layer0 tree0 index0 message0 root0); smt().
qed.

lemma raw_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res<>None => (oget res).`2=root0].
proof.
  conseq (layer_sign_witness_projection (PreparationView(Independent)))
    (observed_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},leaf{m},message{m},shuffle{m}); smt().
  smt().
qed.
