(* Actual key generation, layer signing, and a separate recovery call agree.
   Bounded WOTS count failure remains an explicit optional result. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawKeygenCost RawLayer.
require import MerkleRootWitness RawMerkleRootWitness LayerPriorRoot LayerSignOpening LayerOpeningReplay BuilderTotality.

lemma raw_layer_records_prior_root seed0 layer0 tree0 index0 message0 root0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget res).`1 root0].
proof.
  conseq (raw_layer_matches_prior_root seed0 layer0 tree0 index0 message0 root0)
    (raw_layer_sign_opening seed0 layer0 tree0 index0 message0); smt().
qed.

module ActualLayerConstruction (O : PreparationOracle) = {
  proc run(seed : raw_input, layer tree leaf : int, message shuffle : raw_input) :
      raw_input * (layer_signature * raw_input) option * raw_input option = {
    var root, signature, recovered, value;
    root <@ RawKeygen(O).root(seed,layer,tree);
    signature <@ RawLayer(O).sign(seed,layer,tree,leaf,message,shuffle);
    recovered <- None;
    if (signature <> None) {
      value <@ RawLayer(O).recover(seed,layer,tree,leaf,message,(oget signature).`1);
      recovered <- Some value;
    }
    return (root,signature,recovered);
  }
}.

lemma actual_layer_correct seed0 layer0 tree0 index0 message0 :
  hoare [ActualLayerConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root).
  + call (keygen_root_recorded seed0 layer0 tree0); auto.
  exists* root; elim* => root0.
  seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ root=root0 /\
    (signature<>None => layer_opening Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 index0 message0 (oget signature).`1 root0)).
  + call (raw_layer_records_prior_root seed0 layer0 tree0 index0 message0 root0); auto; smt().
  sp 1; if; last by auto.
  exists* signature; elim* => signature0.
  wp; call (raw_layer_replays_opening seed0 layer0 tree0 index0 message0 (oget signature0).`1 root0).
  auto; smt().
qed.

lemma actual_layer_lossless : islossless ActualLayerConstruction(PreparationView(Independent)).run.
proof.
  proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (layer_sign_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll).
    call (root_lossless (PreparationView(Independent)) independent_hash_ll preparation_wots_ll); auto.
  sp 1; if; auto; wp.
  call (layer_recover_lossless (PreparationView(Independent)) independent_hash_ll); auto.
qed.

lemma total_actual_layer_correct seed0 layer0 tree0 index0 message0 :
  phoare [ActualLayerConstruction(PreparationView(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 ==>
    (res.`2=None => res.`3=None) /\ (res.`2<>None => res.`3=Some res.`1)] = 1%r.
proof. conseq actual_layer_lossless (actual_layer_correct seed0 layer0 tree0 index0 message0); smt(). qed.
