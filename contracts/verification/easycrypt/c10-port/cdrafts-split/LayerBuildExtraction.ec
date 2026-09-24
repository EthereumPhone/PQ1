(* The reference key and authentication path come from the actual Merkle builder. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import WotsReferenceRoot LayerPath MerkleBuilderWots BuilderTotality LayerWotsExtraction.
require import VerifierWotsOpening MemoNodeCollision PublicNodeZero.

module LayerBuildCompare = {
  proc run(seed : raw_input, layer tree kp : int, message : raw_input,
      sig : layer_signature) : raw_input * raw_input = {
    var reference, recovered;
    reference <@ RawMerkle(PreparationView(Independent)).build(seed,layer,tree,kp);
    recovered <@ RawLayer(PreparationView(Independent)).recover(seed,layer,tree,kp,message,sig);
    return (reference.`2,recovered);
  }
}.

lemma actual_layer_builder_extraction seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) :
  hoare [LayerBuildCompare.run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sig=sig0 /\
    0<=kp0<512 /\ layer_width sig0 ==>
    res.`2=res.`1 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists leaf0, wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2)].
proof.
  proc; seq 1 : (exists leaf0,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sig=sig0 /\
    layer_width sig0 /\ rows_width 9 reference.`1 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 reference.`1 reference.`2).
  + call (merkle_build_wots_path seed0 layer0 tree0 kp0); auto; rewrite /layer_path /rows_width; smt().
  elim* => leaf0; exists* reference; elim* => ref0; wp.
  call (raw_layer_extracts_wots_opening seed0 layer0 tree0 kp0 message0 sig0 leaf0 ref0.`1 ref0.`2).
  auto; smt().
qed.

lemma layer_build_compare_ll : islossless LayerBuildCompare.run.
proof.
  proc; call (layer_recover_lossless (PreparationView(Independent)) independent_hash_ll).
  call merkle_independent_build_ll; auto.
qed.

lemma total_actual_layer_builder_extraction seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) :
  phoare [LayerBuildCompare.run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sig=sig0 /\
    0<=kp0<512 /\ layer_width sig0 ==>
    res.`2=res.`1 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists leaf0, wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2)] = 1%r.
proof.
  conseq layer_build_compare_ll (actual_layer_builder_extraction seed0 layer0 tree0 kp0 message0 sig0); smt().
qed.
