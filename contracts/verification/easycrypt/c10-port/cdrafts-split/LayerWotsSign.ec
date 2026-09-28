(* Accepted WOTS signing retains the builder path needed by layer recovery. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawWots.
require import PersistentGrind WotsSignWitness WotsReferenceRoot LayerPath LayerWitness.

lemma wots_sign_layer_witness seed0 layer0 tree0 index0 message0 leaf0 auth0 root0 :
  hoare [RawWots(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=index0 /\ message=message0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 /\
    (res<>None => exists h s,
      wots_opening h s seed0 layer0 tree0 index0 message0 leaf0 (oget res) /\
      extends s Independent.secrethistory /\ extends h Independent.rawhistory)].
proof.
  conseq (raw_wots_sign_witness seed0 layer0 tree0 index0 message0 leaf0)
    (signing_keeps_layer_path RawWots seed0 layer0 tree0 index0 leaf0 auth0 root0).
  + rewrite /layer_witness; smt().
  smt().
qed.
