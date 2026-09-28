(* Returned actual layer signatures replay under later table extensions. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawLayer.
require import PersistentGrind PathReplay LayerPath LayerSignOpening WotsSignWitness LayerRecoveryCorrect.

lemma layer_opening_extends public public' private private' seed layer tree index message signature root :
  extends public public' => extends private private' =>
  layer_opening public private seed layer tree index message signature root =>
  layer_opening public' private' seed layer tree index message signature root.
proof.
  move=> hh hs [pk h0 s0 [ho [hes [heh hp]]]].
  have hp' : layer_path public' seed layer tree index pk signature.`3 root
    by move: hp; rewrite /layer_path; smt(path_recorded_extends).
  rewrite /layer_opening; exists pk h0 s0; move: hh hs hes heh; rewrite /extends; smt().
qed.

lemma raw_layer_replays_opening seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) root0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    layer_opening Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 message0 sig0 root0 ==>
    res=root0].
proof.
  conseq (_ : exists pk h s,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    wots_opening h s seed0 layer0 tree0 index0 message0 pk (sig0.`1,sig0.`2) /\
    extends s Independent.secrethistory /\ extends h Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 pk sig0.`3 root0 ==> res=root0).
  + rewrite /layer_opening; smt().
  elim* => pk h s.
  conseq (layer_recovers_opening seed0 layer0 tree0 index0 message0 sig0 pk root0 h s); smt().
qed.
