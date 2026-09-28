(* Actual layer recovery joins the accepted WOTS opening and actual Merkle path. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer.
require import PersistentGrind WotsSignWitness WotsOpeningRecovery LayerPath.
require import PathReplay RawPathReplay RawPathComparison.

lemma wots_recovery_retains_layer seed0 layer0 tree0 index0 message0 (signature0 : raw_input list * int) leaf0 auth0 root0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=index0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\
    wots_opening h0 s0 seed0 layer0 tree0 index0 message0 leaf0 signature0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    res=leaf0 /\ layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  conseq (raw_wots_recovers_opening seed0 layer0 tree0 index0 message0 signature0 leaf0 h0 s0)
    (recovery_keeps_layer_path RawWots seed0 layer0 tree0 index0 leaf0 auth0 root0); smt().
qed.

lemma layer_recovers_opening seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) leaf0 root0 h0 s0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    wots_opening h0 s0 seed0 layer0 tree0 index0 message0 leaf0 (sig0.`1,sig0.`2) /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 sig0.`3 root0 ==>
    res=root0].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ sig=sig0 /\ pk=leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 sig0.`3 root0).
  + call (wots_recovery_retains_layer seed0 layer0 tree0 index0 message0
      (sig0.`1,sig0.`2) leaf0 sig0.`3 root0 h0 s0); auto.
  call (merkle_recover_recorded_repeat seed0 layer0 tree0 leaf0 index0 sig0.`3 root0).
  auto; rewrite /layer_path; smt().
qed.
