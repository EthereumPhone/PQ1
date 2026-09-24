(* A record of the actual WOTS recovery and its authentication-path result. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import PersistentGrind AcceptedContexts PathReplay RawPathReplay LayerPath.
require import RawRecoveryTrace WotsRecoveryHistory SignerComponentHistory.

op layer_recovery_record h seed layer tree index message (signature : layer_signature) root =
  exists leaf, wots_recovery_trace h seed layer tree index message signature.`1 signature.`2 leaf /\
    layer_path h seed layer tree index leaf signature.`3 root.

lemma layer_record_extends h h' seed layer tree index message signature root :
  extends h h' => layer_recovery_record h seed layer tree index message signature root =>
  layer_recovery_record h' seed layer tree index message signature root.
proof.
  move=> hh [leaf [hw hp]]; exists leaf; split.
  + exact (recovery_trace_extends h h' seed layer tree index message signature.`1 signature.`2 leaf hh hw).
  move: hp; rewrite /layer_path; smt(path_recorded_extends).
qed.

lemma raw_layer_recovery_recorded seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    size sig0.`3=9 ==>
    layer_recovery_record Independent.rawhistory seed0 layer0 tree0 index0 message0 sig0 res].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\ size sig0.`3=9 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 index0 message0 sig0.`1 sig0.`2 pk).
  + call (raw_recovery_recorded seed0 layer0 tree0 index0 message0 sig0.`1 sig0.`2); auto.
  exists* pk; elim* => pk0; wp.
  call (_ : seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=pk0 /\ index=index0 /\ auth=sig0.`3 /\ size sig0.`3=9 /\
      wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 index0 message0 sig0.`1 sig0.`2 pk0 ==>
      wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 index0 message0 sig0.`1 sig0.`2 pk0 /\
      layer_path Independent.rawhistory seed0 layer0 tree0 index0 pk0 sig0.`3 res).
  + conseq (merkle_recover_recorded seed0 layer0 tree0 pk0 index0 sig0.`3)
      (merkle_keeps_recovery_trace RawMerkle seed0 layer0 tree0 index0 message0 sig0.`1 sig0.`2 pk0).
    - smt().
    rewrite /layer_path; smt().
  auto; rewrite /layer_recovery_record; smt().
qed.

lemma layer_record_with_history seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    size sig0.`3=9 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    layer_recovery_record Independent.rawhistory seed0 layer0 tree0 index0 message0 sig0 res].
proof.
  conseq (raw_layer_recovery_recorded seed0 layer0 tree0 index0 message0 sig0)
    (layer_recovery_extends RawLayer s0 h0); smt().
qed.
