(* Recovery replays retained component openings and keeps both histories. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawForest RawLayer.
require import PersistentGrind ForestOpening LayerSignOpening LayerOpeningReplay SignerComponentHistory.

lemma forest_replay_history seed0 ht0 digest0 secrets0 auths0 root0 s0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_opening Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=root0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_forest_replays_opening seed0 ht0 digest0 secrets0 auths0 root0)
    (forest_recovery_extends RawForest s0 h0); smt().
qed.

lemma layer_replay_history seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) root0 s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    layer_opening Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 message0 sig0 root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=root0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq (raw_layer_replays_opening seed0 layer0 tree0 index0 message0 sig0 root0)
    (layer_recovery_extends RawLayer s0 h0); smt().
qed.
