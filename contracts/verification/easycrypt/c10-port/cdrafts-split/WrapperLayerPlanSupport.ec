(* Plans retain their actual accepted-count entries and the builder witness.
   These facts persist across later internal attempts and their shuffle queries. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle RawMerkle RawLayer.
require import PersistentGrind AcceptedContexts PathReplay RawPathReplay PreparationHistory RawCountRecorded WotsCountWitness WotsFirstCount.
require import WotsReference WotsReferenceRoot WotsSignatureValue WotsOpeningPersistent.
require import LayerPath LayerWitness MerkleBuilderWots WrapperWotsPlan WrapperWotsPlanProjection WrapperLayerPlan.

op wrapper_wots_plan_entry h seed layer tree kp message (plan : int * digest) =
  first_wots_count h seed layer tree kp message plan.`1 plan.`2.

op wrapper_layer_plan_supported h s seed layer tree leaf message (plan : wrapper_layer_plan) =
  wrapper_wots_plan_entry h seed layer tree leaf message (plan.`1,plan.`2) /\
  exists pk, layer_witness h s seed layer tree leaf pk plan.`3 plan.`4.

lemma wrapper_wots_plan_entry_extends h h' seed layer tree kp message plan :
  extends h h' => wrapper_wots_plan_entry h seed layer tree kp message plan =>
  wrapper_wots_plan_entry h' seed layer tree kp message plan.
proof. rewrite /wrapper_wots_plan_entry; smt(first_wots_count_extends). qed.

lemma wrapper_wots_plan_histories s0 h0 :
  hoare [WrapperWotsPlan(Independent).plan :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; seq 1 : (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (raw_count_extends s0 h0); auto.
  if; auto; call (raw_shuffle_extends s0 h0); auto.
qed.

lemma wrapper_wots_plan_supported seed0 layer0 tree0 kp0 message0 root0 :
  hoare [WrapperWotsPlan(Independent).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
    (res<>None => wrapper_wots_plan_entry Independent.rawhistory seed0 layer0 tree0 kp0 message0 (oget res))].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
    (accepted<>None => wrapper_wots_plan_entry Independent.rawhistory seed0 layer0 tree0 kp0 message0 (oget accepted))).
  + call (_ : seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
      wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 /\
      (res<>None => wrapper_wots_plan_entry Independent.rawhistory seed0 layer0 tree0 kp0 message0 (oget res))).
    - conseq (raw_count_first seed0 layer0 tree0 kp0 message0)
        (count_keeps_wots_root seed0 layer0 tree0 kp0 root0); rewrite /wrapper_wots_plan_entry; smt().
    auto.
  if; last by auto.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  call (raw_shuffle_extends s0 h0).
  auto; smt(extends_refl wrapper_wots_plan_entry_extends wots_root_extends).
qed.

lemma wrapper_wots_plan_layer_witness seed0 layer0 tree0 kp0 message0 pk0 auth0 root0 :
  hoare [WrapperWotsPlan(Independent).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 pk0 auth0 root0 ==>
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 pk0 auth0 root0 /\
    (res<>None => wrapper_wots_plan_entry Independent.rawhistory seed0 layer0 tree0 kp0 message0 (oget res))].
proof.
  have hw : hoare [WrapperWotsPlan(Independent).plan :
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 pk0 auth0 root0 ==>
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 pk0 auth0 root0].
  + exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
    conseq (wrapper_wots_plan_histories s0 h0); smt(extends_refl layer_witness_extends).
  conseq (wrapper_wots_plan_supported seed0 layer0 tree0 kp0 message0 pk0) hw;
    rewrite /layer_witness; smt().
qed.

lemma wrapper_layer_plan_support seed0 layer0 tree0 leaf0 message0 :
  hoare [WrapperLayerPlan(Independent).plan :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\ 0<=leaf0<512 ==>
    res<>None => wrapper_layer_plan_supported Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 leaf0 message0 (oget res)].
proof.
  proc; seq 1 : (exists pk,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 leaf0 pk built.`1 built.`2).
  + call (merkle_build_wots_path seed0 layer0 tree0 leaf0).
    auto; rewrite /layer_witness /layer_path; smt().
  elim* => pk; exists* built; elim* => built0.
  seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\ built=built0 /\
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2).
  + call (shuffle_keeps_layer_witness seed0 layer0 tree0 leaf0 pk built0.`1 built0.`2); auto.
  wp; call (wrapper_wots_plan_layer_witness seed0 layer0 tree0 leaf0 message0 pk built0.`1 built0.`2).
  auto; rewrite /wrapper_layer_plan_supported; smt().
qed.

lemma wrapper_layer_plan_support_extends h h' s s' seed layer tree leaf message plan :
  extends h h' => extends s s' =>
  wrapper_layer_plan_supported h s seed layer tree leaf message plan =>
  wrapper_layer_plan_supported h' s' seed layer tree leaf message plan.
proof.
  rewrite /wrapper_layer_plan_supported;
    smt(wrapper_wots_plan_entry_extends layer_witness_extends).
qed.

lemma wrapper_layer_planned_extends h h' s s' seed layer tree leaf signed planned :
  extends h h' => extends s s' =>
  wrapper_layer_planned h s seed layer tree leaf signed planned =>
  wrapper_layer_planned h' s' seed layer tree leaf signed planned.
proof.
  rewrite /wrapper_layer_planned; smt(wots_prefix_extends wots_signature_extends).
qed.
