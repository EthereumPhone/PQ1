(* Actual hypertree-layer signatures retain the first accepting WOTS count. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer.
require import PersistentGrind AcceptedContexts SignerComponentHistory WotsFirstCount WotsCountSigning.
require import MerkleRootWitness LayerSignOpening SignerSubtreeReference.

op minimal_layer_count h seed layer tree kp message (signature : layer_signature) =
  exists d, first_wots_count h seed layer tree kp message signature.`2 d.
lemma minimal_layer_count_extends h h' seed layer tree kp message signature :
  extends h h' => minimal_layer_count h seed layer tree kp message signature =>
  minimal_layer_count h' seed layer tree kp message signature.
proof. rewrite /minimal_layer_count; smt(first_wots_count_extends). qed.

lemma raw_layer_first_count seed0 layer0 tree0 index0 message0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 ==>
    res<>None => minimal_layer_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget res).`1].
proof.
  proc; seq 3 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\
    (signed<>None => exists d, first_wots_count Independent.rawhistory seed0 layer0 tree0 index0 message0
      (oget signed).`2 d)).
  + call (raw_wots_first_count seed0 layer0 tree0 index0 message0).
    call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  sp 1; if; last by auto.
  exists* signed,Independent.rawhistory,Independent.secrethistory; elim* => signed0 h0 s0 d0.
  wp; call (layer_recovery_extends RawLayer s0 h0); auto;
    rewrite /minimal_layer_count; smt(extends_refl first_wots_count_extends).
qed.

lemma layer_sign_root_count seed0 layer0 tree0 index0 message0 s0 h0 :
  hoare [RawLayer(PreparationView(Independent)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ 0<=index0<512 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => minimal_layer_count Independent.rawhistory seed0 layer0 tree0 index0 message0 (oget res).`1 /\
      merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 (oget res).`2)].
proof.
  conseq (layer_sign_root_and_opening seed0 layer0 tree0 index0 message0 s0 h0)
    (raw_layer_first_count seed0 layer0 tree0 index0 message0); smt().
qed.
