(* Both internally produced signatures can be compared through their plans.
   The shared recorded H_msg entry fixes the digest and forest reference;
   each supported layer then fixes the next message and materialized values. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle C10HashDomains PrefixGuess KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts SignerTrace SignerCoordinates ForestReferenceHistory ForestRootWitness ForestRootUnique.
require import WrapperLayerPlan WrapperLayerPlanIdentity WrapperLayerPlanTrace WrapperWotsSigningPlan WrapperWotsPlanSigner.

lemma wrapper_plan_trace_component_identity h s seed ht initial sigs plans sigs' plans' k i :
  0<=i<k =>
  wrapper_layer_plan_trace h s seed ht initial sigs plans k =>
  wrapper_layer_plan_trace h s seed ht initial sigs' plans' k =>
  nth ([],0,[]) sigs i=nth ([],0,[]) sigs' i =>
  wrapper_plan_message initial plans i=wrapper_plan_message initial plans' i =>
  nth wrapper_empty_layer_plan plans i=nth wrapper_empty_layer_plan plans' i.
proof.
  move=> hi [ha [hb hc]] [ha' [hb' hc']] he hm.
  have [hv hw] := hc i hi; have [hv' hw'] := hc' i hi.
  have cmp := wrapper_layer_plan_signature_comparison h s seed i
    (signer_tree ht (i+1)) (signer_tree ht i %%512) (wrapper_plan_message initial plans i)
    (nth ([],0,[]) sigs i) (nth wrapper_empty_layer_plan plans i).`4
    (nth ([],0,[]) sigs' i) (nth wrapper_empty_layer_plan plans' i).`4
    (nth wrapper_empty_layer_plan plans i) (nth wrapper_empty_layer_plan plans' i).
  smt().
qed.

lemma wrapper_plan_trace_value_identity h s seed ht initial sigs sigs' plans k :
  wrapper_layer_plan_trace h s seed ht initial sigs plans k =>
  wrapper_layer_plan_trace h s seed ht initial sigs' plans k => sigs=sigs'.
proof.
  move=> [ha [hb hc]] [ha' [hb' hc']].
  apply (eq_from_nth ([],0,[])); first smt().
  move=> i hi; have hi' : 0<=i<k by smt().
  have [hv hw] := hc i hi'; have [hv' hw'] := hc' i hi'.
  smt(wrapper_layer_plan_value_identity).
qed.

lemma wrapper_plan_trace_pair_comparison h s seed ht initial sigs plans sigs' plans' :
  wrapper_layer_plan_trace h s seed ht initial sigs plans 2 =>
  wrapper_layer_plan_trace h s seed ht initial sigs' plans' 2 =>
  (sigs=sigs')=(plans=plans').
proof.
  move=> ha hb.
  have forward : sigs=sigs' => plans=plans'.
  + move=> he.
    have h0 : nth wrapper_empty_layer_plan plans 0=nth wrapper_empty_layer_plan plans' 0.
    - apply (wrapper_plan_trace_component_identity h s seed ht initial sigs plans sigs' plans' 2 0);
        rewrite /wrapper_plan_message; smt().
    have h1 : nth wrapper_empty_layer_plan plans 1=nth wrapper_empty_layer_plan plans' 1.
    - apply (wrapper_plan_trace_component_identity h s seed ht initial sigs plans sigs' plans' 2 1);
        rewrite /wrapper_plan_message; smt().
    apply (eq_from_nth wrapper_empty_layer_plan).
    - move: ha hb; rewrite /wrapper_layer_plan_trace; smt().
    move=> i hi; move: ha hb; rewrite /wrapper_layer_plan_trace; smt().
  smt(wrapper_plan_trace_value_identity).
qed.

lemma wrapper_wots_planned_comparison h s seed root message sig_a sig_b plan_a plan_b :
  wrapper_wots_hmsg_entry h seed root message plan_a => wrapper_wots_hmsg_entry h seed root message plan_b =>
  wrapper_wots_signature_planned h s seed sig_a plan_a =>
  wrapper_wots_signature_planned h s seed sig_b plan_b =>
  (sig_a=sig_b)=(plan_a=plan_b).
proof.
  move=> ha hb hsa hsb.
  have forward : sig_a=sig_b => plan_a=plan_b.
  + move=> he.
    have hd : plan_a.`2=plan_b.`2 by move: ha hb hsa hsb; rewrite /wrapper_wots_hmsg_entry /wrapper_wots_signature_planned; smt().
    have hr : plan_a.`3.`3=plan_b.`3.`3.
    - apply (forest_root_unique h s seed (hypertree_index plan_a.`2));
        move: hsa hsb; rewrite /wrapper_wots_signature_planned; smt().
    have hc := wrapper_plan_trace_pair_comparison h s seed (hypertree_index plan_a.`2) plan_a.`3.`3
      sig_a.`4 plan_a.`4 sig_b.`4 plan_b.`4.
    move: hsa hsb; rewrite /wrapper_wots_signature_planned; smt().
  have backward : plan_a=plan_b => sig_a=sig_b.
  + move=> he.
    have hc := wrapper_plan_trace_value_identity h s seed (hypertree_index plan_a.`2) plan_a.`3.`3
      sig_a.`4 sig_b.`4 plan_a.`4 2.
    move: hsa hsb; rewrite /wrapper_wots_signature_planned; smt().
  smt().
qed.

lemma wrapper_wots_supported_comparison h s seed root message sig_a sig_b plan_a plan_b :
  wrapper_wots_signer_supported h s seed root message sig_a plan_a =>
  wrapper_wots_signer_supported h s seed root message sig_b plan_b => sig_a<>None =>
  (sig_b<>None /\ sig_a=sig_b)=(plan_b<>None /\ plan_a=plan_b).
proof.
  move=> ha hb hsa; case (sig_b=None) => hsb.
  + move: ha hb; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned; smt().
  have he := wrapper_wots_planned_comparison h s seed root message
    (oget sig_a) (oget sig_b) (oget plan_a) (oget plan_b).
  move: ha hb he; rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned; smt().
qed.

lemma wrapper_wots_signature_planned_extends h h' s s' seed signed planned :
  extends h h' => extends s s' => wrapper_wots_signature_planned h s seed signed planned =>
  wrapper_wots_signature_planned h' s' seed signed planned.
proof.
  rewrite /wrapper_wots_signature_planned;
    smt(forest_root_witness_extends wrapper_layer_plan_trace_extends).
qed.

lemma wrapper_wots_supported_extends h h' s s' seed root message signed planned :
  extends h h' => extends s s' => wrapper_wots_signer_supported h s seed root message signed planned =>
  wrapper_wots_signer_supported h' s' seed root message signed planned.
proof.
  move=> hh hs.
  have he : forall p, wrapper_wots_hmsg_entry h seed root message p => wrapper_wots_hmsg_entry h' seed root message p
    by move: hh; rewrite /extends /wrapper_wots_hmsg_entry; smt().
  rewrite /wrapper_wots_signer_supported /wrapper_wots_result_planned;
    smt(wrapper_wots_signature_planned_extends).
qed.

lemma wrapper_wots_signer_plan_preserved (S <: CompleteSigner {-Independent}) seed0 root0 message0 signed0 planned0 :
  hoare [S(Independent).sign :
    wrapper_wots_signer_supported Independent.rawhistory Independent.secrethistory seed0 root0 message0 signed0 planned0 ==>
    wrapper_wots_signer_supported Independent.rawhistory Independent.secrethistory seed0 root0 message0 signed0 planned0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (complete_signer_histories S s0 h0); smt(extends_refl wrapper_wots_supported_extends).
qed.
