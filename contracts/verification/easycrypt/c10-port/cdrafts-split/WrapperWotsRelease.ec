(* Materialize both recorded WOTS layers without changing either memo table.
   The original forest and randomizer are copied from the supported plan. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer RawForest RawSigner.
require import ChainValueView WotsReference WotsSignatureValue SignerCoordinates.
require import WrapperWotsValues WrapperLayerPlan WrapperLayerPlanTrace WrapperLayerRelease WrapperWotsSigningPlan.

module WrapperWotsRelease (O : ChainOracle) = {
  proc run(seed : raw_input, plan : wrapper_wots_signature_plan) : raw_signature = {
    var ht, layer, signed, layers;
    ht <- hypertree_index plan.`2; layer <- 0; layers <- [];
    while (layer<2) {
      signed <@ WrapperLayerRelease(O).run(seed,layer,signer_tree ht (layer+1),signer_tree ht layer %%512,
        nth wrapper_empty_layer_plan plan.`4 layer);
      layers <- rcons layers signed.`1; layer <- layer+1;
    }
    return (plan.`1,plan.`3.`1,plan.`3.`2,layers);
  }
}.

lemma wrapper_layer_release_recorded seed0 layer0 tree0 leaf0 sig0 root0 plan0 h0 s0 :
  hoare [WrapperLayerRelease(ConcreteChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ plan=plan0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wrapper_layer_planned h0 s0 seed0 layer0 tree0 leaf0 (Some (sig0,root0)) (Some plan0) ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=(sig0,root0)].
proof.
  proc; call (wrapper_wots_values_recorded seed0 layer0 tree0 leaf0 plan0.`2 (range 0 43) h0 s0 (perm_eq_refl _)).
  auto; rewrite /wrapper_layer_planned; smt(wrapper_wots_signature_unique).
qed.

lemma wrapper_wots_release_lossless (O <: ChainOracle) :
  islossless O.value => islossless WrapperWotsRelease(O).run.
proof.
  move=> hv; proc; while true (2-layer).
  + move=> z; wp; call (wrapper_layer_release_lossless O hv); auto; smt().
  auto; smt().
qed.

lemma wrapper_wots_release_recorded seed_ref sig_ref plan_ref h_ref s_ref :
  hoare [WrapperWotsRelease(ConcreteChain(Independent)).run :
    seed=seed_ref /\ plan=plan_ref /\ Independent.rawhistory=h_ref /\ Independent.secrethistory=s_ref /\
    wrapper_wots_signature_planned h_ref s_ref seed_ref sig_ref plan_ref ==>
    Independent.rawhistory=h_ref /\ Independent.secrethistory=s_ref /\ res=sig_ref].
proof.
  proc; while (seed=seed_ref /\ plan=plan_ref /\ ht=hypertree_index plan_ref.`2 /\
    Independent.rawhistory=h_ref /\ Independent.secrethistory=s_ref /\
    wrapper_wots_signature_planned h_ref s_ref seed_ref sig_ref plan_ref /\
    0<=layer<=2 /\ layers=take layer sig_ref.`4).
  + exists* layer; elim* => k.
    wp; call (wrapper_layer_release_recorded seed_ref k (signer_tree (hypertree_index plan_ref.`2) (k+1))
      (signer_tree (hypertree_index plan_ref.`2) k %%512) (nth ([],0,[]) sig_ref.`4 k)
      (nth wrapper_empty_layer_plan plan_ref.`4 k).`4 (nth wrapper_empty_layer_plan plan_ref.`4 k) h_ref s_ref).
    auto; rewrite /wrapper_wots_signature_planned /wrapper_layer_plan_trace; smt(take_nth).
  auto; rewrite /wrapper_wots_signature_planned /wrapper_layer_plan_trace; smt(take0 take_size).
qed.

lemma wrapper_wots_release_total seed_ref sig_ref plan_ref h_ref s_ref :
  phoare [WrapperWotsRelease(ConcreteChain(Independent)).run :
    seed=seed_ref /\ plan=plan_ref /\ Independent.rawhistory=h_ref /\ Independent.secrethistory=s_ref /\
    wrapper_wots_signature_planned h_ref s_ref seed_ref sig_ref plan_ref ==>
    Independent.rawhistory=h_ref /\ Independent.secrethistory=s_ref /\ res=sig_ref] = 1%r.
proof.
  conseq (wrapper_wots_release_lossless (ConcreteChain(Independent))
    (concrete_chain_value_lossless Independent independent_hash_ll independent_derive_ll))
    (wrapper_wots_release_recorded seed_ref sig_ref plan_ref h_ref s_ref); smt().
qed.
