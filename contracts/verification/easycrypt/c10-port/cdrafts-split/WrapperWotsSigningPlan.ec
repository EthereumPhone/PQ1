(* Both hypertree layers are planned before any WOTS signature values are
   materialized. The forest remains the actual forest for this WOTS reduction. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawForest RawLayer RawSigner.
require import PersistentGrind AcceptedContexts SignerCoordinates ForestRootWitness ForestRootRecording.
require import WrapperMemoProjection WrapperLayerPlan WrapperLayerPlanSupport WrapperLayerPlanStep WrapperLayerPlanTrace.

type wrapper_wots_signature_plan = raw_input * digest *
  (raw_input list * raw_input list list * raw_input) * wrapper_layer_plan list.

op wrapper_wots_signature_planned h s seed (signature : raw_signature) (plan : wrapper_wots_signature_plan) =
  signature.`1=plan.`1 /\ signature.`2=plan.`3.`1 /\ signature.`3=plan.`3.`2 /\
  forest_root_witness h s seed (hypertree_index plan.`2) plan.`3.`3 /\
  wrapper_layer_plan_trace h s seed (hypertree_index plan.`2) plan.`3.`3 signature.`4 plan.`4 2.

op wrapper_wots_result_planned h s seed (signed : raw_signature option) (planned : wrapper_wots_signature_plan option) =
  (signed=None)=(planned=None) /\
  (signed<>None => wrapper_wots_signature_planned h s seed (oget signed) (oget planned)).

module WrapperWotsSigningPlan (O : PrefixOracle) = {
  proc finish(seed : raw_input, randomizer : raw_input, digest : digest, shuffle : raw_input) : wrapper_wots_signature_plan option = {
    var ht, forest, current, idx_tree, layer, idx_leaf, signed, layers, ok, result;
    ht <- hypertree_index digest;
    forest <@ RawForest(PreparationView(O)).sign(seed,ht,digest,shuffle);
    current <- forest.`3; idx_tree <- ht; layer <- 0; layers <- []; ok <- true;
    while (layer < 2 /\ ok) {
      idx_leaf <- idx_tree %% 512; idx_tree <- idx_tree %/ 512;
      signed <@ WrapperLayerPlan(O).plan(seed,layer,idx_tree,idx_leaf,current,shuffle);
      if (signed=None) { ok <- false; } else {
        layers <- rcons layers (oget signed); current <- (oget signed).`4;
      }
      layer <- layer+1;
    }
    result <- None;
    if (ok) { result <- Some (randomizer,digest,forest,layers); }
    return result;
  }
}.

module type WrapperForestSigner (O : PrefixOracle) = {
  proc sign(seed : raw_input, ht : int, digest : digest, shuffle : raw_input) :
    raw_input list * raw_input list list * raw_input { O.hash,O.derive }
}.
module WrapperConcreteForest (O : PrefixOracle) = {
  proc sign = RawForest(PreparationView(O)).sign
}.

lemma wrapper_forest_sign_table_projection (F <: WrapperForestSigner {-Independent}) :
  equiv [F(Independent).sign ~ F(Independent).sign :
    ={arg,glob F,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob F,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_wots_signing_plan_finish_projection seed_ref digest_ref :
  equiv [RawSigner(Independent).finish ~ WrapperWotsSigningPlan(Independent).finish :
    seed{1}=seed_ref /\ digest{1}=digest_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_wots_result_planned Independent.rawhistory{1} Independent.secrethistory{1} seed_ref res{1} res{2} /\
    (res{2}<>None => (oget res{2}).`2=digest_ref)].
proof.
  proc; seq 2 2 : (seed{1}=seed_ref /\ digest{1}=digest_ref /\ ht{1}=hypertree_index digest_ref /\
    ={seed,randomizer,digest,shuffle,ht,forest,Independent.rawhistory,Independent.secrethistory} /\
    forest_root_witness Independent.rawhistory{1} Independent.secrethistory{1}
      seed_ref (hypertree_index digest_ref) forest{1}.`3).
  + call (_ : seed{1}=seed_ref /\ ht{1}=hypertree_index digest_ref /\ digest{1}=digest_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      forest_root_witness Independent.rawhistory{1} Independent.secrethistory{1}
        seed_ref (hypertree_index digest_ref) res{1}.`3).
    - conseq (wrapper_forest_sign_table_projection WrapperConcreteForest)
        (raw_forest_sign_root seed_ref (hypertree_index digest_ref) digest_ref); smt().
    auto.
  seq 6 6 : (seed{1}=seed_ref /\ digest{1}=digest_ref /\
    ={randomizer,digest,forest,ok,Independent.rawhistory,Independent.secrethistory} /\
    forest_root_witness Independent.rawhistory{1} Independent.secrethistory{1}
      seed_ref (hypertree_index digest_ref) forest{1}.`3 /\
    (ok{1} => wrapper_layer_plan_trace Independent.rawhistory{1} Independent.secrethistory{1}
      seed_ref (hypertree_index digest_ref) forest{1}.`3 layers{1} layers{2} 2)).
  + while (seed{1}=seed_ref /\ digest{1}=digest_ref /\ ht{1}=hypertree_index digest_ref /\
      ={seed,randomizer,digest,shuffle,ht,forest,current,idx_tree,layer,ok,Independent.rawhistory,Independent.secrethistory} /\
      0<=layer{1}<=2 /\ idx_tree{1}=signer_tree (hypertree_index digest_ref) layer{1} /\
      forest_root_witness Independent.rawhistory{1} Independent.secrethistory{1}
        seed_ref (hypertree_index digest_ref) forest{1}.`3 /\
      (ok{1} => wrapper_layer_plan_trace Independent.rawhistory{1} Independent.secrethistory{1}
        seed_ref (hypertree_index digest_ref) forest{1}.`3 layers{1} layers{2} layer{1} /\
        current{1}=wrapper_plan_message forest{1}.`3 layers{2} layer{1})).
    - exists* layer{1},current{1},forest{1},layers{1},layers{2},Independent.rawhistory{1},Independent.secrethistory{1};
        elim* => k message0 forest0 sigs plans h0 s0.
      wp; call (wrapper_layer_plan_step seed_ref k (signer_tree (hypertree_index digest_ref) (k+1))
        (signer_tree (hypertree_index digest_ref) k %%512) message0 s0 h0).
      auto => &1 &2 hp /=.
      have hk : 0<=k<2 by smt().
      have hc := signer_coordinate_step (hypertree_index digest_ref) k (hypertree_index_range digest_ref) hk.
      have hf0 : forest_root_witness h0 s0 seed_ref (hypertree_index digest_ref) forest0.`3 by smt().
      have ht0 : wrapper_layer_plan_trace h0 s0 seed_ref (hypertree_index digest_ref) forest0.`3 sigs plans k by smt().
      have hm : message0=wrapper_plan_message forest0.`3 plans k by smt().
      split; first by smt(extends_refl).
      move=> _ rl rr hl sl hr sr [he [hs [hh [hv hw]]]].
      have hf := forest_root_witness_extends h0 hl s0 sl seed_ref (hypertree_index digest_ref) forest0.`3 hh hs hf0.
      have ht := wrapper_layer_plan_trace_extends h0 hl s0 sl seed_ref (hypertree_index digest_ref) forest0.`3 sigs plans k hh hs ht0.
      case (rr=None) => hn.
      * have hn' : rl=None by move: hv; rewrite /wrapper_layer_planned; smt().
        rewrite ?hn ?hn' /=; smt().
      have hn' : rl<>None by move: hv; rewrite /wrapper_layer_planned; smt().
      rewrite ?hn ?hn' /=.
      have hv' : wrapper_layer_planned hl sl seed_ref k (signer_tree (hypertree_index digest_ref) (k+1))
        (signer_tree (hypertree_index digest_ref) k %%512)
        (Some ((oget rl).`1,(oget rl).`2)) (Some (oget rr)) by smt().
      have hnew := wrapper_layer_plan_trace_step hl sl seed_ref (hypertree_index digest_ref) forest0.`3 sigs plans k
        (oget rl).`1 (oget rl).`2 (oget rr) _ ht hv' _; first 2 smt().
      have hlen : size plans=k by move: ht; rewrite /wrapper_layer_plan_trace; smt().
      have hnext := wrapper_plan_message_last forest0.`3 plans (oget rr).
      move: hv; rewrite /wrapper_layer_planned; smt().
    auto; rewrite /wrapper_plan_message /signer_tree;
      smt(wrapper_layer_plan_trace_empty).
  auto; rewrite /wrapper_wots_result_planned /wrapper_wots_signature_planned; smt().
qed.
