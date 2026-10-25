(* A complete layer step carries both directions of the projection, the new
   supported plan, and the histories needed to retain all earlier plans. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer.
require import PersistentGrind SignerComponentHistory WrapperLayerPlan WrapperLayerPlanSupport.

lemma wrapper_layer_supported_projection seed0 layer0 tree0 leaf0 message0 :
  equiv [RawLayer(PreparationView(Independent)).sign ~ WrapperLayerPlan(Independent).plan :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\
    0<=leaf0<512 /\ ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_layer_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 res{1} res{2} /\
    (res{2}<>None => wrapper_layer_plan_supported Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 message0 (oget res{2}))].
proof.
  have hp : equiv [WrapperLayerPlan(Independent).plan ~ RawLayer(PreparationView(Independent)).sign :
    seed{2}=seed0 /\ layer{2}=layer0 /\ tree{2}=tree0 /\ leaf{2}=leaf0 /\ message{2}=message0 /\
    0<=leaf0<512 /\ ={arg,Independent.rawhistory,Independent.secrethistory} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    wrapper_layer_planned Independent.rawhistory{2} Independent.secrethistory{2}
      seed0 layer0 tree0 leaf0 res{2} res{1}].
  + symmetry; conseq (wrapper_layer_plan_projection seed0 layer0 tree0 leaf0 message0); smt().
  symmetry; conseq hp (wrapper_layer_plan_support seed0 layer0 tree0 leaf0 message0); smt().
qed.

lemma wrapper_layer_plan_step seed0 layer0 tree0 leaf0 message0 s0 h0 :
  equiv [RawLayer(PreparationView(Independent)).sign ~ WrapperLayerPlan(Independent).plan :
    seed{1}=seed0 /\ layer{1}=layer0 /\ tree{1}=tree0 /\ leaf{1}=leaf0 /\ message{1}=message0 /\
    0<=leaf0<512 /\ ={arg,Independent.rawhistory,Independent.secrethistory} /\
    extends s0 Independent.secrethistory{1} /\ extends h0 Independent.rawhistory{1} ==>
    ={Independent.rawhistory,Independent.secrethistory} /\
    extends s0 Independent.secrethistory{1} /\ extends h0 Independent.rawhistory{1} /\
    wrapper_layer_planned Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 res{1} res{2} /\
    (res{2}<>None => wrapper_layer_plan_supported Independent.rawhistory{1} Independent.secrethistory{1}
      seed0 layer0 tree0 leaf0 message0 (oget res{2}))].
proof.
  conseq (wrapper_layer_supported_projection seed0 layer0 tree0 leaf0 message0)
    (layer_sign_extends RawLayer s0 h0); smt().
qed.
