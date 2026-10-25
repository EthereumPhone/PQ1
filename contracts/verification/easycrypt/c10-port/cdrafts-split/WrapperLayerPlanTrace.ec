(* A sequence of supported public plans records the messages linking layers.
   It also retains the actual signatures without materializing them internally. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawLayer RawForest.
require import PersistentGrind SignerCoordinates WrapperLayerPlan WrapperLayerPlanSupport.

op wrapper_empty_layer_plan : wrapper_layer_plan = (0,[],[],[]).
op wrapper_plan_message initial plans k =
  if k=0 then initial else (nth wrapper_empty_layer_plan plans (k-1)).`4.

op wrapper_layer_plan_trace h s seed ht initial signatures plans k =
  size signatures=k /\ size plans=k /\
  forall i, 0<=i<k =>
    wrapper_layer_planned h s seed i (signer_tree ht (i+1)) (signer_tree ht i %%512)
      (Some (nth ([],0,[]) signatures i,(nth wrapper_empty_layer_plan plans i).`4))
      (Some (nth wrapper_empty_layer_plan plans i)) /\
    wrapper_layer_plan_supported h s seed i (signer_tree ht (i+1)) (signer_tree ht i %%512)
      (wrapper_plan_message initial plans i) (nth wrapper_empty_layer_plan plans i).

lemma wrapper_plan_message_rcons initial plans plan i :
  0<=i<=size plans => wrapper_plan_message initial (rcons plans plan) i=wrapper_plan_message initial plans i.
proof. rewrite /wrapper_plan_message nth_rcons; smt(). qed.

lemma wrapper_plan_message_last initial plans plan :
  wrapper_plan_message initial (rcons plans plan) (size plans+1)=plan.`4.
proof. rewrite /wrapper_plan_message nth_rcons; smt(size_ge0). qed.

lemma wrapper_layer_plan_trace_empty h s seed ht initial :
  wrapper_layer_plan_trace h s seed ht initial [] [] 0.
proof. rewrite /wrapper_layer_plan_trace /=; smt(). qed.

lemma wrapper_layer_plan_trace_extends h h' s s' seed ht initial signatures plans k :
  extends h h' => extends s s' =>
  wrapper_layer_plan_trace h s seed ht initial signatures plans k =>
  wrapper_layer_plan_trace h' s' seed ht initial signatures plans k.
proof.
  rewrite /wrapper_layer_plan_trace;
    smt(wrapper_layer_planned_extends wrapper_layer_plan_support_extends).
qed.

lemma wrapper_layer_plan_trace_step h s seed ht initial signatures plans k sig root plan :
  0<=k => wrapper_layer_plan_trace h s seed ht initial signatures plans k =>
  wrapper_layer_planned h s seed k (signer_tree ht (k+1)) (signer_tree ht k %%512)
    (Some (sig,root)) (Some plan) =>
  wrapper_layer_plan_supported h s seed k (signer_tree ht (k+1)) (signer_tree ht k %%512)
    (wrapper_plan_message initial plans k) plan =>
  wrapper_layer_plan_trace h s seed ht initial (rcons signatures sig) (rcons plans plan) (k+1).
proof.
  move=> hk [hs [hp hi]] hv hw.
  have hr : root=plan.`4 by move: hv; rewrite /wrapper_layer_planned; smt().
  rewrite /wrapper_layer_plan_trace !size_rcons hs hp; split; first smt().
  split; first smt().
  move=> i hil.
  rewrite (wrapper_plan_message_rcons initial plans plan i) 1:/# !nth_rcons hs hp.
  case (i=k) => he; smt().
qed.
