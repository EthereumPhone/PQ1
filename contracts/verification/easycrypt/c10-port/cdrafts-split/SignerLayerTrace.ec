(* Stored layer signatures connect each successive message/root in the trace. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawLayer RawForest.
require import PersistentGrind LayerSignOpening LayerOpeningReplay SignerCoordinates.

op signer_layer_trace public private seed ht layers values k =
  size layers=k /\ size values=k+1 /\
  forall i, 0<=i<k => layer_opening public private seed i (signer_tree ht (i+1))
    (signer_tree ht i %%512) (nth [] values i) (nth ([],0,[]) layers i) (nth [] values (i+1)).

lemma signer_trace_empty public private seed ht value :
  signer_layer_trace public private seed ht [] [value] 0.
proof. rewrite /signer_layer_trace /=; smt(). qed.

lemma signer_trace_extends public public' private private' seed ht layers values k :
  extends public public' => extends private private' =>
  signer_layer_trace public private seed ht layers values k =>
  signer_layer_trace public' private' seed ht layers values k.
proof.
  rewrite /signer_layer_trace; move=> hh hs [hl [hv ho]]; split; first exact hl.
  split; first exact hv.
  move=> i hi; exact (layer_opening_extends public public' private private' seed i
    (signer_tree ht (i+1)) (signer_tree ht i %%512) (nth [] values i)
    (nth ([],0,[]) layers i) (nth [] values (i+1)) hh hs (ho i hi)).
qed.

lemma signer_trace_step public private seed ht layers values k signature root :
  0<=k => signer_layer_trace public private seed ht layers values k =>
  layer_opening public private seed k (signer_tree ht (k+1))
    (signer_tree ht k %%512) (nth [] values k) signature root =>
  signer_layer_trace public private seed ht (rcons layers signature) (rcons values root) (k+1).
proof.
  rewrite /signer_layer_trace; move=> hk [hl [hv ho]] hn.
  rewrite !size_rcons hl hv; split; first smt().
  split; first smt().
  move=> i hi.
  rewrite !nth_rcons hl hv; case: (i=k) => he; smt().
qed.
