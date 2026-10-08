(* Returned component counters justify a selected opening in persistent tables. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawLayer.
require import PersistentGrind ForestRootWitness MerkleRootWitness ObservedWotsOpening.

op bottom_cut_opened h s seed ht (layers : layer_signature list) index cut =
  exists forest, forest_root_witness h s seed ht forest /\
    opened_wots_count h seed 0 (ht %/512) (ht %%512) forest (nth ([],0,[]) layers 0).`2 index cut.
op top_cut_opened h s seed ht (layers : layer_signature list) index cut =
  exists lower, merkle_root_witness h s seed 0 (ht %/512) lower /\
    opened_wots_count h seed 1 0 (ht %/512) lower (nth ([],0,[]) layers 1).`2 index cut.
op signed_cut_opened h s seed ht layers layer tree kp index cut =
  (layer=0 /\ tree=ht %/512 /\ kp=ht %%512 /\ bottom_cut_opened h s seed ht layers index cut) \/
  (layer=1 /\ tree=0 /\ kp=ht %/512 /\ top_cut_opened h s seed ht layers index cut).

lemma bottom_cut_opened_extends h h' s s' seed ht layers index cut :
  extends h h' => extends s s' => bottom_cut_opened h s seed ht layers index cut =>
  bottom_cut_opened h' s' seed ht layers index cut.
proof. rewrite /bottom_cut_opened; smt(forest_root_witness_extends opened_wots_count_extends). qed.
lemma top_cut_opened_extends h h' s s' seed ht layers index cut :
  extends h h' => extends s s' => top_cut_opened h s seed ht layers index cut =>
  top_cut_opened h' s' seed ht layers index cut.
proof. rewrite /top_cut_opened; smt(merkle_root_witness_extends opened_wots_count_extends). qed.
lemma signed_cut_opened_extends h h' s s' seed ht layers layer tree kp index cut :
  extends h h' => extends s s' => signed_cut_opened h s seed ht layers layer tree kp index cut =>
  signed_cut_opened h' s' seed ht layers layer tree kp index cut.
proof. rewrite /signed_cut_opened; smt(bottom_cut_opened_extends top_cut_opened_extends). qed.

lemma bottom_cut_first h h' s s' seed ht layers forest (signature : layer_signature) index cut :
  extends h h' => extends s s' => size layers=0 =>
  forest_root_witness h s seed ht forest =>
  opened_wots_count h' seed 0 (ht %/512) (ht %%512) forest signature.`2 index cut =>
  bottom_cut_opened h' s' seed ht (rcons layers signature) index cut.
proof.
  move=> hh hs hl hf ho; exists forest; rewrite nth_rcons hl /=;
    smt(forest_root_witness_extends).
qed.
lemma bottom_cut_append h h' s s' seed ht layers signature index cut :
  extends h h' => extends s s' => 1<=size layers => bottom_cut_opened h s seed ht layers index cut =>
  bottom_cut_opened h' s' seed ht (rcons layers signature) index cut.
proof.
  move=> hh hs hl [forest [hf ho]]; exists forest; rewrite nth_rcons; smt(forest_root_witness_extends opened_wots_count_extends).
qed.
lemma top_cut_second h h' s s' seed ht layers lower (signature : layer_signature) index cut :
  extends h h' => extends s s' => size layers=1 =>
  merkle_root_witness h s seed 0 (ht %/512) lower =>
  opened_wots_count h' seed 1 0 (ht %/512) lower signature.`2 index cut =>
  top_cut_opened h' s' seed ht (rcons layers signature) index cut.
proof.
  move=> hh hs hl hf ho; exists lower; rewrite nth_rcons hl /=;
    smt(merkle_root_witness_extends).
qed.
