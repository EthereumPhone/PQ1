(* Common functional FORS/Merkle values; no sampled-oracle interpretation. *)
require import AllCore List IntDiv StdOrder.
import IntOrder.
require import C10Representation C10RawOracle C10RawGrind RawKeygen.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue.

lemma functional_path_fold f seed layer tree kind kp value index auth steps :
  tree_path_value f seed layer tree kind kp value index auth steps =
    foldl (fun current i => tree_path_step f seed layer tree kind kp auth index current i)
      value (mkseq (fun i => i) steps).
proof. by rewrite /tree_path_value -foldl_rev revK. qed.

lemma functional_path_zero f seed layer tree kind kp value index auth :
  tree_path_value f seed layer tree kind kp value index auth 0 = value.
proof. by rewrite functional_path_fold mkseq0. qed.

lemma functional_path_next f seed layer tree kind kp value index auth n : 0 <= n =>
  tree_path_value f seed layer tree kind kp value index auth (n+1) =
    tree_path_step f seed layer tree kind kp auth index
      (tree_path_value f seed layer tree kind kp value index auth n) n.
proof. by move=> hn; rewrite !functional_path_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_path_parent index h : 0 <= h =>
  (index %/ 2^h) %/ 2 = index %/ 2^(h+1).
proof.
  move=> hh; have hp : 0 <= 2^h by smt(expr_gt0).
  have he : 2^(h+1) = 2^h * 2 by rewrite exprS 1:hh; ring.
  have hd := divz_mul index (2^h) 2 hp.
  by smt().
qed.

lemma functional_fors_recovery_value f seed ht tree target secret auth :
  fors_recover_value f seed ht tree target secret auth =
    tree_path_value f seed 0 ht 3 tree (fors_leaf_value f seed ht tree target secret) target auth 11.
proof. by rewrite /fors_recover_value. qed.

lemma functional_merkle_recovery_value f seed layer tree leaf index auth :
  merkle_recover_value f seed layer tree leaf index auth =
    tree_path_value f seed layer tree 2 0 leaf index auth 9.
proof. by rewrite /merkle_recover_value. qed.

op functional_tree_query f seed layer tree kind kp value index auth h =
  let current = tree_path_value (interpreted_backend f) seed layer tree kind kp value index auth h in
  let sibling = nth (nseq 16 0) auth h in
  let idx = index %/ 2^h in
  pair_preimage seed (address_words layer tree kind kp 0 (h+1) (idx %/ 2))
    (pad_node (if idx %% 2 = 0 then current else sibling))
    (pad_node (if idx %% 2 = 0 then sibling else current)).

lemma functional_tree_step f seed layer tree kind kp value index auth h :
  backend_width f => 0 <= h =>
  node (f (functional_tree_query f seed layer tree kind kp value index auth h)) =
    tree_path_value (interpreted_backend f) seed layer tree kind kp value index auth (h+1).
proof.
  move=> hf hh; rewrite functional_path_next 1:hh /tree_path_step /tree_pair_value.
  by rewrite /functional_tree_query interpreted_node 1:hf.
qed.
