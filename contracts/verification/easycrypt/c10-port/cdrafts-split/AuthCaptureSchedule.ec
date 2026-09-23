(* The unique parent merge at which a target's sibling becomes available. *)
require import AllCore List IntDiv.
require import DyadicStack StackAlignment NodeGridIndex NodeCatalogDomain.

op target_pair_edge target level =
  node_right_edge (level+1) (target %/ (2^(level+1))).
op pair_captured n height target level =
  target_pair_edge target level < n \/
    (target_pair_edge target level = n /\ level < height).

lemma pair_capture_start n target level :
  0 <= level =>
  pair_captured (n+1) 0 target level <=> target_pair_edge target level <= n.
proof. rewrite /pair_captured; smt(). qed.

lemma pair_capture_next n height target level :
  pair_captured n (height+1) target level <=>
  pair_captured n height target level \/
    (level = height /\ target_pair_edge target level = n).
proof. rewrite /pair_captured; smt(). qed.

lemma pair_capture_finish heights height n target level :
  0 <= level => active_stack heights height =>
  (heights = [] \/ head 0 heights <> height) =>
  stack_mass heights + 2^height = n =>
  (pair_captured n height target level <=> target_pair_edge target level <= n).
proof.
  move=> hl ha hx hn.
  have he : target_pair_edge target level = n => level < height.
  + move=> hp.
    have hd : 2^(level+1) %| n.
    - rewrite -hp /target_pair_edge; apply node_edge_divisible.
    have hh := finished_stack_maximal heights height n (level+1) ha hx hn _ hd;
      smt().
  rewrite /pair_captured; smt().
qed.

lemma pair_capture_matches n height target :
  0 <= height => 2^(height+1) %| n =>
  (target_pair_edge target height = n <=>
    target %/ (2^(height+1)) = (n-1) %/ (2^(height+1))).
proof.
  move=> hh hd.
  have he := node_index_edge n (height+1) _ hd; first by smt().
  have hi := node_edge_index (height+1) (target %/ (2^(height+1))) n _;
    first by smt().
  rewrite /target_pair_edge; smt().
qed.

lemma pair_capture_final total target level :
  0 <= level < total => 0 <= target < 2^total =>
  target_pair_edge target level <= 2^total.
proof.
  move=> hl ht.
  have hi := dyadic_index_range target (level+1) total _ ht; first by smt().
  have hn := node_due_range total (level+1) (target %/ (2^(level+1))) _ hi;
    first by smt().
  move: hn; rewrite /node_due /target_pair_edge; smt().
qed.
