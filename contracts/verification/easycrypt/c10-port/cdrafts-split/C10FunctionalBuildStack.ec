(* Shared node values attached to each live interval of the actual tree stack. *)
require import AllCore List IntDiv StdOrder.
require import C10Representation C10FunctionalBuildValue.
require import C10RawOracle DyadicStack StackProjection StackAlignment CatalogStack NodeGridIndex.
import IntOrder.

op functional_build_node f seed layer tree kind kp total leaves height index =
  nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total height leaves) index.

op functional_build_forest f seed layer tree kind kp total leaves (stack : (raw_input*int) list) n =
  with stack = [] => n = 0
  with stack = entry :: rest =>
    0 <= entry.`2 /\ 2^(entry.`2) %| n /\
    entry.`1 = functional_build_node f seed layer tree kind kp total leaves
      entry.`2 ((n-1) %/ (2^(entry.`2))) /\
    functional_build_forest f seed layer tree kind kp total leaves rest (n-2^(entry.`2)).

lemma functional_build_node_zero f seed layer tree kind kp total leaves i :
  functional_build_node f seed layer tree kind kp total leaves 0 i = nth (nseq 16 0) leaves i.
proof. by rewrite /functional_build_node functional_build_zero. qed.

lemma functional_build_node_next f seed layer tree kind kp total leaves h i :
  0 <= h < total => 0 <= i < 2^(total-(h+1)) =>
  functional_build_node f seed layer tree kind kp total leaves (h+1) i =
    tree_pair_value f seed (address_words layer tree kind kp 0 (h+1) i)
      (functional_build_node f seed layer tree kind kp total leaves h (2*i))
      (functional_build_node f seed layer tree kind kp total leaves h (2*i+1)).
proof.
  move=> hh hi; rewrite /functional_build_node functional_build_next 1:/#.
  by rewrite functional_level_nth 1:/#.
qed.

lemma functional_build_forest_push f seed layer tree kind kp total leaves stack n current h :
  0 <= h => 2^h %| n =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  functional_build_forest f seed layer tree kind kp total leaves ((current,h)::stack) n.
proof. by rewrite /=. qed.

lemma functional_build_forest_pop f seed layer tree kind kp total leaves stack n h :
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  stack <> [] => (head ([],0) stack).`2 = h =>
  0 <= h /\
  (head ([],0) stack).`1 = functional_build_node f seed layer tree kind kp total leaves
    h ((n-2^h-1) %/ (2^h)) /\
  functional_build_forest f seed layer tree kind kp total leaves (behead stack) (n-2^(h+1)).
proof.
  case stack => //= entry rest.
  move=> [#] hh hd hv hr he.
  have hp : 2^(h+1) = 2*2^h by rewrite exprS 1:/#; ring.
  smt().
qed.

lemma functional_build_forest_root f seed layer tree kind kp total leaves stack :
  0 <= total => map snd stack = [total] =>
  functional_build_forest f seed layer tree kind kp total leaves stack (2^total) =>
  (head (nseq 16 0,0) stack).`1 = tree_root_value f seed layer tree kind kp total leaves.
proof.
  case stack => //= entry rest; case rest => [|next tail] //=.
  move=> hh he hf.
  have hp := pow2_pos total hh.
  have hi : (2^total-1) %/ (2^total) = 0 by apply pdiv_small; smt().
  rewrite /tree_root_value /functional_build_node; smt().
qed.

lemma functional_build_pair_children f seed layer tree kind kp total leaves stack n h current :
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = n =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  (head ([],0) stack).`1 = functional_build_node f seed layer tree kind kp total leaves
    h (2*((n-1) %/ (2^(h+1)))) /\
  current = functional_build_node f seed layer tree kind kp total leaves
    h (2*((n-1) %/ (2^(h+1)))+1).
proof.
  move=> ha hs hh hm hf hc.
  have [ha' hm'] := projected_carry_pop stack [] h ha hs hh.
  have hd := active_stack_alignment (map snd (behead stack)) (h+1) n ha' _; first by smt().
  have [hz [hl hr]] := functional_build_forest_pop f seed layer tree kind kp total leaves stack n h hf hs hh.
  have hi := aligned_pair_indices n h hz hd.
  smt().
qed.

lemma functional_build_merge f seed layer tree kind kp total leaves stack n h current :
  0 <= total => 0 < n <= 2^total =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = n =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  tree_pair_value f seed (address_words layer tree kind kp 0 (h+1) ((n-1) %/ (2^(h+1))))
    (head ([],0) stack).`1 current =
      functional_build_node f seed layer tree kind kp total leaves (h+1) ((n-1) %/ (2^(h+1))) /\
  functional_build_forest f seed layer tree kind kp total leaves (behead stack) (n-2^(h+1)).
proof.
  move=> ht hn ha hs hh hm hf hc.
  have hb := projected_carry_height_bound stack [] h n total ht ha hs hh hm _; first by smt().
  have [ha' hm'] := projected_carry_pop stack [] h ha hs hh.
  have hd := active_stack_alignment (map snd (behead stack)) (h+1) n ha' _; first by smt().
  have [hz [hl hr]] := functional_build_forest_pop f seed layer tree kind kp total leaves stack n h hf hs hh.
  have hi := aligned_pair_indices n h hz hd.
  have hp := dyadic_index_range (n-1) (h+1) total _ _; first 2 by smt().
  split; last exact hr.
  rewrite functional_build_node_next 1:hb 1:hp hl hc; smt().
qed.
