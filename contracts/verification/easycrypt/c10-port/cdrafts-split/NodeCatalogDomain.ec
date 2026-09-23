require import AllCore List FMap IntDiv StdOrder.
require import C10RawOracle DyadicStack StackAlignment NodeCatalog.
import IntOrder.

op node_right_edge level index = (index+1)*2^level.
op node_due n level index =
  0 <= level /\ 0 <= index /\ node_right_edge level index <= n.
op node_due_through n height level index =
  node_due n level index /\
  (node_right_edge level index < n \/ level <= height).
op catalog_exact (c : node_catalog) n =
  forall level index, (level,index) \in c <=> node_due n level index.
op catalog_partial (c : node_catalog) n height =
  forall level index, (level,index) \in c <=> node_due_through n height level index.

lemma node_edge_index level index n :
  0 <= level => node_right_edge level index = n =>
  (n-1) %/ (2^level) = index.
proof.
  move=> hl; rewrite /node_right_edge => <-.
  have hp := pow2_pos level hl.
  rewrite (_ : (index+1)*2^level-1 = index*2^level+(2^level-1)) 1:/#.
  rewrite edivz_eq // ger0_norm; smt().
qed.

lemma node_index_edge n level :
  0 <= level => 2^level %| n =>
  node_right_edge level ((n-1) %/ (2^level)) = n.
proof.
  move=> hl hd.
  have hp := pow2_pos level hl.
  have hn := divzK (2^level) n hd.
  have hi : n-1 = (n %/ (2^level)-1)*2^level+(2^level-1) by smt().
  rewrite /node_right_edge hi edivz_eq // ger0_norm; smt().
qed.

lemma node_edge_positive level index :
  0 <= level => 0 <= index => 0 < node_right_edge level index.
proof. rewrite /node_right_edge; smt(pow2_pos). qed.

lemma catalog_exact_empty : catalog_exact empty 0.
proof.
  rewrite /catalog_exact /node_due; smt(mem_empty node_edge_positive).
qed.

lemma catalog_partial_leaf c n value :
  0 <= n => catalog_exact c n =>
  catalog_partial c.[(0,n) <- value] (n+1) 0.
proof.
  move=> hn hc; rewrite /catalog_partial /node_due_through /node_due.
  move=> level index; rewrite mem_set.
  have he := hc level index.
  move: he; rewrite /node_due /node_right_edge.
  case (level = 0) => hl.
  + rewrite hl expr0 /=; smt().
  smt().
qed.

lemma catalog_partial_next c n height value :
  0 < n => 0 <= height => 2^(height+1) %| n =>
  catalog_partial c n height =>
  catalog_partial c.[(height+1,(n-1) %/ (2^(height+1))) <- value] n (height+1).
proof.
  move=> hn hh hd hc.
  have he := node_index_edge n (height+1) _ hd; first by smt().
  have hi : 0 <= (n-1) %/ (2^(height+1)).
  + rewrite divz_ge0; smt(pow2_pos).
  rewrite /catalog_partial /node_due_through /node_due.
  move=> level index; rewrite mem_set.
  have ho := hc level index.
  have hu : node_right_edge level index = n => 0 <= level =>
    index = (n-1) %/ (2^level) by smt(node_edge_index).
  move: ho; rewrite /node_due_through /node_due; smt().
qed.

lemma catalog_partial_fresh c n height :
  0 <= height => 2^(height+1) %| n => catalog_partial c n height =>
  (height+1,(n-1) %/ (2^(height+1))) \notin c.
proof.
  move=> hh hd hc.
  have he := node_index_edge n (height+1) _ hd; first by smt().
  have ho := hc (height+1) ((n-1) %/ (2^(height+1))).
  move: ho; rewrite /node_due_through /node_due; smt().
qed.

lemma catalog_leaf_fresh c n :
  catalog_exact c n => (0,n) \notin c.
proof.
  move=> hc; have ho := hc 0 n.
  move: ho; rewrite /node_due /node_right_edge expr0; smt().
qed.

lemma node_edge_divisible level index : 2^level %| node_right_edge level index.
proof. rewrite /node_right_edge; apply dvdz_mull; apply dvdzz. qed.

lemma catalog_partial_finish c heights height n :
  active_stack heights height =>
  (heights = [] \/ head 0 heights <> height) =>
  stack_mass heights + 2^height = n =>
  catalog_partial c n height => catalog_exact c n.
proof.
  move=> ha hx hn hc; rewrite /catalog_exact.
  move=> level index.
  have ho := hc level index.
  have hm : 0 <= level => node_right_edge level index = n => level <= height.
  + move=> hl he.
    have hd : 2^level %| n by rewrite -he; apply node_edge_divisible.
    exact (finished_stack_maximal heights height n level ha hx hn hl hd).
  move: ho; rewrite /node_due_through /node_due; smt().
qed.

lemma node_due_range total level index :
  0 <= level <= total => 0 <= index < 2^(total-level) =>
  node_due (2^total) level index.
proof.
  move=> hl hi.
  have hp := pow2_pos level _; first by smt().
  have he : 2^total = 2^(total-level)*2^level.
  + rewrite -exprD_nneg 1,2:/#; smt().
  rewrite /node_due /node_right_edge; smt().
qed.
