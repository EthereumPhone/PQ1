(* The shuffled actual forest builder accumulates complete per-tree references. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawWidths PersistentGrind.
require import ForsRootWitness ForestRootWitness ForestWitness.

op forest_root_prefix h s seed ht roots visited =
  rows_width 13 roots /\ forall t, mem visited t =>
    fors_root_witness h s seed ht t (nth (nseq 16 0) roots t).

lemma forest_root_prefix_extends h h' s s' seed ht roots visited :
  extends h h' => extends s s' => forest_root_prefix h s seed ht roots visited =>
  forest_root_prefix h' s' seed ht roots visited.
proof. rewrite /forest_root_prefix; smt(fors_root_witness_extends). qed.

lemma forest_root_prefix_empty h s seed ht :
  forest_root_prefix h s seed ht (nseq 13 (nseq 16 0)) [].
proof. rewrite /forest_root_prefix /=; smt(rows_zeros). qed.

lemma forest_root_prefix_step h s seed ht roots visited t root :
  0<=t<12 => forest_root_prefix h s seed ht roots visited =>
  fors_root_witness h s seed ht t root =>
  forest_root_prefix h s seed ht (put roots t root) (rcons visited t).
proof.
  move=> hi [hw hp] hr; split; first by smt(rows_put fors_root_witness_width).
  move=> i; rewrite mem_rcons nth_put; first by move: hw; rewrite /rows_width; smt().
  smt().
qed.

lemma forest_root_prefix_complete h s seed ht roots order :
  perm_eq order (range 0 12) => forest_root_prefix h s seed ht roots (take 12 order) =>
  forest_root_prefix h s seed ht roots (range 0 12).
proof. rewrite /forest_root_prefix; smt(perm_eq_size size_range take_size perm_eq_mem). qed.

lemma forest_root_special h s seed ht roots lastroot special :
  forest_root_prefix h s seed ht roots (range 0 12) =>
  fors_root_witness h s seed ht 12 lastroot =>
  h.[forest_special_input seed ht lastroot]=Some special =>
  rows_width 13 (put roots 12 (node special)) /\
  (forall t, 0<=t<12 => fors_root_witness h s seed ht t (nth (nseq 16 0) (put roots 12 (node special)) t)) /\
  fors_root_witness h s seed ht 12 lastroot /\
  h.[forest_special_input seed ht lastroot]=Some special /\
  nth (nseq 16 0) (put roots 12 (node special)) 12=node special.
proof.
  move=> [hw hp] hl hd; split; first smt(rows_put node_width).
  split.
  + move=> t hi; rewrite nth_put; first by move: hw; rewrite /rows_width; smt().
    smt(mem_range).
  rewrite nth_put; first by move: hw; rewrite /rows_width; smt().
  smt().
qed.
