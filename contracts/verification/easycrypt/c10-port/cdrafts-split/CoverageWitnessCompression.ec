(* Coordinate-wise coverage yields at most twelve distinct witness positions. *)
require import AllCore List Distr.
require import C10RawOracle AcceptedCoordinateLaw CoverageAssignment SelectedCoverageMass PoolCoverageEvent.

op coordinate_witness (nodes : digest list) target i k =
  0<=k<size nodes /\ k<>target /\
  take 18 (drop 143 (nth [] nodes k))=take 18 (drop 143 (nth [] nodes target)) /\
  take 11 (drop (11*i) (nth [] nodes k))=take 11 (drop (11*i) (nth [] nodes target)).
op selected_position nodes target i =
  nth 0 (range 0 (size nodes)) (find (coordinate_witness nodes target i) (range 0 (size nodes))).
lemma selected_position_spec nodes target i :
  (exists k, coordinate_witness nodes target i k) =>
  coordinate_witness nodes target i (selected_position nodes target i).
proof.
  move=> [k hk]; rewrite /selected_position;
    apply (nth_find 0 (coordinate_witness nodes target i) (range 0 (size nodes))); apply/hasP.
  exists k; rewrite mem_range; smt().
qed.
lemma coordinate_witness_pool nodes target :
  0<=target<size nodes =>
  (forall i, 0<=i<12 => exists k, coordinate_witness nodes target i k) => pool_coverage nodes.
proof.
  move=> ht hc.
  pose pick := selected_position nodes target.
  have hp : forall i, 0<=i<12 => coordinate_witness nodes target i (pick i).
  + move=> i hi; exact (selected_position_spec nodes target i (hc i hi)).
  pose positions := mkseq pick 12.
  pose witnesses := undup positions.
  pose assignment := mkseq (fun i => index (pick i) witnesses) 12.
  have hs : size positions=12 by rewrite /positions size_mkseq.
  have hm : forall k, mem witnesses k => exists i, 0<=i<12 /\ k=pick i.
  + move=> k; rewrite /witnesses mem_undup /positions mkseqP; smt().
  have hm0 : mem witnesses (pick 0) by rewrite /witnesses mem_undup /positions mkseqP; exists 0; smt().
  have hnon : witnesses<>[] by smt().
  have hws : 1<=size witnesses<=12 by
    have h1 := size_undup positions; smt(size_ge0 size_eq0).
  have hwb : all (fun k=>0<=k<size nodes /\ k<>target) witnesses.
  + apply/allP=> k hk; have [i [hi he]] := hm k hk; have h:=hp i hi; smt().
  have hpm : forall i, 0<=i<12 => mem witnesses (pick i).
  + move=> i hi; rewrite /witnesses mem_undup /positions mkseqP; exists i; smt().
  have hfa : coverage_assignment (size witnesses) assignment.
  + rewrite /coverage_assignment /assignment size_mkseq /=; split=> //.
    apply/allP=> g /mkseqP [i [hi ->]]; rewrite /is_digit; smt(index_ge0 index_mem).
  exists target witnesses assignment; split=> //; split.
  + rewrite /= /witnesses undup_uniq /=; smt(allP).
  split.
  + rewrite /= ht /=; apply/allP=> k hk; move: hwb=> /allP h; smt().
  split=> //; rewrite /assignment_pool_event=> g hg.
  have hgm : mem witnesses (nth 0 witnesses g) by exact (mem_nth _ _ _ hg).
  have [u [hu heu]] := hm _ hgm.
  have hwu := hp u hu.
  rewrite /group_event; split; last by smt().
  rewrite /coordinate_predicate /group_coordinate=> i hi hgi.
  have hfgi : index (pick i) witnesses=g by move: hgi; rewrite /assignment nth_mkseq //.
  have hki : nth 0 witnesses g=pick i by rewrite -hfgi nth_index 1:(hpm i hi).
  have hwi := hp i hi; smt().
qed.
