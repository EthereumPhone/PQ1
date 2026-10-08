(* Canonical reindexing retains the coverage event and removes redundant
   assignment choices. Witnesses are in reverse last-occurrence order. *)
require import AllCore List Distr.
require import C10RawOracle CountDS AcceptedCoordinateLaw CoverageAssignment SelectedCoverageMass.
require import CoverageWitnessCompression CanonicalWitnessIndices BoundedAssignmentWords PoolCoverageEvent.

op canonical_pool_coverage (nodes : digest list) =
  exists target witnesses f,
    1<=size witnesses<=12 /\ uniq (target::witnesses) /\
    all (fun i=>0<=i<size nodes) (target::witnesses) /\
    canonical_assignment (size witnesses) f /\ assignment_pool_event target witnesses f nodes.

lemma coordinate_witness_canonical_pool nodes target :
  0<=target<size nodes =>
  (forall i, 0<=i<12 => exists k, coordinate_witness nodes target i k) => canonical_pool_coverage nodes.
proof.
  move=> ht hc.
  pose pick := selected_position nodes target.
  have hp : forall i, 0<=i<12 => coordinate_witness nodes target i (pick i).
  + move=> i hi; exact (selected_position_spec nodes target i (hc i hi)).
  pose positions := mkseq pick 12.
  pose witnesses := rev (undup positions).
  pose assignment := mkseq (fun i => index (pick i) witnesses) 12.
  have hs : size positions=12 by rewrite /positions size_mkseq.
  have hm : forall k, mem witnesses k => exists i, 0<=i<12 /\ k=pick i.
  + move=> k; rewrite /witnesses mem_rev mem_undup /positions mkseqP; smt().
  have hm0 : mem witnesses (pick 0) by rewrite /witnesses mem_rev mem_undup /positions mkseqP; exists 0; smt().
  have hnon : witnesses<>[] by smt().
  have hws : 1<=size witnesses<=12.
  + have h1 := size_undup positions.
    have hwsize : size witnesses=size (undup positions) by rewrite /witnesses size_rev.
    smt(size_ge0 size_eq0).
  have hwb : all (fun k=>0<=k<size nodes /\ k<>target) witnesses.
  + apply/allP=> k hk; have [i [hi he]] := hm k hk; have h:=hp i hi; smt().
  have hpm : forall i, 0<=i<12 => mem witnesses (pick i).
  + move=> i hi; rewrite /witnesses mem_rev mem_undup /positions mkseqP; exists i; smt().
  have hfa : coverage_assignment (size witnesses) assignment.
  + rewrite /coverage_assignment /assignment size_mkseq /=; split=> //.
    apply/allP=> g /mkseqP [i [hi ->]]; rewrite /is_digit; smt(index_ge0 index_mem).
  have hcanon : canonical_assignment (size witnesses) assignment.
  + rewrite canonical_assignment_shape; split.
    - by rewrite /assignment size_mkseq.
    move=> i hi; rewrite /assignment nth_mkseq // /=.
    have hmem := hpm i hi.
    have hindex := reverse_undup_index 0 positions i _.
    - by rewrite hs.
    have hpos : nth 0 positions i=pick i by rewrite /positions nth_mkseq.
    have hbound : 0<=index (pick i) witnesses<size witnesses by smt(index_ge0 index_mem).
    smt().
  exists target witnesses assignment; split=> //; split.
  + rewrite /= /witnesses rev_uniq undup_uniq /=; smt(allP).
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
