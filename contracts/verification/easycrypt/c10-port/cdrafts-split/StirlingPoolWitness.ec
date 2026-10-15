(* Every covered coordinate has a canonical restricted-growth label.
   Normalization preserves the actual selected witness and digest equalities. *)
require import AllCore List Distr.
require import C10RawOracle CountDS AcceptedCoordinateLaw CoverageAssignment SelectedCoverageMass.
require import CoverageWitnessCompression RestrictedGrowthWords ReverseGrowthEncoding PoolCoverageEvent.

op stirling_pool_coverage (nodes : digest list) =
  exists target witnesses f,
    1<=size witnesses<=12 /\ uniq (target::witnesses) /\
    all (fun i=>0<=i<size nodes) (target::witnesses) /\
    mem (exact_growth_words 12 (size witnesses)) f /\ assignment_pool_event target witnesses f nodes.

lemma coordinate_witness_stirling_pool nodes target :
  0<=target<size nodes =>
  (forall i, 0<=i<12 => exists k, coordinate_witness nodes target i k) => stirling_pool_coverage nodes.
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
  have hcanon : mem (exact_growth_words 12 (size witnesses)) assignment.
  + have he : assignment=reverse_labels positions.
    - by rewrite /assignment /reverse_labels /witnesses /positions map_mkseq /(\o) /=.
    rewrite he exact_growth_words_member 1:/# reverse_labels_size hs.
    have hh:=reverse_labels_growth positions.
    have hwsize : size witnesses=size (undup positions) by rewrite /witnesses size_rev.
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
