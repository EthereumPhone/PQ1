(* Exact distinct-witness and restricted-growth enumerators preserve the
   existing pool coverage event in both directions. *)
require import AllCore List Distr.
require import C10RawOracle CountDS AcceptedCoordinateLaw AcceptedPrefixSampling.
require import CoverageAssignment SelectedCoverageMass PoolCoverageEvent CoverageWitnessCompression.
require import BoundedAssignmentWords CanonicalPoolWitness CanonicalPoolEvent.
require import RestrictedGrowthWords ReverseGrowthEncoding DistinctWitnessWords StirlingPoolWitness.

op stirling_pool_j n j (nodes : digest list) =
  has (fun target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (exact_growth_words 12 j)) (distinct_witness_words n target j)) (range 0 n).
op stirling_pool_enumerated n (nodes : digest list) =
  has (fun j => stirling_pool_j n j nodes) (range 1 13).

lemma exact_growth_assignment j f :
  mem (exact_growth_words 12 j) f => coverage_assignment j f.
proof.
  rewrite exact_growth_words_member 1:/#; move=> [hs [hw hj]].
  have hc:=growth_is_canonical f j hs hw hj.
  exact (canonical_assignment_ordinary j f hc).
qed.

lemma pool_coverage_stirling nodes : pool_coverage nodes=stirling_pool_coverage nodes.
proof.
  rewrite eq_iff; split.
  + move=> [t w f [hj [hu [hb [hf he]]]]].
    move: hb=> /= [ht hw]; apply (coordinate_witness_stirling_pool nodes t ht)=> i hi.
    have hfi : 0<=nth 0 f i<size w.
    - have hm : mem f (nth 0 f i) by apply mem_nth; smt().
      move: hf=> [hs /allP hall]; have h:=hall _ hm; by move: h; rewrite /is_digit.
    pose k := nth 0 w (nth 0 f i).
    have hkm : mem w k by exact (mem_nth _ _ _ hfi).
    have hk : 0<=k<size nodes by move: hw=> /allP; apply.
    have hkt : k<>t by move: hu=> /=; smt().
    have [hcoord hht] := he (nth 0 f i) hfi.
    have hc := hcoord i hi _; first by [].
    exists k; rewrite /coordinate_witness; smt().
  move=> [t w f [hj [hu [hb [hf he]]]]]; exists t w f.
  have hfa:=exact_growth_assignment _ _ hf; smt().
qed.

lemma stirling_pool_enumeration n nodes : size nodes=n =>
  stirling_pool_coverage nodes=stirling_pool_enumerated n nodes.
proof.
  move=> hn; rewrite /stirling_pool_coverage /stirling_pool_enumerated hasP eq_iff; split.
  + move=> [t w f [hj [hu [hb [hf he]]]]].
    exists (size w); rewrite mem_range /=; split; first smt().
    rewrite /stirling_pool_j hasP; exists t; rewrite mem_range /=.
    move: hb=> /= [ht hw]; split; first smt().
    rewrite hasP; exists w; rewrite distinct_witness_words_member 1:size_ge0 /=.
    split.
    - split; first smt().
      apply/allP=> x hx; move: hw=> /allP hw.
      have hb:=hw x hx; smt().
    rewrite hasP; exists f; smt().
  move=> [j [hj he]]; move: hj; rewrite mem_range=> hj.
  move: he; rewrite /= /stirling_pool_j hasP; move=> [t [ht he]].
  move: he; rewrite /= hasP; move=> [w [hw he]].
  move: he; rewrite /= hasP; move=> [f [hf he]].
  move: ht; rewrite mem_range=> ht.
  move: hw; rewrite distinct_witness_words_member 1:/#; move=> [hs [hu hw]].
  have hb : all (fun x=>0<=x<size nodes) (t::w).
  + rewrite /= hn ht /=; apply/allP=> x hx.
    move: hw=> /allP hw; have h:=hw x hx; smt().
  exists t w f; rewrite hs /=; smt().
qed.

lemma stirling_pool_extension : extension_closed stirling_pool_coverage.
proof.
  move=> nodes more; rewrite -!pool_coverage_stirling.
  exact (pool_coverage_extension nodes more).
qed.
