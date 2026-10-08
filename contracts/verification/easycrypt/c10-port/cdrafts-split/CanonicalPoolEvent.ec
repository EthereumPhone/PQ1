(* Canonical coverage is exactly the existing event, with fewer assignments. *)
require import AllCore List Distr.
require import C10RawOracle CountDS AcceptedCoordinateLaw AcceptedPrefixSampling.
require import CoverageAssignment SelectedCoverageMass PoolCoverageEvent CoverageWitnessCompression.
require import BoundedAssignmentWords CanonicalPoolWitness.

op canonical_pool_j n j (nodes : digest list) =
  has (fun target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (canonical_words j)) (words j n)) (range 0 n).
op canonical_pool_enumerated n (nodes : digest list) =
  has (fun j => canonical_pool_j n j nodes) (range 1 13).

lemma canonical_assignment_ordinary j f : canonical_assignment j f => coverage_assignment j f.
proof.
  rewrite canonical_assignment_shape /coverage_assignment.
  move=> [hs hf]; split=> //.
  apply/allP=> g hg.
  have hi : 0<=index g f<12 by smt(index_ge0 index_mem).
  have h:=hf (index g f) hi.
  rewrite (nth_index 0 g f hg) in h;
  rewrite /is_digit; smt().
qed.
lemma pool_coverage_canonical nodes : pool_coverage nodes=canonical_pool_coverage nodes.
proof.
  rewrite eq_iff; split.
  + move=> [t w f [hj [hu [hb [hf he]]]]].
    move: hb=> /= [ht hw]; apply (coordinate_witness_canonical_pool nodes t ht)=> i hi.
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
  have hfa:=canonical_assignment_ordinary _ _ hf; smt().
qed.
lemma canonical_pool_enumeration n nodes : size nodes=n =>
  canonical_pool_coverage nodes=canonical_pool_enumerated n nodes.
proof.
  move=> hn; rewrite /canonical_pool_coverage /canonical_pool_enumerated hasP eq_iff; split.
  + move=> [t w f [hj [hu [hb [hf he]]]]].
    exists (size w); rewrite mem_range /=; split; first smt().
    rewrite /canonical_pool_j hasP; exists t; rewrite mem_range /=.
    move: hb=> /= [ht hw]; split; first smt().
    rewrite hasP; exists w; rewrite mem_words 1:size_ge0 /= /is_digit.
    split; first by smt().
    rewrite hasP; exists f; rewrite canonical_words_member; smt().
  move=> [j [hj he]]; move: hj; rewrite mem_range=> hj.
  move: he; rewrite /= /canonical_pool_j hasP.
  move=> [t [ht he]].
  move: he; rewrite /= hasP.
  move=> [w [hw he]].
  move: he; rewrite /= hasP.
  move=> [f [hf he]].
  move: ht hw hf; rewrite mem_range (mem_words j n _) 1:/# /is_digit canonical_words_member=> ht [hs hw] hf.
  exists t w f; rewrite hs /=; smt().
qed.
lemma canonical_pool_extension : extension_closed canonical_pool_coverage.
proof.
  move=> nodes more; rewrite -!pool_coverage_canonical.
  exact (pool_coverage_extension nodes more).
qed.
