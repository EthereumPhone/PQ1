(* Exact falling-factorial and Stirling counts bound the same adaptive
   accepted-pool event, using the existing fixed-assignment law. *)
require import AllCore List Distr DList StdBigop StdOrder Ring.
require import C10RawOracle CountDS AcceptedDigestDistribution AcceptedPrefixSampling.
require import CoverageAssignment SelectedCoverageMass PoolCoverageEvent PoolCoverageBound.
require import BoundedAssignmentWords CanonicalCoverageBound.
require import RestrictedGrowthWords ReverseGrowthEncoding DistinctWitnessWords StirlingPoolWitness StirlingPoolEvent.
import RField RealOrder Bigreal Bigreal.BRA.

op stirling_coverage_charge n = bigi predT
  (fun j => n%r*(falling (n-1) j)%r*(stirling 12 j)%r*(1%r/2%r)^(132+18*j)) 1 13.

lemma stirling_witness_union n j target witnesses :
  0<=n => 0<=j => 0<=target<n => witnesses \in distinct_witness_words n target j =>
  mu (dlist accepted_digest n) (fun nodes => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes) (exact_growth_words 12 j)) <=
    (stirling 12 j)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj ht hw; move: hw; rewrite distinct_witness_words_member 1:hj; move=> [hs [hu hw]].
  have hb := mu_has_leM (fun nodes f => uniq (target::witnesses) /\
    assignment_pool_event target witnesses f nodes) (dlist accepted_digest n) (exact_growth_words 12 j)
    ((1%r/2%r)^(132+18*j)) _.
  + move=> f hf.
    have hfc : mem (exact_growth_words 12 j) f by exact hf.
    have hfa : coverage_assignment (size witnesses) f.
    - have h:=exact_growth_assignment j f hfc; by rewrite hs.
    have hbw : all (fun i=>0<=i<n) (target::witnesses).
    - rewrite /= ht /=; apply/allP=> i hi; move: hw=> /allP hall; have h:=hall i hi; smt().
    have h := guarded_assignment_mass n target witnesses f hn hbw hfa.
    by move: h; rewrite hs.
  by move: hb; rewrite exact_growth_words_size 1:/#.
qed.
lemma stirling_target_union n j target :
  0<=n => 0<=j => 0<=target<n =>
  mu (dlist accepted_digest n) (fun nodes => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (exact_growth_words 12 j)) (distinct_witness_words n target j)) <=
    (falling (n-1) j)%r*((stirling 12 j)%r*(1%r/2%r)^(132+18*j)).
proof.
  move=> hn hj ht; have hb := mu_has_leM (fun nodes witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (exact_growth_words 12 j)) (dlist accepted_digest n) (distinct_witness_words n target j)
    ((stirling 12 j)%r*(1%r/2%r)^(132+18*j)) _.
  + move=> witnesses hw; exact (stirling_witness_union n j target witnesses hn hj ht hw).
  by move: hb; rewrite distinct_witness_words_size //.
qed.
lemma stirling_j_union n j : 0<=n => 0<=j =>
  mu (dlist accepted_digest n) (stirling_pool_j n j) <=
    n%r*(falling (n-1) j)%r*(stirling 12 j)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj; have hb := mu_has_leM (fun nodes target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (exact_growth_words 12 j)) (distinct_witness_words n target j)) (dlist accepted_digest n) (range 0 n)
    ((falling (n-1) j)%r*((stirling 12 j)%r*(1%r/2%r)^(132+18*j))) _.
  + move=> target ht; apply stirling_target_union=> //; by move: ht; rewrite mem_range.
  by move: hb; rewrite size_range /= (: max 0 n=n) 1:/# /stirling_pool_j !mulrA.
qed.
lemma iid_stirling_coverage_bound n : 0<=n =>
  mu (dlist accepted_digest n) stirling_pool_coverage <= stirling_coverage_charge n.
proof.
  move=> hn.
  have he : mu (dlist accepted_digest n) stirling_pool_coverage=
    mu (dlist accepted_digest n) (stirling_pool_enumerated n).
  + apply mu_eq_support=> nodes hs; apply stirling_pool_enumeration.
    exact (supp_dlist_size accepted_digest n nodes hn hs).
  rewrite he /stirling_pool_enumerated /stirling_coverage_charge.
  apply (ler_trans (bigi predT (fun j => mu (dlist accepted_digest n) (stirling_pool_j n j)) 1 13)).
  + exact (mu_has_le (fun nodes j => stirling_pool_j n j nodes) (dlist accepted_digest n) (range 1 13)).
  apply ler_sum_seq=> j /mem_range hj /=.
  move=> _; apply stirling_j_union=> //; smt().
qed.
lemma adaptive_stirling_coverage_bound (A <: AcceptedClient {-AcceptedSamples}) n &m :
  0<=n => Pr[AcceptedGame(A).run() @ &m : size AcceptedSamples.nodes<=n /\ stirling_pool_coverage AcceptedSamples.nodes]
    <= stirling_coverage_charge n.
proof.
  move=> hn; apply (ler_trans (mu (dlist accepted_digest n) stirling_pool_coverage)).
  + exact (accepted_adaptive_prefix A n stirling_pool_coverage &m hn stirling_pool_extension).
  exact (iid_stirling_coverage_bound n hn).
qed.

lemma stirling_coverage_charge_tighter n :
  0<=n => stirling_coverage_charge n<=canonical_coverage_charge n.
proof.
  move=> hn; rewrite /stirling_coverage_charge /canonical_coverage_charge.
  apply ler_sum_seq=> j /mem_range hj /= _.
  have hj0 : 0<=j by smt().
  have hc:=stirling_canonical_upper j.
  have hf:=falling_upper (n-1) n j hj0 hn _; first smt().
  have hfn:=falling_nonnegative (n-1) j hj0.
  have hnp : 0<=n^j by apply IntOrder.expr_ge0.
  have hp : 0%r<=(1%r/2%r)^(132+18*j) by apply expr_ge0; smt().
  have hcr : 0%r<=(stirling 12 j)%r /\
      (stirling 12 j)%r<=(canonical_assignment_count j)%r by smt().
  have hfr : 0%r<=(falling (n-1) j)%r /\
      (falling (n-1) j)%r<=(n^j)%r by smt().
  apply ler_wpmul2r; first exact hp.
  rewrite -!mulrA.
  apply ler_wpmul2l; first smt().
  apply ler_pmul; smt().
qed.
