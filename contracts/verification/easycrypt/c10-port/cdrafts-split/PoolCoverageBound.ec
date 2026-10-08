(* Conservative finite union charge for arbitrary accepted-pool coverage. *)
require import AllCore List Distr DList StdBigop StdOrder Ring.
require import C10RawOracle CountDS AcceptedDigestDistribution AcceptedPrefixSampling.
require import CoverageAssignment SelectedCoverageMass PoolCoverageEvent.
import RField RealOrder Bigreal Bigreal.BRA.

op coverage_charge n = bigi predT
  (fun j => n%r*(n^j)%r*(j^12)%r*(1%r/2%r)^(132+18*j)) 1 13.

lemma guarded_assignment_mass n target witnesses f :
  0<=n => all (fun i=>0<=i<n) (target::witnesses) => coverage_assignment (size witnesses) f =>
  mu (dlist accepted_digest n) (fun nodes => uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    <= (1%r/2%r)^(132+18*size witnesses).
proof.
  move=> hn hb hf; case (uniq (target::witnesses))=> hu /=.
  + rewrite (selected_assignment_mass n target witnesses f hn hu hb hf); smt().
  rewrite mu0; apply expr_ge0; smt().
qed.
lemma pool_witness_union n j target witnesses :
  0<=n => 0<=j => 0<=target<n => witnesses \in words j n =>
  mu (dlist accepted_digest n) (fun nodes => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes) (words 12 j)) <=
    (j^12)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj ht hw; move: hw; rewrite mem_words // /is_digit; move=> [hs hw].
  have hb := mu_has_leM (fun nodes f => uniq (target::witnesses) /\
    assignment_pool_event target witnesses f nodes) (dlist accepted_digest n) (words 12 j)
    ((1%r/2%r)^(132+18*j)) _.
  + move=> f hf.
    have hfa : coverage_assignment (size witnesses) f by
      move: hf; rewrite mem_words // /coverage_assignment hs; smt().
    have hbw : all (fun i=>0<=i<n) (target::witnesses) by smt().
    have h := guarded_assignment_mass n target witnesses f hn hbw hfa.
    by move: h; rewrite hs.
  by move: hb; rewrite words_size //.
qed.
lemma pool_target_union n j target :
  0<=n => 0<=j => 0<=target<n =>
  mu (dlist accepted_digest n) (fun nodes => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (words 12 j)) (words j n)) <=
    (n^j)%r*((j^12)%r*(1%r/2%r)^(132+18*j)).
proof.
  move=> hn hj ht; have hb := mu_has_leM (fun nodes witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (words 12 j)) (dlist accepted_digest n) (words j n)
    ((j^12)%r*(1%r/2%r)^(132+18*j)) _.
  + move=> witnesses hw; exact (pool_witness_union n j target witnesses hn hj ht hw).
  by move: hb; rewrite words_size //.
qed.
lemma pool_j_union n j : 0<=n => 0<=j =>
  mu (dlist accepted_digest n) (pool_coverage_j n j) <=
    n%r*(n^j)%r*(j^12)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj; have hb := mu_has_leM (fun nodes target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (words 12 j)) (words j n)) (dlist accepted_digest n) (range 0 n)
    ((n^j)%r*((j^12)%r*(1%r/2%r)^(132+18*j))) _.
  + move=> target ht; apply pool_target_union=> //; by move: ht; rewrite mem_range.
  by move: hb; rewrite size_range /= (: max 0 n=n) 1:/# /pool_coverage_j !mulrA.
qed.
lemma iid_pool_coverage_bound n : 0<=n =>
  mu (dlist accepted_digest n) pool_coverage <= coverage_charge n.
proof.
  move=> hn.
  have he : mu (dlist accepted_digest n) pool_coverage=
    mu (dlist accepted_digest n) (pool_coverage_enumerated n).
  + apply mu_eq_support=> nodes hs; apply pool_coverage_enumeration.
    exact (supp_dlist_size accepted_digest n nodes hn hs).
  rewrite he /pool_coverage_enumerated /coverage_charge.
  apply (ler_trans (bigi predT (fun j => mu (dlist accepted_digest n) (pool_coverage_j n j)) 1 13)).
  + exact (mu_has_le (fun nodes j => pool_coverage_j n j nodes) (dlist accepted_digest n) (range 1 13)).
  apply ler_sum_seq=> j /mem_range hj /=.
  move=> _; apply pool_j_union=> //; smt().
qed.
lemma adaptive_pool_coverage_bound (A <: AcceptedClient {-AcceptedSamples}) n &m :
  0<=n => Pr[AcceptedGame(A).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]
    <= coverage_charge n.
proof.
  move=> hn; apply (ler_trans (mu (dlist accepted_digest n) pool_coverage)).
  + exact (accepted_adaptive_prefix A n pool_coverage &m hn pool_coverage_extension).
  exact (iid_pool_coverage_bound n hn).
qed.
