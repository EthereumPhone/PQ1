(* A smaller assignment union for the same adaptive accepted-pool event. *)
require import AllCore List Distr DList StdBigop StdOrder Ring.
require import C10RawOracle CountDS AcceptedDigestDistribution AcceptedPrefixSampling.
require import CoverageAssignment SelectedCoverageMass PoolCoverageEvent PoolCoverageBound.
require import BoundedAssignmentWords CanonicalPoolWitness CanonicalPoolEvent.
import RField RealOrder Bigreal Bigreal.BRA.

op canonical_coverage_charge n = bigi predT
  (fun j => n%r*(n^j)%r*(canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j)) 1 13.

lemma canonical_witness_union n j target witnesses :
  0<=n => 0<=j => 0<=target<n => witnesses \in words j n =>
  mu (dlist accepted_digest n) (fun nodes => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes) (canonical_words j)) <=
    (canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj ht hw; move: hw; rewrite mem_words // /is_digit; move=> [hs hw].
  have hb := mu_has_leM (fun nodes f => uniq (target::witnesses) /\
    assignment_pool_event target witnesses f nodes) (dlist accepted_digest n) (canonical_words j)
    ((1%r/2%r)^(132+18*j)) _.
  + move=> f hf.
    have hfc : canonical_assignment j f by move: hf; rewrite canonical_words_member.
    have hfa : coverage_assignment (size witnesses) f.
    - have h:=canonical_assignment_ordinary j f hfc; by rewrite hs.
    have hbw : all (fun i=>0<=i<n) (target::witnesses) by smt().
    have h := guarded_assignment_mass n target witnesses f hn hbw hfa.
    by move: h; rewrite hs.
  by move: hb; rewrite canonical_words_size.
qed.
lemma canonical_target_union n j target :
  0<=n => 0<=j => 0<=target<n =>
  mu (dlist accepted_digest n) (fun nodes => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (canonical_words j)) (words j n)) <=
    (n^j)%r*((canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j)).
proof.
  move=> hn hj ht; have hb := mu_has_leM (fun nodes witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (canonical_words j)) (dlist accepted_digest n) (words j n)
    ((canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j)) _.
  + move=> witnesses hw; exact (canonical_witness_union n j target witnesses hn hj ht hw).
  by move: hb; rewrite words_size //.
qed.
lemma canonical_j_union n j : 0<=n => 0<=j =>
  mu (dlist accepted_digest n) (canonical_pool_j n j) <=
    n%r*(n^j)%r*(canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j).
proof.
  move=> hn hj; have hb := mu_has_leM (fun nodes target => has (fun witnesses => has (fun f =>
    uniq (target::witnesses) /\ assignment_pool_event target witnesses f nodes)
    (canonical_words j)) (words j n)) (dlist accepted_digest n) (range 0 n)
    ((n^j)%r*((canonical_assignment_count j)%r*(1%r/2%r)^(132+18*j))) _.
  + move=> target ht; apply canonical_target_union=> //; by move: ht; rewrite mem_range.
  by move: hb; rewrite size_range /= (: max 0 n=n) 1:/# /canonical_pool_j !mulrA.
qed.
lemma iid_canonical_coverage_bound n : 0<=n =>
  mu (dlist accepted_digest n) canonical_pool_coverage <= canonical_coverage_charge n.
proof.
  move=> hn.
  have he : mu (dlist accepted_digest n) canonical_pool_coverage=
    mu (dlist accepted_digest n) (canonical_pool_enumerated n).
  + apply mu_eq_support=> nodes hs; apply canonical_pool_enumeration.
    exact (supp_dlist_size accepted_digest n nodes hn hs).
  rewrite he /canonical_pool_enumerated /canonical_coverage_charge.
  apply (ler_trans (bigi predT (fun j => mu (dlist accepted_digest n) (canonical_pool_j n j)) 1 13)).
  + exact (mu_has_le (fun nodes j => canonical_pool_j n j nodes) (dlist accepted_digest n) (range 1 13)).
  apply ler_sum_seq=> j /mem_range hj /=.
  move=> _; apply canonical_j_union=> //; smt().
qed.
lemma adaptive_canonical_coverage_bound (A <: AcceptedClient {-AcceptedSamples}) n &m :
  0<=n => Pr[AcceptedGame(A).run() @ &m : size AcceptedSamples.nodes<=n /\ canonical_pool_coverage AcceptedSamples.nodes]
    <= canonical_coverage_charge n.
proof.
  move=> hn; apply (ler_trans (mu (dlist accepted_digest n) canonical_pool_coverage)).
  + exact (accepted_adaptive_prefix A n canonical_pool_coverage &m hn canonical_pool_extension).
  exact (iid_canonical_coverage_bound n hn).
qed.

lemma canonical_coverage_charge_tighter n : 0<=n => canonical_coverage_charge n<=coverage_charge n.
proof.
  move=> hn; rewrite /canonical_coverage_charge /coverage_charge.
  apply ler_sum_seq=> j /mem_range hj /= _.
  have hc:=canonical_count_upper j _; first smt().
  have hnp : 0<=n^j by apply IntOrder.expr_ge0.
  have hp : 0%r<=(1%r/2%r)^(132+18*j) by apply expr_ge0; smt().
  have hcr : (canonical_assignment_count j)%r<=(j^12)%r by smt().
  have hnpr : 0%r<=n%r*(n^j)%r by smt().
  smt().
qed.
