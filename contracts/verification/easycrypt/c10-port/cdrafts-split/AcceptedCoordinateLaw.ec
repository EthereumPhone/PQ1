(* Conditional accepted-digest laws for coordinate predicates fixed before a draw. *)
require import AllCore List Distr DList DBool StdBigop StdOrder.
require import C10RawOracle C10Randomizer C10RawGrind.
require import GrindJointCoverage FreshCoverage DigestPrefix DigestPair AcceptedSampling AcceptedDigestDistribution.
import RField RealOrder Bigreal Bigreal.BRM.

op coordinate_predicate (p : int -> digest -> bool) d =
  forall i, 0<=i<12 => p i (take 11 (drop (11*i) d)).
op accepted_chunk_predicate (p : int -> digest -> bool) i chunk =
  if i<12 then p i chunk else chunk=nseq 11 false.
op coordinate_mass (p : int -> digest -> bool) =
  bigi predT (fun i => mu (dlist dbool 11) (p i)) 0 12.

lemma accepted_chunks_event p d :
  (forall i, 0<=i<13 => accepted_chunk_predicate p i (nth [] (digest_chunks 11 13 d) i)) <=>
  accept_digest d /\ coordinate_predicate p d.
proof.
  split.
  + move=> h; split.
    - have h12 := h 12 _; first smt().
      move: h12; rewrite /accepted_chunk_predicate /digest_chunks nth_mkseq 1:/# /= /accept_digest.
      by [].
    move=> i hi; have hc := h i _; first smt().
    move: hc; rewrite /accepted_chunk_predicate /digest_chunks nth_mkseq 1:/# /=; smt().
  move=> [ha hc] i hi.
  rewrite /accepted_chunk_predicate /digest_chunks nth_mkseq 1:/# /=.
  case (i<12) => hlt; first by move: hc; rewrite /coordinate_predicate; smt().
  have -> : i=12 by smt().
  by move: ha; rewrite /accept_digest.
qed.

lemma fresh_coordinate_mass p :
  accepted_mass (coordinate_predicate p)=coordinate_mass p*acceptance_rate.
proof.
  rewrite /accepted_mass (mu_eq _ _ (fun d => forall i, 0<=i<13 =>
    accepted_chunk_predicate p i (nth [] (digest_chunks 11 13 d) i))).
  + by move=> d; rewrite accepted_chunks_event.
  have hd := digest_chunks_uniform 11 13 _ _ _; first 3 smt().
  rewrite -(dmapE full_digest (digest_chunks 11 13)
    (fun xs => forall i, 0<=i<13 => accepted_chunk_predicate p i (nth [] xs i))) hd.
  rewrite (dlistE [] (dlist dbool 11) (accepted_chunk_predicate p) 13).
  rewrite (big_int_recr 12 0) 1:/# /=.
  have he : bigi predT (fun i => mu (dlist dbool 11) (accepted_chunk_predicate p i)) 0 12 =
    coordinate_mass p.
  + apply eq_big_seq; move=> i /mem_range hi /=.
    apply mu_eq => chunk; rewrite /accepted_chunk_predicate; smt().
  rewrite he /accepted_chunk_predicate /=.
  have hm : mu (dlist dbool 11) (fun chunk => chunk=nseq 11 false) = acceptance_rate.
  + change (mu1 (dlist dbool 11) (nseq 11 false)=acceptance_rate).
    have hs : size (nseq 11 false)=11 by rewrite size_nseq.
    by rewrite -{1}hs bool_word_mass hs /acceptance_rate.
  by rewrite hm.
qed.

lemma accepted_coordinate_mass p :
  mu accepted_digest (coordinate_predicate p)=coordinate_mass p.
proof.
  rewrite accepted_digest_probability /accepted_probability fresh_coordinate_mass.
  rewrite mulrK; smt(acceptance_rate_positive).
qed.

lemma coordinate_predicate_prefix p d :
  coordinate_predicate p (take 143 d)=coordinate_predicate p d.
proof.
  have hc : forall i, 0<=i<12 =>
    take 11 (drop (11*i) (take 143 d))=take 11 (drop (11*i) d).
  + move=> i hi; by rewrite drop_take 1,2:/# take_take (: 11<=143-11*i) 1:/#.
  rewrite /coordinate_predicate; smt().
qed.

lemma accepted_joint_coordinate_mass p (target : digest) : size target=18 =>
  mu accepted_digest (fun d => coordinate_predicate p d /\ take 18 (drop 143 d)=target) =
    coordinate_mass p*(1%r/2%r)^18.
proof.
  move=> ht.
  have hp := digest_pair_mass 143 18
    (fun d => accept_digest d /\ coordinate_predicate p d)
    (fun d => d=target) _ _ _; first 3 smt().
  have hf : mu (dlist dbool 143) (fun d => accept_digest d /\ coordinate_predicate p d)=
    accepted_mass (coordinate_predicate p).
  + rewrite -(digest_prefix_uniform 143 _) 1:/# dmapE /pred_o /(\o).
    rewrite /accepted_mass; apply mu_eq => d /=.
    by rewrite acceptance_prefix coordinate_predicate_prefix.
  have hl : mu (dlist dbool 18) (fun d => d=target)=(1%r/2%r)^18.
  + change (mu1 (dlist dbool 18) target=(1%r/2%r)^18).
    by rewrite -{1}ht bool_word_mass ht.
  have hp2 := hp; rewrite hf hl in hp2.
  rewrite accepted_digest_probability /accepted_probability.
  have hm : accepted_mass (fun d => coordinate_predicate p d /\ take 18 (drop 143 d)=target)=
    accepted_mass (coordinate_predicate p)*(1%r/2%r)^18.
  + rewrite -hp2 /accepted_mass; apply mu_eq => d /=.
    rewrite acceptance_prefix coordinate_predicate_prefix; smt().
  rewrite hm fresh_coordinate_mass.
  rewrite -mulrAC mulrK; smt(acceptance_rate_positive).
qed.
