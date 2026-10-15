(* Accepted WOTS collisions in an adaptive prefix of fresh digest samples. *)
require import AllCore List Distr DList RealSeries StdOrder Ring.
require import C10RawOracle C10Randomizer RawWots WotsAcceptanceMass.
require import AcceptedPrefixSampling FullDigestPrefixSampling.
import RField RealOrder.

op accepted_encoding_words (nodes : digest list) = map raw_digits (filter count_accepts nodes).
op accepted_encoding_pool_collision nodes = !uniq (accepted_encoding_words nodes).

lemma accepted_encoding_words_cat xs ys :
  accepted_encoding_words (xs++ys)=accepted_encoding_words xs++accepted_encoding_words ys.
proof. by rewrite /accepted_encoding_words filter_cat map_cat. qed.

lemma accepted_encoding_pool_extension : extension_closed accepted_encoding_pool_collision.
proof.
  rewrite /extension_closed /accepted_encoding_pool_collision => xs ys hn.
  rewrite accepted_encoding_words_cat cat_uniq; smt().
qed.

lemma accepted_encoding_member d xs : count_accepts d =>
  mem (accepted_encoding_words xs) (raw_digits d)=has (fun e=>raw_digits d=raw_digits e) xs.
proof.
  move=> hd; rewrite /accepted_encoding_words eq_iff; split.
  + move/mapP=> [e [he heq]]; apply/hasP; exists e; move: he; rewrite mem_filter; smt().
  move/hasP=> [e [he heq]]; apply/mapP; exists e.
  rewrite mem_filter; move: hd; rewrite /count_accepts; smt().
qed.

lemma accepted_encoding_pool_cons d xs :
  accepted_encoding_pool_collision (d::xs)=
    (accepted_encoding_pool_collision xs \/
      (count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) xs)).
proof.
  rewrite /accepted_encoding_pool_collision {1}/accepted_encoding_words /=.
  case (count_accepts d)=> hd /=; last by [].
  rewrite -/(accepted_encoding_words xs) accepted_encoding_member 1:hd; smt().
qed.

lemma iid_has_bound ['a] (d : 'a distr) n (p : 'a -> bool) :
  is_lossless d => 0<=n => mu (dlist d n) (has p)<=n%r*mu d p.
proof.
  move=> hd; elim: n=> [|n hn ih].
  + by rewrite (dlist0 d 0) // dunitE /=.
  rewrite dlistS 1:hn /= dmapE /(\o) /=.
  have h := le_dprod_or d (dlist d n) p (has p).
  rewrite hd (dlist_ll d n hd) /= in h.
  smt().
qed.

lemma accepted_head_collision_bound n : 0<=n =>
  mu (full_digest `*` dlist full_digest n) (fun (p : digest * digest list)=>
    count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2)<=
    n%r*wots_acceptance_mass*(1%r/2%r)^129.
proof.
  move=> hn; rewrite dprod_partition /=.
  pose k := n%r*(1%r/2%r)^129.
  have hs : summable (fun d=>k*(if count_accepts d then mu1 full_digest d else 0%r)).
  + apply summableZ; exact (summable_mu1_cond full_digest count_accepts).
  have hb : sum (fun d=>mu (dlist full_digest n)
      (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)*mu1 full_digest d)<=
    sum (fun d=>k*(if count_accepts d then mu1 full_digest d else 0%r)).
  + apply ler_sum_pos=> // d.
    case (count_accepts d)=> hd /=.
    - have he : mu (dlist full_digest n)
          (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)=
        mu (dlist full_digest n) (has (fun e=>raw_digits d=raw_digits e)).
      * apply mu_eq=> ds; smt().
      rewrite he.
      have hh := iid_has_bound full_digest n (fun e=>raw_digits d=raw_digits e) full_digest_ll hn.
      rewrite raw_digits_atom in hh.
      have hm := ge0_mu1 full_digest d.
      have hg := ge0_mu (dlist full_digest n) (has (fun e=>raw_digits d=raw_digits e)).
      rewrite /k; smt().
    have hz : mu (dlist full_digest n)
      (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)=0%r.
    - apply mu0_false=> ds; smt().
    rewrite hz; smt().
  rewrite sumZ -muE raw_wots_acceptance_mass /k in hb.
  have he : n%r*(1%r/2%r)^129*wots_acceptance_mass=n%r*wots_acceptance_mass*(1%r/2%r)^129 by ring.
  by move: hb; rewrite he /=.
qed.

op accepted_encoding_charge q = (q*(q-1))%r/2%r*wots_acceptance_mass*(1%r/2%r)^129.

lemma accepted_encoding_charge_step q :
  accepted_encoding_charge (q+1)=accepted_encoding_charge q+q%r*wots_acceptance_mass*(1%r/2%r)^129.
proof. rewrite /accepted_encoding_charge !fromintM !fromintD ?fromintB /=; field; smt(). qed.

lemma iid_accepted_encoding_bound n : 0<=n =>
  mu (dlist full_digest n) accepted_encoding_pool_collision<=accepted_encoding_charge n.
proof.
  elim: n=> [|n hn ih].
  + by rewrite (dlist0 full_digest 0) // dunitE /accepted_encoding_pool_collision
      /accepted_encoding_words /accepted_encoding_charge /=.
  rewrite dlistS 1:hn /= dmapE /(\o).
  have he : mu (full_digest `*` dlist full_digest n)
      (fun (p : digest * digest list)=>accepted_encoding_pool_collision (p.`1::p.`2))=
    mu (full_digest `*` dlist full_digest n) (predU
      (fun (p : digest * digest list)=>accepted_encoding_pool_collision p.`2)
      (fun (p : digest * digest list)=>count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2)).
  + apply mu_eq=> p; rewrite /predU accepted_encoding_pool_cons; by [].
  rewrite he mu_or dprodEr full_digest_ll /= accepted_encoding_charge_step.
  apply (ler_trans (mu (dlist full_digest n) accepted_encoding_pool_collision+
    mu (full_digest `*` dlist full_digest n) (fun (p : digest * digest list)=>
      count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2))).
  + rewrite ler_subl_addr ler_addl; exact (ge0_mu _ _).
  apply ler_add; first exact ih.
  exact (accepted_head_collision_bound n hn).
qed.

lemma adaptive_accepted_encoding_bound (A <: FullDigestClient {-FullDigestSamples}) q &m :
  0<=q => Pr[FullDigestGame(A).run() @ &m :
    size FullDigestSamples.nodes<=q /\ accepted_encoding_pool_collision FullDigestSamples.nodes]<=
    accepted_encoding_charge q.
proof.
  move=> hq; have hp := full_digest_adaptive_prefix A q accepted_encoding_pool_collision &m hq accepted_encoding_pool_extension.
  have hi := iid_accepted_encoding_bound q hq; smt().
qed.

lemma accepted_encoding_charge_tighter q : 0<=q =>
  accepted_encoding_charge q<=(q*(q-1))%r/2%r*(1%r/2%r)^129.
proof.
  move=> hq; have hp := wots_acceptance_mass_bounds.
  have hc : 0%r<=(q*(q-1))%r/2%r by smt().
  rewrite /accepted_encoding_charge; apply ler_wpmul2r.
  + apply expr_ge0; smt().
  apply (ler_trans ((q*(q-1))%r/2%r*1%r)); last by rewrite mulr1.
  apply ler_wpmul2l; smt().
qed.
