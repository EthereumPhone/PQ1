(* Birthday bound for a fixed pool of accepted full digests. *)
require import AllCore List Distr DList RealSeries StdOrder Ring.
require import C10RawOracle RawWots WotsAcceptedDistribution AcceptedEncodingPool.
import RField RealOrder.

lemma conditional_head_collision_bound n : 0<=n =>
  mu (accepted_wots_digest `*` dlist accepted_wots_digest n)
    (fun (p : digest * digest list)=>
      count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2)
    <= n%r*accepted_word_mass.
proof.
  move=> hn; rewrite dprod_partition /=.
  pose k := n%r*accepted_word_mass.
  have hs : summable (fun d=>k*(if count_accepts d then mu1 accepted_wots_digest d else 0%r)).
  + apply summableZ; exact (summable_mu1_cond accepted_wots_digest count_accepts).
  have hb : sum (fun d=>mu (dlist accepted_wots_digest n)
      (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)*mu1 accepted_wots_digest d)<=
    sum (fun d=>k*(if count_accepts d then mu1 accepted_wots_digest d else 0%r)).
  + apply ler_sum_pos=> // d.
    case (count_accepts d)=> hd /=.
    - have he : mu (dlist accepted_wots_digest n)
          (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)=
        mu (dlist accepted_wots_digest n) (has (fun e=>raw_digits d=raw_digits e)).
      * apply mu_eq=> ds; smt().
      rewrite he.
      have hh := iid_has_bound accepted_wots_digest n (fun e=>raw_digits d=raw_digits e)
        accepted_wots_digest_ll hn.
      rewrite (accepted_wots_word_mass d hd) in hh.
      have hm := ge0_mu1 accepted_wots_digest d.
      have hg := ge0_mu (dlist accepted_wots_digest n) (has (fun e=>raw_digits d=raw_digits e)).
      rewrite /k; smt().
    have hz : mu (dlist accepted_wots_digest n)
      (fun ds=>count_accepts d /\ has (fun e=>raw_digits d=raw_digits e) ds)=0%r.
    - apply mu0_false=> ds; smt().
    rewrite hz; smt().
  by move: hb; rewrite sumZ -muE accepted_wots_digest_accepts /k mulr1.
qed.

op conditional_encoding_charge q = (q*(q-1))%r/2%r*accepted_word_mass.

lemma conditional_encoding_charge_step q :
  conditional_encoding_charge (q+1)=conditional_encoding_charge q+q%r*accepted_word_mass.
proof.
  rewrite /conditional_encoding_charge !fromintM !fromintD ?fromintB /=; field; smt().
qed.

lemma iid_conditional_encoding_bound n : 0<=n =>
  mu (dlist accepted_wots_digest n) accepted_encoding_pool_collision<=conditional_encoding_charge n.
proof.
  elim: n=> [|n hn ih].
  + by rewrite (dlist0 accepted_wots_digest 0) // dunitE /accepted_encoding_pool_collision
      /accepted_encoding_words /conditional_encoding_charge /=.
  rewrite dlistS 1:hn /= dmapE /(\o).
  have he : mu (accepted_wots_digest `*` dlist accepted_wots_digest n)
      (fun (p : digest * digest list)=>accepted_encoding_pool_collision (p.`1::p.`2))=
    mu (accepted_wots_digest `*` dlist accepted_wots_digest n) (predU
      (fun (p : digest * digest list)=>accepted_encoding_pool_collision p.`2)
      (fun (p : digest * digest list)=>count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2)).
  + apply mu_eq=> p; rewrite /predU accepted_encoding_pool_cons; by [].
  rewrite he mu_or dprodEr accepted_wots_digest_ll /= conditional_encoding_charge_step.
  apply (ler_trans (mu (dlist accepted_wots_digest n) accepted_encoding_pool_collision+
    mu (accepted_wots_digest `*` dlist accepted_wots_digest n) (fun (p : digest * digest list)=>
      count_accepts p.`1 /\ has (fun e=>raw_digits p.`1=raw_digits e) p.`2))).
  + rewrite ler_subl_addr ler_addl; exact (ge0_mu _ _).
  apply ler_add; first exact ih.
  exact (conditional_head_collision_bound n hn).
qed.
