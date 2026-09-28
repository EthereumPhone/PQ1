(* External Q research: a fresh acceptance-constrained digest leaves its
   18 hypertree bits uniform; bounded fresh sampling preserves the upper bound. *)
require import AllCore List Distr DList DBool StdOrder.
require import C10RawOracle C10Randomizer C10RawGrind DigestWindow AcceptedSampling.
import RField RealOrder.

lemma accepted_ht_event d (target : bool list) : size d = 256 =>
  (accept_digest d /\ take 18 (drop 143 d) = target) <=>
  take 29 (drop 132 d) = nseq 11 false ++ target.
proof.
  move=> hs; rewrite (_ : 29 = 11+18) 1:// takeD 1,2:// drop_drop 1,2:// /=.
  rewrite eqseq_cat.
  + rewrite size_take 1:// size_drop 1:// hs size_nseq; smt().
  by rewrite /accept_digest.
qed.

lemma accepted_ht_mass (target : bool list) : size target = 18 =>
  accepted_mass (fun d => take 18 (drop 143 d) = target) = (1%r/2%r)^29.
proof.
  move=> ht; rewrite /accepted_mass.
  have he : mu full_digest (fun d => accept_digest d /\ take 18 (drop 143 d) = target) =
    mu full_digest (fun d => take 29 (drop 132 d) = nseq 11 false ++ target).
  + apply mu_eq_support => d hd /=.
    have hs : size d = 256 by exact (supp_dlist_size dbool 256 d _ hd); smt().
    have hx := accepted_ht_event d target hs; smt().
  rewrite he; apply digest_window_mass.
  + smt().
  + smt().
  + smt().
  by rewrite size_cat size_nseq ht.
qed.

lemma accepted_ht_probability target : size target = 18 =>
  accepted_probability (fun d => take 18 (drop 143 d) = target) = (1%r/2%r)^18.
proof.
  move=> ht; rewrite /accepted_probability (accepted_ht_mass target ht) /acceptance_rate.
  rewrite (_ : 29 = 18+11) 1:// exprD_nneg 1,2://.
  rewrite mulrK; smt(expr_gt0).
qed.

lemma fresh_accepted_ht_bound target budget &m : size target = 18 =>
  Pr[FreshAccept.run(budget) @ &m : res <> None /\ take 18 (drop 143 (oget res)) = target]
    <= (1%r/2%r)^18.
proof.
  move=> ht; have h := accepted_sampling_bound (fun d => take 18 (drop 143 d) = target) budget &m.
  by rewrite (accepted_ht_probability target ht) in h.
qed.
