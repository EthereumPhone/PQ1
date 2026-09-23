(* External Q research: one fixed hypertree index and opening sets fixed
   before the actual grind. No claim about later enlarged opening sets. *)
require import AllCore List Distr DList DBool FMap StdOrder StdBigop.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess RawTrial.
require import RTailFresh RoleGrind StreamBound GrindExhaustion.
require import DigestPrefix DigestPair FreshCoverage AcceptedSampling.
require import StreamAccepted AcceptedCoverage.
import RField RealOrder Bigreal Bigreal.BRM.

lemma covered_prefix opened d :
  prior_covered opened (take 143 d) = prior_covered opened d.
proof.
  have hc : forall i, 0 <= i < 12 =>
    take 11 (drop (11*i) (take 143 d)) = take 11 (drop (11*i) d).
  + move=> i hi.
    by rewrite drop_take 1,2:/# take_take (_ : 11 <= 143 - 11*i) 1:/#.
  rewrite /prior_covered; smt().
qed.

lemma acceptance_prefix d : accept_digest (take 143 d) = accept_digest d.
proof. by rewrite /accept_digest drop_take 1,2:/# take_take. qed.

lemma accepted_joint_probability opened (target : bool list) : size target = 18 =>
  accepted_probability
    (fun d => prior_covered opened d /\ take 18 (drop 143 d) = target) =
    prior_coverage_mass opened * (1%r/2%r)^18.
proof.
  move=> ht.
  have hp := digest_pair_mass 143 18
    (fun d => accept_digest d /\ prior_covered opened d)
    (fun d => d = target) _ _ _; first 3 smt().
  have hfirst :
    mu (dlist dbool 143) (fun d => accept_digest d /\ prior_covered opened d) =
    accepted_mass (prior_covered opened).
  + rewrite -(digest_prefix_uniform 143 _) 1:/# dmapE /pred_o /(\o).
    rewrite /accepted_mass; apply mu_eq => d /=.
    by rewrite acceptance_prefix covered_prefix.
  have hlast : mu (dlist dbool 18) (fun d => d = target) = (1%r/2%r)^18.
  + change (mu1 (dlist dbool 18) target = (1%r/2%r)^18).
    by rewrite -{1}ht bool_word_mass ht.
  have hp2 := hp; rewrite hfirst hlast in hp2.
  have hmass :
    accepted_mass (fun d => prior_covered opened d /\ take 18 (drop 143 d) = target) =
    accepted_mass (prior_covered opened) * (1%r/2%r)^18.
  + rewrite -hp2 /accepted_mass; apply mu_eq => d /=.
    rewrite acceptance_prefix covered_prefix; smt().
  rewrite /accepted_probability hmass.
  rewrite -mulrAC -/(accepted_probability (prior_covered opened)) accepted_coverage_probability.
  by [].
qed.

lemma role_grind_joint_coverage opened target q0 random message seed root &m :
  size target = 18 =>
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m :
    res <> None /\ prior_covered opened (oget res).`2 /\
      take 18 (drop 143 (oget res).`2) = target]
    <= prior_coverage_cardinality opened * (1%r/2%r)^18 + revisit_charge q0.
proof.
  move=> ht hq hsize hrecord hf hs hr.
  have h := role_grind_accepted_bound
    (fun d => prior_covered opened d /\ take 18 (drop 143 d) = target)
    q0 random message seed root &m hq hsize hrecord hf hs hr.
  rewrite (accepted_joint_probability opened target ht) in h.
  have hc := prior_coverage_cardinality_bound opened.
  have hp : 0%r <= (1%r/2%r)^18 by apply expr_ge0; smt().
  apply (ler_trans (prior_coverage_mass opened * (1%r/2%r)^18 + revisit_charge q0)).
  + exact h.
  apply ler_add; last by [].
  by apply ler_wpmul2r.
qed.
