(* External Q research: bounded independent fresh draws, stopped at the first
   accepted digest. Relating this sampler to cached adaptive signing is separate. *)
require import AllCore List Distr Xreal StdOrder.
require import C10RawOracle C10Randomizer C10RawGrind FORSC10Digest.
import RField RealOrder.

op acceptance_rate = (1%r/2%r)^11.
op accepted_mass (p : digest -> bool) = mu full_digest (fun d => accept_digest d /\ p d).
op accepted_probability (p : digest -> bool) = accepted_mass p / acceptance_rate.

lemma acceptance_rate_positive : 0%r < acceptance_rate.
proof. rewrite /acceptance_rate; apply expr_gt0; smt(). qed.
lemma accepted_mass_bounds p : 0%r <= accepted_mass p <= acceptance_rate.
proof.
  rewrite /accepted_mass; split; first smt(mu_bounded).
  move=> _; rewrite /acceptance_rate -fors_acceptance_mass.
  apply mu_sub; smt().
qed.
lemma accepted_probability_bounds p : 0%r <= accepted_probability p <= 1%r.
proof.
  have ha := acceptance_rate_positive; have hm := accepted_mass_bounds p.
  rewrite /accepted_probability; split.
  + apply divr_ge0; smt().
  move=> _; rewrite ler_pdivr_mulr 1:ha mul1r; smt().
qed.

lemma accepted_step_potential p :
  Ep full_digest (fun d => if accept_digest d then (p d)%xr
    else (accepted_probability p)%xr) = (accepted_probability p)%xr.
proof.
  have hp := accepted_probability_bounds p.
  have hm := accepted_mass_bounds p.
  have ha := acceptance_rate_positive.
  have hr : 0%r <= 1%r - acceptance_rate by have := mu_bounded full_digest accept_digest;
    rewrite fors_acceptance_mass /acceptance_rate; smt().
  rewrite (eq_Ep _ _ ((fun d => (accept_digest d /\ p d)%xr) +
    (fun d => (accepted_probability p)%rp ** (!accept_digest d)%xr))).
  + move=> d _ /=; case (accept_digest d); case (p d); by rewrite /= ?smulrp /=.
  rewrite EpD Ep_mu EpsZ Ep_mu mu_not full_digest_ll fors_acceptance_mass -/acceptance_rate.
  rewrite -/(accepted_mass p) ?smulrp /=.
  have hk : accepted_probability p * acceptance_rate = accepted_mass p.
  + rewrite /accepted_probability mulrVK; smt().
  rewrite -of_realM 1:/# 1:hr -of_realD 1:/# 1:/#.
  congr; rewrite mulrBr mulr1 hk; ring.
qed.

module FreshAccept = {
  proc run(budget : int) : digest option = {
    var i, hd, result;
    i <- 0; result <- None;
    while (i < budget /\ result = None) {
      hd <$ full_digest;
      if (accept_digest hd) { result <- Some hd; }
      i <- i+1;
    }
    return result;
  }
}.

ehoare accepted_sampling p : FreshAccept.run : (accepted_probability p)%xr ==>
  (res <> None /\ p (oget res))%xr.
proof.
  proc; while (if result = None then (accepted_probability p)%xr else (p (oget result))%xr).
  + move=> &hr; apply xle_cxr_r => hg.
    case (result{hr} = None); rewrite /=; smt(to_realP).
  + wp; skip => &hr; apply xle_cxr_r => hg.
    have hn : result{hr} = None by smt().
    rewrite hn /=.
    rewrite (eq_Ep _ _ (fun d => if accept_digest d then (p d)%xr else (accepted_probability p)%xr)).
    - by move=> d _ /=; case (accept_digest d); rewrite /=.
    by rewrite accepted_step_potential.
  by auto.
qed.

lemma accepted_sampling_bound p budget &m :
  Pr[FreshAccept.run(budget) @ &m : res <> None /\ p (oget res)] <= accepted_probability p.
proof. by byehoare (accepted_sampling p) => //. qed.
