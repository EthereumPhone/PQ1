(* External Q research: accepted-output law for the actual memoized R/H_msg
   stream. Revisited public inputs are charged by the existing explicit event. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10RawGrind C10Counter C10Randomizer.
require import PrefixGuess RawTrial RTailFresh RoleGrind StreamBound GrindExhaustion.
require import AcceptedSampling TrialAccepted.
import RField RealOrder.

op stream_acceptance_potential (p : digest -> bool) (bad : bool)
  (result : (raw_input * digest) option) =
  if bad then 0%xr else if result = None then (accepted_probability p)%xr
  else (p (oget result).`2)%xr.

ehoare stream_acceptance p : StreamGrind.run : (accepted_probability p)%xr ==>
  (!Stream.bad /\ res <> None /\ p (oget res).`2)%xr.
proof.
  proc; while (stream_acceptance_potential p Stream.bad result).
  + move=> &hr; apply xle_cxr_r => hg.
    rewrite /stream_acceptance_potential.
    case (Stream.bad{hr}); case (result{hr} = None); rewrite /=; smt(to_realP).
  + inline Stream.next; rcondt 2; first by auto.
    wp.
    conseq (_ : (Stream.i < signing_budget /\ result = None) `|`
      stream_acceptance_potential p Stream.bad result ==>
      (!Stream.bad)%xr * (if Trial.known then 0%xr else
        if accept_digest out0.`2 then (p out0.`2)%xr else (accepted_probability p)%xr)) => //.
    - move=> &hr; apply xle_cxr_r => hg; apply xle_cxr_l.
      + move=> known outv; have hn : result{hr} = None by smt().
        rewrite /stream_acceptance_potential /= hn /=.
        case (Stream.bad{hr}); case known; case (accept_digest outv.`2); by rewrite /=.
      apply xle_cxr_l; first exact hg.
      by [].
    - by move=> &hr; apply xle_cxr_r => h; exact (h Trial.known{hr} out0{hr}).
    call /(fun x => (!Stream.bad)%xr * x) (trial_acceptance_potential p).
    auto => &hr.
    apply xle_cxr_r => hg.
    have hn : result{hr} = None by smt().
    by rewrite /stream_acceptance_potential hn /=; case (Stream.bad{hr}); rewrite /=.
  by inline Stream.init; auto; rewrite /stream_acceptance_potential /=.
qed.

lemma stream_no_revisit_accepted p random message seed root &m :
  Pr[StreamGrind.run(random,message,seed,root) @ &m :
    !Stream.bad /\ res <> None /\ p (oget res).`2] <= accepted_probability p.
proof. by byehoare (stream_acceptance p) => //. qed.

lemma stream_accepted_bound p q0 random message seed root &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[StreamGrind.run(random,message,seed,root) @ &m :
    res <> None /\ p (oget res).`2]
    <= accepted_probability p + revisit_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have hc := stream_cached_bound q0 random message seed root &m hq hsize hrecord hf hs hr.
  have ht := stream_no_revisit_accepted p random message seed root &m.
  have hsplit :
    Pr[StreamGrind.run(random,message,seed,root) @ &m : res <> None /\ p (oget res).`2]
    <= Pr[StreamGrind.run(random,message,seed,root) @ &m : Stream.bad]
      + Pr[StreamGrind.run(random,message,seed,root) @ &m :
        !Stream.bad /\ res <> None /\ p (oget res).`2].
  + rewrite Pr[mu_split Stream.bad] ler_add.
    - by rewrite Pr[mu_sub]; smt().
    by rewrite Pr[mu_sub]; smt().
  by rewrite /revisit_charge; smt().
qed.

lemma role_grind_accepted_bound p q0 random message seed root &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m :
    res <> None /\ p (oget res).`2]
    <= accepted_probability p + revisit_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have he :
    Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m :
      res <> None /\ p (oget res).`2] =
    Pr[StreamGrind.run(random,message,seed,root) @ &m :
      res <> None /\ p (oget res).`2]
    by byequiv stream_refines_grind => //.
  by rewrite he; apply (stream_accepted_bound p q0 random message seed root &m).
qed.
