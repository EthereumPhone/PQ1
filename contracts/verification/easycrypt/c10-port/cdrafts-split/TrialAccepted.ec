(* External Q research: acceptance potential for the actual private-R/public
   H_msg trial. Cached public queries are excluded by the recorded event. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10RawGrind C10Randomizer.
require import PrefixGuess RawTrial AcceptedSampling.
import RField RealOrder.

ehoare trial_acceptance_potential p : Trial.run : (accepted_probability p)%xr ==>
  (if Trial.known then 0%xr else
    if accept_digest res.`2 then (p res.`2)%xr else (accepted_probability p)%xr).
proof.
  proc; seq 4 : ((Trial.known = (x \in Independent.rawhistory)) `|` (accepted_probability p)%xr).
  + wp; conseq (_ : _ ==> (accepted_probability p)%xr) => //.
    call (_ : (accepted_probability p)%xr ==> (accepted_probability p)%xr).
    - proc; if; auto.
      + move=> &hr; apply xle_cxr_r => _; by rewrite EpC full_digest_ll /=.
      by move=> &hr; apply xle_cxr_r.
    by auto.
  inline Independent.hash; wp.
  skip => &hr; apply xle_cxr_r => hk.
  case (x{hr} \in Independent.rawhistory{hr}) => hx.
  + have hb : Trial.known{hr} by smt().
    rewrite hb /=; smt(accepted_probability_bounds to_pos_pos).
  have hb : !Trial.known{hr} by smt().
  rewrite hb /=.
  rewrite (eq_Ep _ _ (fun hd => if accept_digest hd then (p hd)%xr else (accepted_probability p)%xr)).
  + by move=> hd _ /=; rewrite FMap.get_set_sameE /=.
  by rewrite accepted_step_potential.
qed.
