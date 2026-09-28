(* No-revisit exhaustion event in the actual stateful stream. *)
require import AllCore List Distr FMap Xreal StdOrder.
require import C10RawOracle C10RawGrind C10Counter C10Randomizer FORSC10Digest.
require import PrefixGuess RawTrial StreamBound GrindTail TrialExpectation.
import RField RealOrder.

ehoare stream_rejection_potential : StreamGrind.run :
  (reject_mass ^ signing_budget)%xr ==> (!Stream.bad /\ res = None)%xr.
proof.
  proc; while ((0 <= Stream.i <= signing_budget) `|`
    (reject_mass ^ (signing_budget-Stream.i))%xr * (!Stream.bad /\ result = None)%xr).
  + move=> &hr; apply xle_cxr_r => hg; apply xle_cxr_r => hi.
    case (!Stream.bad{hr} /\ result{hr} = None) => hb.
    - have he : Stream.i{hr} = signing_budget by smt().
      by rewrite he /= expr0 /=.
    by [].
  + inline Stream.next; rcondt 2; first by auto.
    wp.
    conseq (_ : (Stream.i < signing_budget /\ result = None) `|`
      ((0 <= Stream.i <= signing_budget) `|`
       (reject_mass ^ (signing_budget-Stream.i))%xr * (!Stream.bad /\ result = None)%xr)
       ==> (0 <= Stream.i+1 <= signing_budget) `|`
      (reject_mass ^ (signing_budget-(Stream.i+1)))%xr *
      ((!Stream.bad /\ result = None)%xr * (!Trial.known /\ !accept_digest out0.`2)%xr)) => //.
    - move=> &hr; apply xle_cxr_l; last by [].
      by move=> known outv; case (accept_digest outv.`2); case (Stream.bad{hr});
        case known; case (result{hr} = None); rewrite /=.
    - by move=> &hr; apply xle_cxr_r => h; exact (h Trial.known{hr} out0{hr}).
    call /(fun x => (0 <= Stream.i+1 <= signing_budget) `|`
      (reject_mass ^ (signing_budget-(Stream.i+1)))%xr * ((!Stream.bad /\ result = None)%xr * x))
      trial_rejection_potential.
    auto => &hr; apply xle_cxr_r => -[[hl hr] hi].
    have hn : 0 <= Stream.i{hr}+1 <= signing_budget by smt().
    rewrite hn hr /=; case (Stream.bad{hr}) => hb; first by [].
    rewrite /=.
    have hp : forall n, 0%r <= reject_mass^n by move=> n; apply expr_ge0; smt(reject_positive).
    have hp0 : 0%r <= reject_mass by smt(reject_positive).
    rewrite !to_pos_pos 1:hp 1:hp0 1:hp.
    have he : signing_budget-Stream.i{hr} = (signing_budget-(Stream.i{hr}+1))+1 by ring.
    by rewrite he exprSr 1:/#.
  by inline Stream.init; auto; rewrite /signing_budget /=.
qed.

lemma stream_no_revisit_tail random message seed root &m :
  Pr[StreamGrind.run(random,message,seed,root) @ &m : !Stream.bad /\ res = None]
    <= reject_mass^signing_budget.
proof. by byehoare stream_rejection_potential => //. qed.
