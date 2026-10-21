(* Actual key generation establishes the live-history premise. The complete
   experiment retains final verification and transfers only a returned Boolean. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal PrefixState.
require import KeygenPrefixes KeygenExhaustion PreparedHistory RawTrial RTailFresh.
require import SessionPhysical GrindExhaustion FullSession FullSessionCost FullPrefix.
require import RObservedSigner FullRBound FullRGame.
import RealOrder Bigreal BRA.

lemma full_r_driver_exhaustion (A <: FullClient {-FullSession,-Independent,-RFailure}) q0 qr0 qs0 :
  0 <= q0 => 0 <= qr0 => 0 <= qs0 =>
  phoare[FullRDriver(A,Independent).run : qr = qr0 /\ qs = qs0 /\
    size seed = 32 /\ size root = 32 /\ size Independent.queries <= q0 /\
    history_recorded Independent.rawhistory Independent.queries /\
    no_r_tails Independent.secrethistory ==>
    RFailure.bad] <= (bigi predT (fun _ => exhaustion_charge (q0+qr0+qs0*full_r_sign_cost)) 0 qs0).
proof.
  move=> hq hqr hqs; bypr => &m [#] hqr0 hqs0 hs hr hsize hrecord hnor.
  have he : Pr[FullRRun(A).run(seed{m},root{m},qr{m},qs{m}) @ &m : RFailure.bad] =
    Pr[FullRDriver(A,Independent).run(seed{m},root{m},qr{m},qs{m}) @ &m : RFailure.bad]
    by byequiv (full_r_final_verification_preserves_event A) => //.
  rewrite -he hqr0 hqs0.
  exact (full_r_adaptive_exhaustion A q0 qr0 qs0 seed{m} root{m} &m hq hqr hqs hs hr hsize hrecord hnor).
qed.

lemma full_r_initialized_independent
    (A <: FullClient {-FullSession,-Independent,-RFailure,-FullLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  phoare[IndependentGame(FullRFailureContext(A)).run :
    FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs ==> res] <=
    (bigi predT (fun _ => exhaustion_charge (155135+qr+qs*full_r_sign_cost)) 0 qs).
proof.
  move=> hqr hqs; have hz : 0 <= 155135 by smt().
  proc; inline FullRFailureContext(A,Independent).run FullRContext(A,Independent).run; wp.
  call (full_r_driver_exhaustion A 155135 qr qs hz hqr hqs).
  call keygen_history_cost; inline Independent.init; auto.
  rewrite /no_r_tails /history_recorded; smt(FMap.mem_empty).
qed.

lemma full_r_context_public_cost
    (A <: FullClient {-FullSession,-Independent,-Physical,-RFailure,-FullLimits,-KeygenInputs}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[FullRContext(A,Independent).run :
    FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\ Independent.queries = [] ==>
    size Independent.queries <= full_public_budget qr qs].
proof.
  move=> hqr hqs.
  have he : equiv[FullRContext(A,Independent).run ~ FullContext(A,Independent).run :
    ={glob A,glob Independent,glob FullLimits,glob KeygenInputs} ==> ={glob Independent}]
    by symmetry; conseq (full_r_context_erases A Independent); smt().
  conseq he (full_context_public_cost A qr qs hqr hqs).
  + move=> &m hm; exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}
      Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}; smt().
  rewrite /full_public_budget; smt().
qed.

lemma full_r_failure_context_public_cost
    (A <: FullClient {-FullSession,-Independent,-Physical,-RFailure,-FullLimits,-KeygenInputs}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[FullRFailureContext(A,Independent).run :
    FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\ Independent.queries = [] ==>
    size Independent.queries <= full_public_budget qr qs].
proof.
  move=> hqr hqs; proc; call (full_r_context_public_cost A qr qs hqr hqs); auto.
qed.

lemma full_r_initialized_physical
    (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent})
    qr qs &m :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => FullLimits.raw_cap{m} = qr => FullLimits.sign_cap{m} = qs =>
  Pr[RealGame(FullRFailureContext(A)).run() @ &m : res] <=
    bigi predT (fun _ => exhaustion_charge (155135+qr+qs*full_r_sign_cost)) 0 qs +
    (full_public_budget qr qs)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  have hll : forall (O <: PrefixOracle {-FullRFailureContext(A)}),
    islossless O.hash => islossless O.derive => islossless FullRFailureContext(A,O).run.
  + move=> O hh hd; exact (full_r_failure_context_lossless A O ha hh hd).
  have hq : 0 <= full_public_budget qr qs by rewrite /full_public_budget /signing_budget; smt().
  have hb : hoare[FullRFailureContext(A,Independent).run : Independent.queries = [] /\
    (glob FullRFailureContext(A)) = (glob FullRFailureContext(A)){m} ==>
    size Independent.queries <= full_public_budget qr qs].
  + conseq (full_r_failure_context_public_cost A qr qs hqr hqs); auto; smt().
  have hp := physical_to_independent_at_state (FullRFailureContext(A))
    (full_public_budget qr qs) &m hll hq hb.
  have hi : Pr[IndependentGame(FullRFailureContext(A)).run() @ &m : res] <=
    bigi predT (fun _ => exhaustion_charge (155135+qr+qs*full_r_sign_cost)) 0 qs
    by byphoare (full_r_initialized_independent A qr qs hqr hqs) => //.
  smt().
qed.
