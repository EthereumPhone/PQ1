(* Actual persistent signing failure in the original initialized byte game.
   R exhaustion uses its returned-event bound; WOTS exhaustion is bounded
   directly in the physical cache, including every adaptive prefill query. *)
require import AllCore List Distr FMap StdOrder Ring.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen KeygenExhaustion FullSession ByteSession.
require import RObservedSigner FullRGame ByteRAvailability FullAvailabilityTrace.
require import WotsRejectDomain PhysicalRejectBound.
import RField RealOrder.

op byte_total_availability_charge qr qs =
  byte_r_availability_charge qr qs + wots_domain_charge signing_budget.

lemma signing_budget_fits_wots_schedule : 0<=signing_budget<=2^256.
proof.
  by rewrite /signing_budget (_ : 256=2*2*2*2*2*2*2*2) 1://
    !IntID.exprM !IntID.expr2.
qed.

lemma full_r_observer_probability
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(FullRContext(A)).run() @ &m : RFailure.bad] =
    Pr[RealGame(FullRFailureContext(A)).run() @ &m : res].
proof.
  byequiv (_ : ={glob A,glob FullLimits,glob KeygenInputs,glob FullSession,
    glob Physical,glob Shared,RFailure.bad} ==> RFailure.bad{1}=res{2}) => //.
  proc; inline FullRFailureContext(A,Physical).run; sim.
qed.

lemma byte_failed_probability_erases
    (A <: ByteClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) &m :
  Pr[RealGame(ByteContext(A)).run() @ &m : FullSession.failed] =
    Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : FullSession.failed].
proof. by byequiv (byte_r_initialized_erases A) => //. qed.

lemma byte_total_initialized_availability
    (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-RFailure,-Physical,-Hybrid,-Shared,-Independent})
    qr qs &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[RealGame(ByteContext(A)).run() @ &m : FullSession.failed] <=
    byte_total_availability_charge qr qs.
proof.
  move=> ha hqr hqs hr hs.
  pose seed0 := pad (node KeygenInputs.public_seed{m}).
  have hR := byte_r_initialized_exhaustion A qr qs &m ha hqr hqs hr hs.
  rewrite -(full_r_observer_probability (ByteLift(A)) &m) in hR.
  have hW := physical_wots_domain_bound (FullRContext(ByteLift(A))) seed0 signing_budget &m
    signing_budget_fits_wots_schedule.
  have hz : Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : FullSession.failed /\
    !full_availability_failure seed0 Shared.history RFailure.bad]=0%r.
  + byphoare (_ : pad (node KeygenInputs.public_seed)=seed0 ==> FullSession.failed /\
      !full_availability_failure seed0 Shared.history RFailure.bad) => //.
    hoare; conseq (full_availability_initialized (ByteLift(A)) seed0); smt().
  have hb : Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : FullSession.failed] <=
    Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m :
      full_availability_failure seed0 Shared.history RFailure.bad].
  + rewrite Pr[mu_split (full_availability_failure seed0 Shared.history RFailure.bad)] hz /=.
    by rewrite Pr[mu_sub]; smt().
  have hu : Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m :
      full_availability_failure seed0 Shared.history RFailure.bad] <=
    Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : RFailure.bad] +
    Pr[RealGame(FullRContext(ByteLift(A))).run() @ &m : wots_domain_exhausted seed0 signing_budget Shared.history].
  + rewrite /full_availability_failure Pr[mu_or]; smt(ge0_mu).
  rewrite (byte_failed_probability_erases A &m) /byte_total_availability_charge; smt().
qed.
