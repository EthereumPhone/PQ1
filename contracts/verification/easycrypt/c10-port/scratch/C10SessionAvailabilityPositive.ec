require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RSession SessionKeygen RawSession SessionClosedForm RawSessionCost.
lemma checked_adaptive_availability
  (A <: RClient {-RSession,-Independent,-SessionLimits,-Physical,-Hybrid,-Shared}) qr qs &m :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => SessionLimits.raw_cap{m} = qr => SessionLimits.sign_cap{m} = qs =>
  Pr[RawSessionGame(A).run() @ &m : res] <= session_availability_bound qr qs.
proof. exact (raw_session_exhaustion_explicit A qr qs &m). qed.
lemma checked_session_physical_cost
  (A <: RClient {-RSession,-Shared,-Physical,-SessionLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[RawSessionGame(A).run : SessionLimits.raw_cap = qr /\ SessionLimits.sign_cap = qs ==>
    Shared.calls <= 177151+qr+2*qs*signing_budget].
proof. exact (raw_session_total_cost A qr qs). qed.
