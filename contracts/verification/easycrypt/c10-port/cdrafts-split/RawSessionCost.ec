(* Physical SHA-oracle calls for the entire keygen-plus-grinding session. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid PhysicalKeygenCost KeygenExhaustion.
require import RSession SessionKeygen RawSession.

lemma raw_client_cost (A <: RClient {-RSession,-Shared,-Physical}) q0 :
  hoare[A(RawSession).run :
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    Shared.calls <= q0+RSession.raw_calls+2*RSession.sign_calls*signing_budget ==>
    0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    Shared.calls <= q0+RSession.raw_calls+2*RSession.sign_calls*signing_budget].
proof.
  proc (0 <= RSession.raw_calls <= RSession.raw_limit /\
    0 <= RSession.sign_calls <= RSession.sign_limit /\
    Shared.calls <= q0+RSession.raw_calls+2*RSession.sign_calls*signing_budget) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Shared.calls; elim* => c.
    call (physical_hash_count c); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Shared.calls,Shared.draws; elim* => c d.
  call (grind_cost c d); auto; smt().
qed.

lemma raw_driver_cost (A <: RClient {-RSession,-Shared,-Physical}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[RawSessionDriver(A).run : qr = qr0 /\ qs = qs0 /\ Shared.calls <= q0 ==>
    Shared.calls <= q0+qr0+2*qs0*signing_budget].
proof.
  move=> hqr hqs; proc; call (raw_client_cost A q0).
  inline RSession(Physical).init; auto; rewrite /signing_budget; smt().
qed.

lemma raw_session_total_cost (A <: RClient {-RSession,-Shared,-Physical,-SessionLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[RawSessionGame(A).run : SessionLimits.raw_cap = qr /\ SessionLimits.sign_cap = qs ==>
    Shared.calls <= 177151+qr+2*qs*signing_budget].
proof.
  move=> hqr hqs; proc; call (raw_driver_cost A 177151 qr qs hqr hqs).
  call (keygen_physical_cost 0); inline Shared.init; auto; smt().
qed.
