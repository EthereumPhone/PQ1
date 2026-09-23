(* Whole-session costs instantiate the same-secret prefix hybrid budget. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrindCost KeygenExhaustion.
require import RawSigner RawSignerCost FullSession.

lemma full_client_physical_cost (A <: FullClient {-FullSession,-Shared,-Physical}) q0 :
  hoare[A(FullSession(Physical)).run :
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    Shared.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646) ==>
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    Shared.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646)].
proof.
  proc (0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    Shared.calls <= q0+FullSession.raw_calls+FullSession.sign_calls*(4*signing_budget+435646)) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Shared.calls; elim* => z; call (physical_hash_count z); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Shared.calls; elim* => z; call (signer_sign_physical_cost z); auto; smt().
qed.
lemma full_driver_physical_cost (A <: FullClient {-FullSession,-Shared,-Physical}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[FullDriver(A,Physical).run : qr = qr0 /\ qs = qs0 /\ Shared.calls <= q0 ==>
    Shared.calls <= q0+qr0+qs0*(4*signing_budget+435646)+771].
proof.
  move=> hqr hqs; proc; seq 2 : (Shared.calls <= q0+qr0+qs0*(4*signing_budget+435646)).
  + call (full_client_physical_cost A q0); inline FullSession(Physical).init;
    auto; rewrite /signing_budget; smt().
  sp 1; if; last by auto; smt().
  exists* Shared.calls; elim* => z; call (signer_verify_physical_cost z); auto; smt().
qed.
lemma full_context_physical_cost (A <: FullClient {-FullSession,-Shared,-Physical,-FullLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[FullContext(A,Physical).run : FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\
    Shared.calls = 0 ==>
    Shared.calls <= 177151+qr+qs*(4*signing_budget+435646)+771].
proof.
  move=> hqr hqs; proc; call (full_driver_physical_cost A 177151 qr qs hqr hqs).
  call (keygen_physical_cost 0); auto; smt().
qed.

lemma full_client_public_cost (A <: FullClient {-FullSession,-Independent,-Physical}) q0 :
  hoare[A(FullSession(Independent)).run :
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892) ==>
    0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)].
proof.
  proc (0 <= FullSession.raw_calls <= FullSession.raw_limit /\
    0 <= FullSession.sign_calls <= FullSession.sign_limit /\
    size Independent.queries <= q0+FullSession.raw_calls+FullSession.sign_calls*(3*signing_budget+364892)) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => zs; call (signer_sign_public_cost (size zs)); auto; smt().
qed.
lemma full_driver_public_cost (A <: FullClient {-FullSession,-Independent,-Physical}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[FullDriver(A,Independent).run : qr = qr0 /\ qs = qs0 /\ size Independent.queries <= q0 ==>
    size Independent.queries <= q0+qr0+qs0*(3*signing_budget+364892)+771].
proof.
  move=> hqr hqs; proc; seq 2 : (size Independent.queries <= q0+qr0+qs0*(3*signing_budget+364892)).
  + call (full_client_public_cost A q0); inline FullSession(Independent).init;
    auto; rewrite /signing_budget; smt().
  sp 1; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (signer_verify_public_cost (size zs)); auto; smt().
qed.
lemma full_context_public_cost (A <: FullClient {-FullSession,-Independent,-Physical,-FullLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[FullContext(A,Independent).run : FullLimits.raw_cap = qr /\ FullLimits.sign_cap = qs /\
    size Independent.queries = 0 ==>
    size Independent.queries <= 155135+qr+qs*(3*signing_budget+364892)+771].
proof.
  move=> hqr hqs; proc; call (full_driver_public_cost A 155135 qr qs hqr hqs).
  call keygen_preparation_cost; auto; smt(size_eq0).
qed.
