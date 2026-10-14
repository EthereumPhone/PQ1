(* Cost bounds for the explicit wrapper context. The internal verifier is
   charged per admitted attempt and the final candidate verifier once more.
   Refused attempts are counted without requiring successful release.
   These lemmas do not instantiate a cryptographic reduction for this context. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrindCost KeygenExhaustion.
require import RawSigner RawSignerCost RawWrapper RawWrapperCost WrapperSession.

lemma wrapper_client_physical_cost (A <: WrapperClient {-WrapperSession,-Shared,-Physical}) q0 :
  hoare[A(WrapperSession(Physical)).run :
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    Shared.calls <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_physical_budget ==>
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    Shared.calls <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_physical_budget].
proof.
  proc (0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    Shared.calls <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_physical_budget) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Shared.calls; elim* => z; call (physical_hash_count z); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Shared.calls; elim* => z; call (wrapper_physical_cost z); auto; smt().
qed.
lemma wrapper_driver_physical_cost (A <: WrapperClient {-WrapperSession,-Shared,-Physical}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[WrapperDriver(A,Physical).run : qr = qr0 /\ qs = qs0 /\ Shared.calls <= q0 ==>
    Shared.calls <= q0+qr0+qs0*wrapper_physical_budget+771].
proof.
  move=> hqr hqs; proc; seq 2 : (Shared.calls <= q0+qr0+qs0*wrapper_physical_budget).
  + call (wrapper_client_physical_cost A q0); inline WrapperSession(Physical).init;
    auto; rewrite /wrapper_physical_budget /wrapper_public_budget /signing_budget; smt().
  sp 1; if; last by auto; smt().
  exists* Shared.calls; elim* => z; call (signer_verify_physical_cost z); auto; smt().
qed.
lemma wrapper_context_physical_cost (A <: WrapperClient {-WrapperSession,-Shared,-Physical,-WrapperLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[WrapperContext(A,Physical).run : WrapperLimits.raw_cap = qr /\ WrapperLimits.sign_cap = qs /\
    Shared.calls = 0 ==>
    Shared.calls <= 177151+qr+qs*wrapper_physical_budget+771].
proof.
  move=> hqr hqs; proc; call (wrapper_driver_physical_cost A 177151 qr qs hqr hqs).
  call (keygen_physical_cost 0); auto; smt().
qed.

lemma wrapper_client_public_cost (A <: WrapperClient {-WrapperSession,-Independent,-Physical}) q0 :
  hoare[A(WrapperSession(Independent)).run :
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    size Independent.queries <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget ==>
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    size Independent.queries <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget].
proof.
  proc (0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit /\
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit /\
    size Independent.queries <= q0+WrapperSession.raw_calls+WrapperSession.sign_calls*wrapper_public_budget) => //.
  + proc; sp 1; if; last by auto.
    wp; exists* Independent.queries; elim* => zs; call (independent_hash_count (size zs)); auto; smt().
  proc; sp 1; if; last by auto.
  wp; exists* Independent.queries; elim* => zs; call (wrapper_public_cost (size zs)); auto; smt().
qed.
lemma wrapper_driver_public_cost (A <: WrapperClient {-WrapperSession,-Independent,-Physical}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[WrapperDriver(A,Independent).run : qr = qr0 /\ qs = qs0 /\ size Independent.queries <= q0 ==>
    size Independent.queries <= q0+qr0+qs0*wrapper_public_budget+771].
proof.
  move=> hqr hqs; proc; seq 2 : (size Independent.queries <= q0+qr0+qs0*wrapper_public_budget).
  + call (wrapper_client_public_cost A q0); inline WrapperSession(Independent).init;
    auto; rewrite /wrapper_physical_budget /wrapper_public_budget /signing_budget; smt().
  sp 1; if; last by auto; smt().
  exists* Independent.queries; elim* => zs; call (signer_verify_public_cost (size zs)); auto; smt().
qed.
lemma wrapper_context_public_cost (A <: WrapperClient {-WrapperSession,-Independent,-Physical,-WrapperLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[WrapperContext(A,Independent).run : WrapperLimits.raw_cap = qr /\ WrapperLimits.sign_cap = qs /\
    size Independent.queries = 0 ==>
    size Independent.queries <= 155135+qr+qs*wrapper_public_budget+771].
proof.
  move=> hqr hqs; proc; call (wrapper_driver_public_cost A 155135 qr qs hqr hqs).
  call keygen_preparation_cost; auto; smt(size_eq0).
qed.
