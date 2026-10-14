(* Cost bounds for the explicit wrapper context. The internal verifier is
   charged per admitted attempt and the final candidate verifier once more.
   Refused attempts are counted without requiring successful release.
   These lemmas do not instantiate a cryptographic reduction for this context. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen PhysicalKeygenCost RoleGrindCost KeygenExhaustion.
require import RawSigner RawSignerCost RawWrapper RawWrapperCost.
(* Adaptive cost context for the abstract wrapper schedule. Every admitted
   attempt is charged, including refusals; later attempts may still run.
   Caller-selected guard booleans only overapproximate environment outcomes.
   All queries share one persistent oracle. No EUF or Rust/session refinement
   theorem follows from this accounting context. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind.
require import RawWrapper.
require import KeygenExhaustion RawSigner RawSignature.

module WrapperLimits = { var raw_cap, sign_cap : int }.
module type WrapperClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option
}.
module type WrapperClient (O : WrapperClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_signature { O.hash, O.sign }
}.
module WrapperSession (O : PrefixOracle) = {
  var seed, root : raw_input
  var raw_limit, sign_limit, raw_calls, sign_calls : int
  var signed_messages : raw_input list
  proc init(ps pr : raw_input, qr qs : int) : unit = {
    seed <- ps; root <- pr; raw_limit <- qr; sign_limit <- qs;
    raw_calls <- 0; sign_calls <- 0; signed_messages <- [];
  }
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (true) {
      result <@ O.hash(x); raw_calls <- raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle_a shuffle_b : raw_input, ready final_guard : bool) : raw_signature option = {
    var result; result <- None;
    if (size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle_a = 32 /\ size shuffle_b = 32 /\ sign_calls < sign_limit) {
      result <@ RawWrapper(O).sign(seed,root,random,message,shuffle_a,shuffle_b,ready,final_guard);
      sign_calls <- sign_calls+1;
      if (result <> None) { signed_messages <- rcons signed_messages message; }
    }
    return result;
  }
}.
module WrapperDriver (A : WrapperClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    WrapperSession(O).init(seed,root,qr,qs);
    forged <@ A(WrapperSession(O)).run(seed,root);
    result <- false;
    if (size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem WrapperSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module WrapperContext (A : WrapperClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ WrapperDriver(A,O).run(inputs.`3,inputs.`4,WrapperLimits.raw_cap,WrapperLimits.sign_cap);
    return result;
  }
}.

(* Full caps and a refused readiness check are explicit normal-return cases. *)
lemma wrapper_sign_full (O <: PrefixOracle {-WrapperSession}) :
  hoare[WrapperSession(O).sign :
    WrapperSession.sign_calls = WrapperSession.sign_limit ==>
    res = None /\ WrapperSession.sign_calls = WrapperSession.sign_limit].
proof.
  proc; rcondf 2; first by auto.
  by auto.
qed.
lemma wrapper_raw_full (O <: PrefixOracle {-WrapperSession}) :
  hoare[WrapperSession(O).hash :
    WrapperSession.raw_calls = WrapperSession.raw_limit ==>
    WrapperSession.raw_calls = WrapperSession.raw_limit].
proof.
  proc; rcondf 2; first by auto.
  by auto.
qed.
lemma wrapper_ready_refusal_charge (O <: PrefixOracle {-WrapperSession}) n :
  hoare[WrapperSession(O).sign :
    WrapperSession.sign_calls = n /\ size message = 32 /\
    (size random = 0 \/ size random = 16) /\ size shuffle_a = 32 /\
    size shuffle_b = 32 /\ n < WrapperSession.sign_limit /\ !ready ==>
    res = None /\ WrapperSession.sign_calls = n+1].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (_ : ready = false ==> res = None).
  + proc; rcondf 2; first by auto.
    by auto.
  auto => />.
qed.

(* Admission charges an attempt even when the wrapper refuses. These exact
   counter facts are separate from the larger hash-query arithmetic. *)
lemma wrapper_attempt_charge (O <: PrefixOracle {-WrapperSession}) n :
  hoare[WrapperSession(O).sign :
    WrapperSession.sign_calls = n /\ size message = 32 /\
    (size random = 0 \/ size random = 16) /\ size shuffle_a = 32 /\
    size shuffle_b = 32 /\ n < WrapperSession.sign_limit ==>
    WrapperSession.sign_calls = n+1].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (_ : true); auto; smt().
qed.
lemma wrapper_sign_cap (O <: PrefixOracle {-WrapperSession}) :
  hoare[WrapperSession(O).sign :
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit ==>
    0 <= WrapperSession.sign_calls <= WrapperSession.sign_limit].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (_ : true); auto; smt().
qed.
lemma wrapper_raw_cap (O <: PrefixOracle {-WrapperSession}) :
  hoare[WrapperSession(O).hash :
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit ==>
    0 <= WrapperSession.raw_calls <= WrapperSession.raw_limit].
proof.
  proc; sp 1; if; last by auto; smt().
  wp; call (_ : true); auto; smt().
qed.


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
