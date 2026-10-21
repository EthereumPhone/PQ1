(* Actual persistent failed-session state implies nonce exhaustion or a cached
   WOTS exhaustion witness. Refused requests do not set the failed ledger. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames.
require import RawKeygen RawSigner PersistentGrind AcceptedContexts KeygenPrefixes KeygenExhaustion.
require import FullSession RObservedSigner FullRSession FullRGame.
require import WotsRejectDomain WotsPhysicalFailure WotsSignerFailure.

op full_availability_failure seed h rbad = rbad \/ wots_domain_exhausted seed signing_budget h.

lemma physical_hash_extends h0 :
  hoare[Physical.hash : extends h0 Shared.history ==> extends h0 Shared.history].
proof. proc; call (hash_extends h0); auto. qed.

lemma full_availability_hash seed0 :
  hoare[FullRSession(Physical).hash : FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad) ==>
    FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad)].
proof.
  proc; sp 1; if; last by auto.
  exists* Shared.history; elim* => h0; wp; call (physical_hash_extends h0).
  auto; rewrite /full_availability_failure; smt(wots_domain_exhausted_extends extends_refl).
qed.

lemma full_availability_sign seed0 :
  hoare[FullRSession(Physical).sign : FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad) ==>
    FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad)].
proof.
  proc; sp 1; if; last by auto.
  wp; call (physical_observed_sign_failure seed0).
  auto; rewrite /full_availability_failure; smt().
qed.

lemma full_availability_client
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared}) seed0 :
  hoare[A(FullRSession(Physical)).run : FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad) ==>
    FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad)].
proof.
  proc (FullSession.seed=seed0 /\
    (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad)) => //.
  + exact (full_availability_hash seed0).
  exact (full_availability_sign seed0).
qed.

lemma full_availability_driver
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared}) seed0 :
  hoare[FullRDriver(A,Physical).run : seed=seed0 ==>
    FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad].
proof.
  proc; seq 2 : (FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad).
  + call (full_availability_client A seed0).
    inline FullRSession(Physical).init FullSession(Physical).init; auto.
  sp 1; if; last by auto.
  call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma full_availability_context
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) seed0 :
  hoare[FullRContext(A,Physical).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad].
proof.
  proc; call (full_availability_driver A seed0).
  inline KeygenPreparation(PreparationView(Physical)).run; wp.
  call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma full_availability_initialized
    (A <: FullClient {-FullSession,-RFailure,-Physical,-Shared,-FullLimits,-KeygenInputs}) seed0 :
  hoare[RealGame(FullRContext(A)).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.failed => full_availability_failure seed0 Shared.history RFailure.bad].
proof.
  proc; call (full_availability_context A seed0); inline Shared.init; auto.
qed.
