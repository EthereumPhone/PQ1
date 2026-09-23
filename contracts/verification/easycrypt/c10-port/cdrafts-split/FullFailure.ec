(* An exhausted signer never resumes or wins the byte/structured experiment.
   Returning None is an experiment device, not a recoverable Rust panic API. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind.
require import RawSigner RawSignature FullSession.

lemma full_failed_query_stops (O <: PrefixOracle {-FullSession}) g c messages :
  hoare[FullSession(O).sign : FullSession.failed /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages ==>
    res = None /\ FullSession.failed /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages].
proof. proc; rcondf 2; auto; smt(). qed.

lemma full_win_has_no_failure (A <: FullClient {-FullSession})
  (O <: PrefixOracle {-A,-FullSession}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive =>
  hoare[FullDriver(A,O).run : true ==> res => !FullSession.failed].
proof.
  move=> ha hh hd; proc; seq 2 : true.
  + call (_ : true ==> true).
    - by conseq (ha (FullSession(O)) (full_hash_lossless O hh) (full_sign_lossless O hh hd)).
    inline FullSession(O).init; auto.
  sp 1; if; last by auto.
  call (_ : true ==> true); first by conseq (signer_verify_lossless O hh).
  auto.
qed.
