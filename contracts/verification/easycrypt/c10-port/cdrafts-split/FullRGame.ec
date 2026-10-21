(* Complete keygen, adaptive session and final verification with private R
   observation. Erasing that observation gives the original complete game. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import PreparedGrind.
require import RawSigner RawSignature FullSession RObservedSigner FullRSession FullRBound.

module FullRDriver (A : FullClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullRSession(O).init(seed,root,qr,qs);
    forged <@ A(FullRSession(O)).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.

module FullRContext (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ FullRDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

module FullRFailureContext (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var result;
    result <@ FullRContext(A,O).run();
    return RFailure.bad;
  }
}.

lemma full_r_failure_context_event (A <: FullClient) (O <: PrefixOracle) :
  hoare[FullRFailureContext(A,O).run : true ==> res = RFailure.bad].
proof. proc; call (_ : true); auto. qed.

lemma full_r_client_erases (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  equiv[A(FullSession(O)).run ~ A(FullRSession(O)).run :
    ={arg,glob A,glob FullSession,glob O} ==> ={res,glob A,glob FullSession,glob O}].
proof.
  proc (={glob FullSession,glob O}) => //.
  + by conseq (full_r_hash_erases O).
  by conseq (full_r_sign_erases O); smt().
qed.

lemma full_r_driver_erases (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  equiv[FullDriver(A,O).run ~ FullRDriver(A,O).run :
    ={arg,glob A,glob O} ==> ={res,glob A,glob FullSession,glob O}].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob FullSession,glob O}).
  + call (full_r_client_erases A O); call (full_r_init_erases O); auto.
  sp 1 1; if; first by auto.
  + call (_ : ={glob O}); first by sim.
    auto.
  by auto.
qed.

lemma full_r_context_erases (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure,-FullLimits,-KeygenInputs}) :
  equiv[FullContext(A,O).run ~ FullRContext(A,O).run :
    ={glob A,glob O,glob FullLimits,glob KeygenInputs} ==>
    ={res,glob A,glob O,glob FullSession}].
proof.
  proc; call (full_r_driver_erases A O).
  call (_ : ={glob O,glob KeygenInputs}); first by sim.
  auto.
qed.

lemma full_r_final_verification_preserves_event
    (A <: FullClient {-FullSession,-Independent,-RFailure}) :
  equiv[FullRRun(A).run ~ FullRDriver(A,Independent).run :
    ={arg,glob A,glob Independent} ==> ={RFailure.bad}].
proof.
  proc; seq 2 2 : (={seed,root,qr,qs,forged,glob A,glob Independent,glob FullSession,RFailure.bad}).
  + by sim.
  sp 0 1; if{2}.
  + call{2} (signer_verify_lossless Independent independent_hash_ll); auto.
  by auto.
qed.

lemma full_r_driver_lossless (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless FullRDriver(A,O).run.
proof.
  move=> ha hh hd; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (FullRSession(O)) (full_hash_lossless O hh) (full_r_sign_lossless O hh hd)).
    inline FullRSession(O).init FullSession(O).init; auto.
  sp 1; if; auto; call (signer_verify_lossless O hh); auto.
qed.

lemma full_r_context_lossless (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless FullRContext(A,O).run.
proof.
  move=> ha hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; call (full_r_driver_lossless A O ha hh hd).
  call (keygen_preparation_lossless (PreparationView(O)) hvh hvw hvf); auto.
qed.

lemma full_r_failure_context_lossless (A <: FullClient {-FullSession,-RFailure})
    (O <: PrefixOracle {-A,-FullSession,-RFailure}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless FullRFailureContext(A,O).run.
proof.
  move=> ha hh hd; proc; call (full_r_context_lossless A O ha hh hd); auto.
qed.
