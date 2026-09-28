(* Adaptive EUF experiment for the structured raw signer. All accepted signer
   calls, public queries and final verification share one persistent oracle.
   The byte-codec/Rust correspondence is a separate obligation. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes PreparedGrind.
require import KeygenExhaustion RawSigner RawSignature.

module FullLimits = { var raw_cap, sign_cap : int }.
module type FullClientOracle = {
  proc hash(x : raw_input) : digest
  proc sign(random message shuffle : raw_input) : raw_signature option
}.
module type FullClient (O : FullClientOracle) = {
  proc run(seed root : raw_input) : raw_input * raw_signature { O.hash, O.sign }
}.
module FullSession (O : PrefixOracle) = {
  var seed, root : raw_input
  var raw_limit, sign_limit, raw_calls, sign_calls : int
  var signed_messages : raw_input list
  var failed : bool
  proc init(ps pr : raw_input, qr qs : int) : unit = {
    seed <- ps; root <- pr; raw_limit <- qr; sign_limit <- qs;
    raw_calls <- 0; sign_calls <- 0; signed_messages <- []; failed <- false;
  }
  proc hash(x : raw_input) : digest = {
    var result; result <- nseq 256 false;
    if (raw_calls < raw_limit) {
      result <@ O.hash(x); raw_calls <- raw_calls+1;
    }
    return result;
  }
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result; result <- None;
    if (!failed /\ size message = 32 /\ (size random = 0 \/ size random = 16) /\
        size shuffle = 32 /\ sign_calls < sign_limit) {
      result <@ RawSigner(O).sign(seed,root,random,message,shuffle);
      sign_calls <- sign_calls+1;
      if (result <> None) { signed_messages <- rcons signed_messages message; }
      else { failed <- true; }
    }
    return result;
  }
}.
module FullDriver (A : FullClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    var forged, result;
    FullSession(O).init(seed,root,qr,qs);
    forged <@ A(FullSession(O)).run(seed,root);
    result <- false;
    if (!FullSession.failed /\ size forged.`1 = 32 /\ signature_width forged.`2 /\
        !List.mem FullSession.signed_messages forged.`1) {
      result <@ RawSigner(O).verify(seed,root,forged.`1,forged.`2);
    }
    return result;
  }
}.
module FullContext (A : FullClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ FullDriver(A,O).run(inputs.`3,inputs.`4,FullLimits.raw_cap,FullLimits.sign_cap);
    return result;
  }
}.

lemma full_hash_lossless (O <: PrefixOracle {-FullSession}) :
  islossless O.hash => islossless FullSession(O).hash.
proof. move=> hh; proc; sp 1; if; auto; wp; call hh; auto. qed.
lemma full_sign_lossless (O <: PrefixOracle {-FullSession}) :
  islossless O.hash => islossless O.derive => islossless FullSession(O).sign.
proof.
  move=> hh hd; proc; sp 1; if; auto; wp; call (signer_sign_lossless O hh hd); auto.
qed.
lemma full_driver_lossless (A <: FullClient {-FullSession}) (O <: PrefixOracle {-A,-FullSession}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless FullDriver(A,O).run.
proof.
  move=> ha hh hd; proc; seq 2 : true 1%r 1%r 0%r 0%r => //.
  + call (ha (FullSession(O)) (full_hash_lossless O hh) (full_sign_lossless O hh hd)).
    inline FullSession(O).init; auto.
  sp 1; if; auto; call (signer_verify_lossless O hh); auto.
qed.
lemma full_context_lossless (A <: FullClient {-FullSession}) (O <: PrefixOracle {-A,-FullSession}) :
  (forall (V <: FullClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless FullContext(A,O).run.
proof.
  move=> ha hh hd; have [#] hvh hvw hvf := preparation_view_lossless O hh hd.
  proc; call (full_driver_lossless A O ha hh hd).
  call (keygen_preparation_lossless (PreparationView(O)) hvh hvw hvf); auto.
qed.
