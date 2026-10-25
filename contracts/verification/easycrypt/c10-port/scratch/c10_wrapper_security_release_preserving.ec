(* Private observers for the existing wrapper. Internal signing results are
   not exposure entries: an entry is appended only when the wrapper releases
   its result to the adaptive client. Hash logs record admitted client calls. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner RawSignature.
require import WrapperSession WrapperLossless ExposureLog ClientQueryLog.

module WrapperExposureSession (O : PrefixOracle) = {
  proc hash = WrapperSession(O).hash
  proc sign(random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var result;
    result <@ WrapperSession(O).sign(random,message,shuffle_a,shuffle_b,ready,final_guard);
    if ((fun b => b) (result <> None)) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.
module WrapperQueryExposureSession (O : PrefixOracle) = {
  proc hash(x : raw_input) : digest = {
    var result;
    if (WrapperSession.raw_calls < WrapperSession.raw_limit) {
      ClientQueryLog.inputs <- rcons ClientQueryLog.inputs x;
    }
    result <@ WrapperSession(O).hash(x);
    return result;
  }
  proc sign = WrapperExposureSession(O).sign
}.

lemma wrapper_exposure_sign_projection
    (O <: PrefixOracle {-WrapperSession,-ExposureLog}) :
  equiv[WrapperSession(O).sign ~ WrapperExposureSession(O).sign :
    ={arg,glob O,glob WrapperSession} ==> ={res,glob O,glob WrapperSession}].
proof. proc; inline WrapperSession(O).sign; sim. qed.

lemma wrapper_exposure_records
    (O <: PrefixOracle {-WrapperSession,-ExposureLog}) entries0 message0 :
  hoare[WrapperExposureSession(O).sign :
    ExposureLog.entries=entries0 /\ message=message0 ==>
    ExposureLog.entries=(if res=None then entries0 else rcons entries0 (message0,oget res))].
proof.
  proc; wp; call (_ : true ==> true); first by trivial.
  auto; move=> &hr [he hm] result0; rewrite he hm.
  by case (result0=None).
qed.

lemma wrapper_query_hash_projection
    (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  equiv[WrapperExposureSession(O).hash ~ WrapperQueryExposureSession(O).hash :
    ={arg,glob O,glob WrapperSession,glob ExposureLog} ==>
    ={res,glob O,glob WrapperSession,glob ExposureLog}].
proof. proc; inline WrapperSession(O).hash; if{2}; sim. qed.

lemma wrapper_logged_client_projection
    (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog})
    (O <: PrefixOracle {-A,-WrapperSession,-ExposureLog,-ClientQueryLog}) :
  equiv[A(WrapperSession(O)).run ~ A(WrapperQueryExposureSession(O)).run :
    ={arg,glob A,glob O,glob WrapperSession} ==>
    ={res,glob A,glob O,glob WrapperSession}].
proof.
  proc (={glob O,glob WrapperSession}) => //.
  + proc; inline WrapperSession(O).hash; if{2}; sim.
  conseq (wrapper_exposure_sign_projection O); smt().
qed.

lemma wrapper_query_hash_exact
    (O <: PrefixOracle {-WrapperSession,-ExposureLog,-ClientQueryLog})
    inputs0 x0 calls0 limit0 :
  hoare[WrapperQueryExposureSession(O).hash :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\
    WrapperSession.raw_calls=calls0 /\ WrapperSession.raw_limit=limit0 ==>
    ClientQueryLog.inputs=(if calls0<limit0 then rcons inputs0 x0 else inputs0)].
proof.
  proc; inline WrapperSession(O).hash; if.
  + rcondt 4; first by auto.
    wp; call (_ : true ==> true); first by trivial.
    auto; smt().
  rcondf 3; first by auto.
  auto; smt().
qed.

lemma wrapper_exposure_sign_lossless
    (O <: PrefixOracle {-WrapperSession,-ExposureLog}) :
  islossless O.hash => islossless O.derive => islossless WrapperExposureSession(O).sign.
proof.
  move=> hh hd; proc; wp; call (wrapper_sign_lossless O hh hd); auto.
qed.

lemma wrapper_query_hash_lossless
    (O <: PrefixOracle {-WrapperSession,-ClientQueryLog}) :
  islossless O.hash => islossless WrapperQueryExposureSession(O).hash.
proof. move=> hh; proc; call (wrapper_hash_lossless O hh); auto. qed.
