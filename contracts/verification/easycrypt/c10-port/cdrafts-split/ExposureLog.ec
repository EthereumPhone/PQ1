(* Passive private recording of every successful adaptive signing response. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawSigner FullSession.

type signing_exposure = raw_input * raw_signature.
module ExposureLog = { var entries : signing_exposure list }.
module ExposureSession (O : PrefixOracle) = {
  proc hash = FullSession(O).hash
  proc sign(random message shuffle : raw_input) : raw_signature option = {
    var result;
    result <@ FullSession(O).sign(random,message,shuffle);
    if (result <> None) { ExposureLog.entries <- rcons ExposureLog.entries (message,oget result); }
    return result;
  }
}.

lemma exposure_sign_projection (O <: PrefixOracle {-FullSession,-ExposureLog}) :
  equiv [FullSession(O).sign ~ ExposureSession(O).sign :
    ={arg,glob O,glob FullSession} ==> ={res,glob O,glob FullSession}].
proof.
  proc; inline FullSession(O).sign; sim.
qed.

lemma exposure_sign_records (O <: PrefixOracle {-FullSession,-ExposureLog}) entries0 message0 :
  hoare [ExposureSession(O).sign : ExposureLog.entries=entries0 /\ message=message0 ==>
    ExposureLog.entries = if res=None then entries0 else rcons entries0 (message0,oget res)].
proof. proc; wp; call (_ : true ==> true); first by trivial. auto; smt(). qed.

lemma exposure_client_projection
  (A <: FullClient {-FullSession,-ExposureLog}) (O <: PrefixOracle {-A,-FullSession,-ExposureLog}) :
  equiv [A(FullSession(O)).run ~ A(ExposureSession(O)).run :
    ={arg,glob A,glob O,glob FullSession} ==> ={res,glob A,glob O,glob FullSession}].
proof.
  proc (={glob O,glob FullSession}) => //.
  + by sim.
  conseq (exposure_sign_projection O); smt().
qed.
