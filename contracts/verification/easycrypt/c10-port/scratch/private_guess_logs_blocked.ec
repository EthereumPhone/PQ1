(* Passive log of forwarded client hash inputs, excluding internal signer hashes. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner FullSession ExposureLog.

module ClientQueryLog = {
  var inputs : raw_input list
  var output : raw_input * raw_signature
}.
module QueryExposureSession (O : PrefixOracle) = {
  proc hash(x : raw_input) : digest = {
    var result;
    if (true) {
      ClientQueryLog.inputs <- rcons ClientQueryLog.inputs x;
    }
    result <@ FullSession(O).hash(x);
    return result;
  }
  proc sign = ExposureSession(O).sign
}.

lemma client_query_hash_projection (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [ExposureSession(O).hash ~ QueryExposureSession(O).hash :
    ={arg,glob O,glob FullSession,glob ExposureLog} ==>
    ={res,glob O,glob FullSession,glob ExposureLog}].
proof.
  proc; inline FullSession(O).hash; if{2}; sim.
qed.

lemma client_query_client_projection
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  equiv [A(ExposureSession(O)).run ~ A(QueryExposureSession(O)).run :
    ={arg,glob A,glob O,glob FullSession,glob ExposureLog} ==>
    ={res,glob A,glob O,glob FullSession,glob ExposureLog}].
proof.
  proc (={glob O,glob FullSession,glob ExposureLog}) => //.
  + conseq (client_query_hash_projection O); smt().
  by sim.
qed.

op client_query_accounting (inputs : raw_input list) calls limit = size inputs=calls /\ 0<=calls<=limit.

lemma client_query_hash_accounting (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  hoare [QueryExposureSession(O).hash :
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit].
proof.
  proc; inline FullSession(O).hash; sp 0; if.
  + rcondt 4; first by auto.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite /client_query_accounting; smt(size_rcons).
  rcondf 3; first by auto.
  auto.
qed.

lemma client_query_sign_accounting (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) :
  hoare [QueryExposureSession(O).sign :
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit].
proof.
  proc; inline FullSession(O).sign; wp; sp 4; if; auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma client_query_client_accounting
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog})
  (O <: PrefixOracle {-A,-FullSession,-ExposureLog,-ClientQueryLog}) :
  hoare [A(QueryExposureSession(O)).run :
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit ==>
    client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit].
proof.
  proc (client_query_accounting ClientQueryLog.inputs FullSession.raw_calls FullSession.raw_limit) => //.
  + exact (client_query_hash_accounting O).
  exact (client_query_sign_accounting O).
qed.

lemma client_query_sign_keeps_inputs
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 :
  hoare [QueryExposureSession(O).sign : ClientQueryLog.inputs=inputs0 ==>
    ClientQueryLog.inputs=inputs0].
proof.
  proc; inline FullSession(O).sign; wp; sp 4; if; auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma client_query_hash_exact
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 x0 calls0 limit0 :
  hoare [QueryExposureSession(O).hash :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\ FullSession.raw_calls=calls0 /\ FullSession.raw_limit=limit0 ==>
    ClientQueryLog.inputs=(if calls0<limit0 then rcons inputs0 x0 else inputs0)].
proof.
  proc; inline FullSession(O).hash; if.
  + rcondt 4; first by auto.
    wp; call (_ : true ==> true); first by trivial.
    auto; smt().
  rcondf 3; first by auto.
  auto; smt().
qed.
