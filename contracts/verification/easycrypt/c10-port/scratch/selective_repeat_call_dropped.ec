(* Two forwarded calls with an identical input are two observations. *)
require import AllCore List.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner FullSession ExposureLog ClientQueryLog.

module ClientQueryReplay (O : PrefixOracle) = {
  proc run(x : raw_input) : unit = {
    var d;
    d <@ QueryExposureSession(O).hash(x);
  }
}.
lemma forwarded_query_exact_count
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 x0 calls0 cap :
  hoare [QueryExposureSession(O).hash :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\ FullSession.raw_calls=calls0 /\
    FullSession.raw_limit=cap /\ calls0<cap ==>
    ClientQueryLog.inputs=rcons inputs0 x0 /\ FullSession.raw_calls=calls0+1 /\ FullSession.raw_limit=cap].
proof.
  proc; inline FullSession(O).hash; sp 0; if.
  + rcondt 4; first by auto.
    wp; call (_ : true ==> true); first by trivial.
    auto; smt().
  rcondf 3; first by auto.
  auto; smt().
qed.

lemma repeated_query_recorded_twice
  (O <: PrefixOracle {-FullSession,-ExposureLog,-ClientQueryLog}) inputs0 x0 calls0 cap :
  hoare [ClientQueryReplay(O).run :
    ClientQueryLog.inputs=inputs0 /\ x=x0 /\ FullSession.raw_calls=calls0 /\
    FullSession.raw_limit=cap /\ calls0+2<=cap ==>
    ClientQueryLog.inputs=rcons (rcons inputs0 x0) x0 /\ FullSession.raw_calls=calls0+2].
proof.
  proc; call (forwarded_query_exact_count O (rcons inputs0 x0) x0 (calls0+1) cap).
  call (forwarded_query_exact_count O inputs0 x0 calls0 cap); auto; smt().
qed.
