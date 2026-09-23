(* Key generation and an adaptive bounded grinding session under one key. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid PrefixGames PrefixIdeal PrefixState.
require import KeygenPrefixes PreparedGrind PreparedHistory KeygenExhaustion RawKeygenCost.
require import RSession RSessionCost RSessionBound GrindExhaustion.
import RealOrder Bigreal BRA.

module SessionLimits = { var raw_cap, sign_cap : int }.

module SessionDriver (A : RClient) (O : PrefixOracle) = {
  proc run(seed root : raw_input, qr qs : int) : bool = {
    RSession(O).init(seed,root,qr,qs);
    A(RSession(O)).run(seed,root);
    return RSession.bad;
  }
}.

module SessionKeygenContext (A : RClient) (O : PrefixOracle) = {
  proc run() : bool = {
    var inputs, result;
    inputs <@ KeygenPreparation(PreparationView(O)).run();
    result <@ SessionDriver(A,O).run(inputs.`3,inputs.`4,SessionLimits.raw_cap,SessionLimits.sign_cap);
    return result;
  }
}.

lemma driver_cost (A <: RClient {-RSession,-Independent}) q0 qr0 qs0 :
  0 <= qr0 => 0 <= qs0 =>
  hoare[SessionDriver(A,Independent).run :
    qr = qr0 /\ qs = qs0 /\ size Independent.queries <= q0 ==>
    size Independent.queries <= q0+qr0+qs0*signing_budget].
proof.
  move=> hqr hqs; proc; call (client_public_cost A q0).
  inline RSession(Independent).init; auto; rewrite /signing_budget; smt().
qed.

lemma session_keygen_cost (A <: RClient {-RSession,-Independent,-SessionLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  hoare[SessionKeygenContext(A,Independent).run : Independent.queries = [] /\
    SessionLimits.raw_cap = qr /\ SessionLimits.sign_cap = qs ==>
    size Independent.queries <= 155135+qr+qs*signing_budget].
proof.
  move=> hqr hqs; proc; call (driver_cost A 155135 qr qs hqr hqs).
  call keygen_preparation_cost; auto; smt().
qed.

lemma session_keygen_lossless (A <: RClient {-RSession})
  (O <: PrefixOracle {-A,-RSession,-KeygenInputs,-SessionLimits}) :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  islossless O.hash => islossless O.derive => islossless SessionKeygenContext(A,O).run.
proof.
  move=> ha hh hd; proc; inline SessionDriver(A,O).run; wp.
  call (client_lossless A O ha hh hd); inline RSession(O).init; wp.
  have [#] hph hpw hpf := preparation_view_lossless O hh hd.
  call (keygen_preparation_lossless (PreparationView(O)) hph hpw hpf); auto.
qed.

lemma driver_independent (A <: RClient {-RSession,-Independent}) :
  equiv[SessionDriver(A,Independent).run ~ SessionRun(A).run :
    ={seed,root,qr,qs,glob A,glob Independent,glob RSession} ==> ={res,glob Independent,glob RSession,glob A}].
proof. proc; sim. qed.

lemma session_result_bad (A <: RClient {-RSession,-Independent}) seed root qr qs &m :
  Pr[SessionRun(A).run(seed,root,qr,qs) @ &m : res] =
  Pr[SessionRun(A).run(seed,root,qr,qs) @ &m : RSession.bad].
proof.
  byequiv (_ : ={glob A,glob Independent,glob RSession,seed,root,qr,qs} ==>
    res{1} = RSession.bad{2}) => //.
  proc; sim.
qed.

lemma driver_exhaustion (A <: RClient {-RSession,-Independent}) q0 qr0 qs0 :
  0 <= q0 => 0 <= qr0 => 0 <= qs0 =>
  phoare[SessionDriver(A,Independent).run : qr = qr0 /\ qs = qs0 /\
    size seed = 32 /\ size root = 32 /\ size Independent.queries <= q0 /\
    RawTrial.history_recorded Independent.rawhistory Independent.queries /\
    no_r_tails Independent.secrethistory ==>
    res] <= (bigi predT (fun _ => exhaustion_charge (q0+qr0+qs0*signing_budget)) 0 qs0).
proof.
  move=> hq hqr hqs; bypr => &m [#] hqr0 hqs0 hs hr hsize hrecord hnor.
  have he : Pr[SessionDriver(A,Independent).run(seed{m},root{m},qr{m},qs{m}) @ &m : res] =
      Pr[SessionRun(A).run(seed{m},root{m},qr{m},qs{m}) @ &m : res]
    by byequiv (driver_independent A) => //.
  rewrite he (session_result_bad A) hqr0 hqs0.
  exact (adaptive_session_exhaustion A q0 qr0 qs0 seed{m} root{m} &m hq hqr hqs hs hr hsize hrecord hnor).
qed.
