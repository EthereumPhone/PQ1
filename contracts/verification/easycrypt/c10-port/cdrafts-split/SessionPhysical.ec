(* Single physical secret and raw table for keygen plus all bounded R calls.
   Availability only: complete signature generation and forgery reduction remain separate. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10Counter.
require import PrefixGuess PrefixHybrid PrefixGames PrefixIdeal PrefixState.
require import KeygenPrefixes PreparedHistory KeygenExhaustion RawTrial RSession SessionKeygen GrindExhaustion.
import RealOrder Bigreal BRA.

lemma keygen_history_cost :
  hoare[KeygenPreparation(PreparationView(Independent)).run : Independent.queries = [] /\
    no_r_tails Independent.secrethistory /\ history_recorded Independent.rawhistory Independent.queries ==>
    size Independent.queries <= 155135 /\ size res.`3 = 32 /\ size res.`4 = 32 /\
    no_r_tails Independent.secrethistory /\ history_recorded Independent.rawhistory Independent.queries].
proof.
  conseq keygen_preparation_cost (preparation_preserves_history KeygenPreparation); smt().
qed.

lemma keygen_session_ideal (A <: RClient {-RSession,-Independent,-SessionLimits}) qr qs :
  0 <= qr => 0 <= qs =>
  phoare[IndependentGame(SessionKeygenContext(A)).run : SessionLimits.raw_cap = qr /\ SessionLimits.sign_cap = qs ==>
    res] <= (bigi predT (fun _ => exhaustion_charge (155135+qr+qs*signing_budget)) 0 qs).
proof.
  move=> hqr hqs; have hz : 0 <= 155135 by smt().
  proc; inline SessionKeygenContext(A,Independent).run; wp.
  call (driver_exhaustion A 155135 qr qs hz hqr hqs).
  call keygen_history_cost; inline Independent.init; auto.
  rewrite /no_r_tails /history_recorded; smt(FMap.mem_empty).
qed.

lemma whole_physical_session_exhaustion
  (A <: RClient {-RSession,-Independent,-SessionLimits,-Physical,-Hybrid,-Shared}) qr qs &m :
  (forall (V <: RClientOracle {-A}), islossless V.hash => islossless V.sign => islossless A(V).run) =>
  0 <= qr => 0 <= qs => SessionLimits.raw_cap{m} = qr => SessionLimits.sign_cap{m} = qs =>
  Pr[RealGame(SessionKeygenContext(A)).run() @ &m : res] <=
    bigi predT (fun _ => exhaustion_charge (155135+qr+qs*signing_budget)) 0 qs +
    (155135+qr+qs*signing_budget)%r * (1%r/2%r)^256.
proof.
  move=> ha hqr hqs hraw hsign.
  have hll : forall (O <: PrefixOracle {-SessionKeygenContext(A)}),
    islossless O.hash => islossless O.derive => islossless SessionKeygenContext(A,O).run.
  + move=> O hh hd; exact (session_keygen_lossless A O ha hh hd).
  have hq : 0 <= 155135+qr+qs*signing_budget by rewrite /signing_budget; smt().
  have hbudget : hoare[SessionKeygenContext(A,Independent).run : Independent.queries = [] /\
    (glob SessionKeygenContext(A)) = (glob SessionKeygenContext(A)){m} ==>
    size Independent.queries <= 155135+qr+qs*signing_budget].
  + conseq (session_keygen_cost A qr qs hqr hqs); auto; smt().
  have hp := physical_to_independent_at_state (SessionKeygenContext(A))
    (155135+qr+qs*signing_budget) &m hll hq hbudget.
  have hi : Pr[IndependentGame(SessionKeygenContext(A)).run() @ &m : res] <=
    bigi predT (fun _ => exhaustion_charge (155135+qr+qs*signing_budget)) 0 qs
    by byphoare (keygen_session_ideal A qr qs hqr hqs) => //.
  smt().
qed.
