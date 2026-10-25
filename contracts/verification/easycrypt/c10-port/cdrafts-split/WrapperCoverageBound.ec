(* Adaptive FORS coverage charge for the actual initialized wrapper game.
   The accepted-call bound charges two signing passes, internal verification,
   forwarded client queries and the final verification. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog WrapperQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords.
require import PoolCoverageEvent PoolCoverageBound CoveredOutputPool HmsgPoolGame WrapperHmsgEvidence.
import RealOrder.

lemma hmsg_wrapper_coverage_in_pool
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    size AcceptedSamples.nodes<=qr+3*qs+1 /\
    (actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output =>
      pool_coverage AcceptedSamples.nodes)].
proof.
  move=> hr hs.
  have h1 : hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\ size AcceptedSamples.nodes<=qr+3*qs+1].
  + conseq (hmsg_wrapper_byte_count A qr qs hr hs) (hmsg_game_records (WrapperQueryContext(WrapperByteLift(A)))); smt().
  have h2 : hoare[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==>
    size WrapperSession.seed=32 /\ size WrapperSession.root=32 /\ logged_message_width ExposureLog.entries /\
    exposures_supported HmsgMemo.rawhistory HmsgMemo.secrethistory WrapperSession.seed WrapperSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries].
  + conseq (hmsg_wrapper_byte_metadata A) (hmsg_wrapper_byte_history A qs hs); smt().
  conseq h1 h2; smt(actual_coverage_pool).
qed.

lemma hmsg_wrapper_coverage_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output]
    <=coverage_charge (qr+3*qs+1).
proof.
  move=> hr hs hqr hqs.
  have hz : Pr[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    !(size AcceptedSamples.nodes<=qr+3*qs+1 /\
      (actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output =>
       pool_coverage AcceptedSamples.nodes))]=0%r.
  + byphoare (_ : WrapperLimits.raw_cap=qr /\ WrapperLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (hmsg_wrapper_coverage_in_pool A qr qs hr hs); smt().
  have hb := hmsg_game_pool_bound (WrapperQueryContext(WrapperByteLift(A))) (qr+3*qs+1) &m _; first smt().
  have hsub : Pr[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output] <=
    Pr[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
      (size AcceptedSamples.nodes<=qr+3*qs+1 /\ pool_coverage AcceptedSamples.nodes) \/
      !(size AcceptedSamples.nodes<=qr+3*qs+1 /\
        (actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output =>
         pool_coverage AcceptedSamples.nodes))].
  + rewrite Pr[mu_sub]; smt().
  move: hsub; rewrite Pr[mu_or] hz; smt(ge0_mu).
qed.

lemma wrapper_byte_coverage_bound
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output]
    <=coverage_charge (qr+3*qs+1).
proof.
  move=> hr hs hqr hqs.
  have he : Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output]=
    Pr[HmsgGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output].
  + byequiv (hmsg_game_projection (WrapperQueryContext(WrapperByteLift(A)))) => //; smt().
  rewrite he; exact (hmsg_wrapper_coverage_bound A qr qs &m hr hs hqr hqs).
qed.
