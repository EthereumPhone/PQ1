(* Numerical adaptive FORS coverage charge in the original initialized byte game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords.
require import PoolCoverageEvent PoolCoverageBound CoveredOutputPool HmsgPoolGame HmsgByteEvidence.
import RealOrder.

lemma hmsg_byte_coverage_in_pool
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs :
  0<=qr => 0<=qs =>
  hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size AcceptedSamples.nodes<=qr+qs+1 /\
    (actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output =>
      pool_coverage AcceptedSamples.nodes)].
proof.
  move=> hr hs.
  have h1 : hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    accepted_records HmsgMemo.rawhistory HmsgMemo.accepted_keys AcceptedSamples.nodes /\ size AcceptedSamples.nodes<=qr+qs+1].
  + conseq (hmsg_byte_count A qr qs hr hs) (hmsg_game_records (ClientQueryContext(ByteLift(A)))); smt().
  have h2 : hoare[HmsgGame(ClientQueryContext(ByteLift(A))).run : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==>
    size FullSession.seed=32 /\ size FullSession.root=32 /\ logged_message_width ExposureLog.entries /\
    exposures_supported HmsgMemo.rawhistory HmsgMemo.secrethistory FullSession.seed FullSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries].
  + conseq (hmsg_byte_metadata A) (hmsg_byte_history A qs hs); smt().
  conseq h1 h2; smt(actual_coverage_pool).
qed.

lemma hmsg_byte_coverage_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]
    <=coverage_charge (qr+qs+1).
proof.
  move=> hr hs hqr hqs.
  have hz : Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    !(size AcceptedSamples.nodes<=qr+qs+1 /\
      (actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output =>
       pool_coverage AcceptedSamples.nodes))]=0%r.
  + byphoare (_ : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (hmsg_byte_coverage_in_pool A qr qs hr hs); smt().
  have hb := hmsg_game_pool_bound (ClientQueryContext(ByteLift(A))) (qr+qs+1) &m _; first smt().
  have hsub : Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output] <=
    Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
      (size AcceptedSamples.nodes<=qr+qs+1 /\ pool_coverage AcceptedSamples.nodes) \/
      !(size AcceptedSamples.nodes<=qr+qs+1 /\
        (actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output =>
         pool_coverage AcceptedSamples.nodes))].
  + rewrite Pr[mu_sub]; smt().
  move: hsub; rewrite Pr[mu_or] hz; smt(ge0_mu).
qed.

lemma original_byte_coverage_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]
    <=coverage_charge (qr+qs+1).
proof.
  move=> hr hs hqr hqs.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]=
    Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output].
  + byequiv (hmsg_game_projection (ClientQueryContext(ByteLift(A)))) => //; smt().
  rewrite he; exact (hmsg_byte_coverage_bound A qr qs &m hr hs hqr hqs).
qed.
