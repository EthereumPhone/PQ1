(* Numerical adaptive FORS coverage charge in the original initialized byte game. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords.
require import CanonicalCoverageBound CanonicalPoolEvent CanonicalPoolWitness OriginalCoverageBound.
require import PoolCoverageEvent PoolCoverageBound CoveredOutputPool HmsgPoolGame HmsgByteEvidence.
import RealOrder.

lemma hmsg_game_canonical_pool_bound (C <: PrefixContext {-HmsgMemo,-AcceptedSamples}) n &m :
  0<=n => Pr[HmsgGame(C).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]
    <=canonical_coverage_charge n.
proof.
  move=> hn.
  have he : Pr[HmsgGame(C).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]=
    Pr[AcceptedGame(PoolContext(C)).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes].
  + byequiv (_ : ={glob C} ==> ={glob AcceptedSamples}) => //.
    proc; inline PoolContext(C,AcceptedSamples).run.
    call (_ : ={glob HmsgMemo,glob AcceptedSamples}); first 2 by sim.
    inline HmsgMemo(AcceptedSamples).init AcceptedSamples.init; auto.
  rewrite he.
  have hb:=adaptive_canonical_coverage_bound (PoolContext(C)) n &m hn.
  have hc : Pr[AcceptedGame(PoolContext(C)).run() @ &m : size AcceptedSamples.nodes<=n /\ pool_coverage AcceptedSamples.nodes]=
    Pr[AcceptedGame(PoolContext(C)).run() @ &m : size AcceptedSamples.nodes<=n /\ canonical_pool_coverage AcceptedSamples.nodes].
  + rewrite Pr[mu_eq]; smt(pool_coverage_canonical).
  by rewrite hc.
qed.


lemma hmsg_byte_canonical_coverage_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]
    <=canonical_coverage_charge (qr+qs+1).
proof.
  move=> hr hs hqr hqs.
  have hz : Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    !(size AcceptedSamples.nodes<=qr+qs+1 /\
      (actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output =>
       pool_coverage AcceptedSamples.nodes))]=0%r.
  + byphoare (_ : FullLimits.raw_cap=qr /\ FullLimits.sign_cap=qs ==> _) => //.
    hoare; conseq (hmsg_byte_coverage_in_pool A qr qs hr hs); smt().
  have hb := hmsg_game_canonical_pool_bound (ClientQueryContext(ByteLift(A))) (qr+qs+1) &m _; first smt().
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

lemma original_byte_canonical_coverage_bound
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]
    <=canonical_coverage_charge (qr+qs+1).
proof.
  move=> hr hs hqr hqs.
  have he : Pr[IndependentGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output]=
    Pr[HmsgGame(ClientQueryContext(ByteLift(A))).run() @ &m :
    actual_accepted_coverage HmsgMemo.rawhistory FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output].
  + byequiv (hmsg_game_projection (ClientQueryContext(ByteLift(A)))) => //; smt().
  rewrite he; exact (hmsg_byte_canonical_coverage_bound A qr qs &m hr hs hqr hqs).
qed.
