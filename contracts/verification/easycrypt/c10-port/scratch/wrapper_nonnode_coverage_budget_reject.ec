require import AllCore List Distr FMap StdOrder.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import WrapperSession WrapperByteSession ExposureLog ClientQueryLog WrapperQueryDriver.
require import IndependentWidths ExposureSupport ExposureWidths AcceptedPrefixSampling HmsgMemoOracle HmsgPoolRecords.
require import PoolCoverageEvent PoolCoverageBound CoveredOutputPool HmsgPoolGame WrapperHmsgEvidence.
require import WrapperCoverageBound StirlingCoverageBound OriginalStirlingCoverage.
import RealOrder.
require import WrapperStirlingCoverage.
lemma checked
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent,-HmsgMemo,-AcceptedSamples}) qr qs &m :
  0<=qr => 0<=qs => WrapperLimits.raw_cap{m}=qr => WrapperLimits.sign_cap{m}=qs =>
  Pr[IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run() @ &m :
    actual_accepted_coverage Independent.rawhistory WrapperSession.seed WrapperSession.root ExposureLog.entries ClientQueryLog.output]
    <=stirling_coverage_charge (qr+qs+1).
proof. exact (wrapper_byte_stirling_coverage_bound A qr qs &m). qed.
