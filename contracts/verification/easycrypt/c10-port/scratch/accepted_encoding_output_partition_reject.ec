require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import AcceptedActualWotsCut AcceptedWotsCollision.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.
require import AcceptedEncodingCases.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    accepted_encoding_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; exact (query_byte_accepted_encoding_cases A qs hs).
qed.
