require import AllCore List Distr FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion RawKeygen.
require import FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import AcceptedActualWotsCut AcceptedWotsCollision.
require import MemoNodeCollision PublicNodeZero ByteEncodingCharge ActualExposurePartition ActualWotsCut ActualForsOpening CoveredOutputPool.
require import NodeQueryDomain DomainNodeCollision DomainActualPartition HmsgShapes.
require import DomainNodeCases.

lemma checked (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs :
  0<=qs =>
  hoare[IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs ==>
    domain_node_output_cases Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output res].
proof.
  move=> hs; exact (query_byte_domain_node_cases A qs hs).
qed.
