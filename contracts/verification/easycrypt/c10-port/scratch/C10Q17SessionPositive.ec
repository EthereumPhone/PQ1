require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath.
require import RootCoverage RootSessionHistory TopVerifierOpening VerifierTopExtraction SessionTopExtraction ByteGameTopExtraction ByteTopOpeningHop.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement (A <: FullClient {-FullSession,-Independent}) seed0 layer0 tree0 root0 :
  hoare [A(FullSession(Independent)).run :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof. exact (full_client_root_preserved A seed0 layer0 tree0 root0). qed.
