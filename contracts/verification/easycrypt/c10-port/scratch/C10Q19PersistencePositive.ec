require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ByteForestOpeningHop ByteGameForestExtraction ForestCoordinates ForestOpeningCases ForestRecordExtraction ForestRecoveryRecord ForestReferenceHistory ForestRootPrefix ForestRootRecording ForestRootWitness ForsRecordExtraction ForsReturnedRoot ForsRootRecording ForsRootWitness HonestForestMessages SessionForestExtraction SignerForestReference VerifierForestRecords.
import RealOrder.
lemma checked_statement (A <: FullClient {-FullSession,-Independent}) seed0 ht0 root0 :
  hoare [A(FullSession(Independent)).run :
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 root0].
proof. exact (full_client_forest_preserved A seed0 ht0 root0). qed.
