require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ByteForestOpeningHop ByteGameForestExtraction ForestCoordinates ForestOpeningCases ForestRecordExtraction ForestRecoveryRecord ForestReferenceHistory ForestRootPrefix ForestRootRecording ForestRootWitness ForsRecordExtraction ForsReturnedRoot ForsRootRecording ForsRootWitness HonestForestMessages SessionForestExtraction SignerForestReference VerifierForestRecords.
import RealOrder.
lemma checked_statement seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 ==>
    res => verified_forest_records Independent.rawhistory seed0 root0 message0 sig0].
proof. exact (verifier_records_forest seed0 root0 message0 sig0). qed.
