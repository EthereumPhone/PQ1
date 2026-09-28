require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ByteForestOpeningHop ByteGameForestExtraction ForestCoordinates ForestOpeningCases ForestRecordExtraction ForestRecoveryRecord ForestReferenceHistory ForestRootPrefix ForestRootRecording ForestRootWitness ForsRecordExtraction ForsReturnedRoot ForsRootRecording ForsRootWitness HonestForestMessages SessionForestExtraction SignerForestReference VerifierForestRecords.
import RealOrder.
lemma checked_statement seed0 ht0 digest0 secrets0 auths0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    size secrets0=13 /\ size auths0=12 /\ all (fun p => size p=11) auths0 ==>
    forest_opening Independent.rawhistory seed0 ht0 digest0 secrets0 auths0 res].
proof. exact (raw_forest_recovery_recorded seed0 ht0 digest0 secrets0 auths0). qed.
