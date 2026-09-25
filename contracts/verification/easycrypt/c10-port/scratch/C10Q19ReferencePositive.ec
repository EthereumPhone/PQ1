require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ByteForestOpeningHop ByteGameForestExtraction ForestCoordinates ForestOpeningCases ForestRecordExtraction ForestRecoveryRecord ForestReferenceHistory ForestRootPrefix ForestRootRecording ForestRootWitness ForsRecordExtraction ForsReturnedRoot ForsRootRecording ForsRootWitness HonestForestMessages SessionForestExtraction SignerForestReference VerifierForestRecords.
import RealOrder.
lemma checked_statement h s seed ht tree root target :
  fors_root_witness h s seed ht tree root => 0<=target<2048 =>
  exists sd auth, rows_width 11 auth /\ s.[fors_private_key ht tree target]=Some sd /\
    fors_opening h seed ht tree target (node sd) auth root.
proof. exact (fors_root_reference_at h s seed ht tree root target). qed.
