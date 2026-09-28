require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureComponents ExposureCoverage ExposurePartition ExposurePartitionGame ExposurePartitionHop ExposurePrivate ExposureWidths ForsRootDeterminism.
require import C10RawGrind LayerSignOpening SessionForestExtraction ForestRootWitness ExposureSupport ExposureReferences ExposureLog ExposureDriver ExposureAccounting IndependentWidths.
import RealOrder.

lemma empty_has_no_coverage h seed root d : !returned_coverage h seed root [] d.
proof. exact (returned_coverage_empty h seed root d). qed.
lemma repeat_does_not_add_coordinates h seed root entries d :
  returned_coverage h seed root (entries++entries) d = returned_coverage h seed root entries d.
proof. exact (returned_coverage_repeat h seed root entries d). qed.
lemma last_is_not_ordinary h seed root entries ht index :
  !returned_coordinate h seed root entries ht 12 index.
proof. rewrite /returned_coordinate; smt(). qed.
