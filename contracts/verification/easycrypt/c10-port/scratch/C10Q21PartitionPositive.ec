require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureComponents ExposureCoverage ExposurePartition ExposurePartitionGame ExposurePartitionHop ExposurePrivate ExposureWidths ForsRootDeterminism.
require import C10RawGrind LayerSignOpening SessionForestExtraction ForestRootWitness ExposureSupport ExposureReferences ExposureLog ExposureDriver ExposureAccounting IndependentWidths.
import RealOrder.
lemma checked_statement h s seed root entries :
  exposures_supported h s seed (pad root) entries => exposures_width entries => !public_node_collision h =>
  new_message_forest_opening h s seed root (exposure_messages entries) =>
  new_message_exposure_partition h s seed root entries.
proof. exact (new_message_forest_partition h s seed root entries). qed.
