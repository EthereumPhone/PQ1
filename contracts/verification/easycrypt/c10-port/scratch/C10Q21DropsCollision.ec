require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureComponents ExposureCoverage ExposurePartition ExposurePartitionGame ExposurePartitionHop ExposurePrivate ExposureWidths ForsRootDeterminism.
require import C10RawGrind LayerSignOpening SessionForestExtraction ForestRootWitness ExposureSupport ExposureReferences ExposureLog ExposureDriver ExposureAccounting IndependentWidths.
import RealOrder.
lemma checked_statement h s seed root entries ht tree index value :
  exposures_supported h s seed root entries => exposures_width entries =>
  logged_fors_value h seed root entries ht tree index value =>
  exists sd, s.[fors_private_key ht tree index]=Some sd /\ value=node sd.
proof. exact (logged_fors_private_value h s seed root entries ht tree index value). qed.
