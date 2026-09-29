require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureComponents ExposureCoverage ExposurePartition ExposurePartitionGame ExposurePartitionHop ExposurePrivate ExposureWidths ForsRootDeterminism.
require import C10RawGrind LayerSignOpening SessionForestExtraction ForestRootWitness ExposureSupport ExposureReferences ExposureLog ExposureDriver ExposureAccounting IndependentWidths.
import RealOrder.

lemma different_responses_may_cover_different_trees h seed root entries1 entries2 d :
  (forall tree, 0<=tree<12 =>
    returned_coordinate h seed root entries1 (hypertree_index d) tree (forest_index d tree) \/
    returned_coordinate h seed root entries2 (hypertree_index d) tree (forest_index d tree)) =>
  !returned_coverage h seed root entries1 d => !returned_coverage h seed root entries2 d =>
  returned_coverage h seed root (entries1++entries2) d /\
    !returned_coverage h seed root entries1 d /\ !returned_coverage h seed root entries2 d.
proof.
  move=> hc hn1 hn2; split; last smt().
  rewrite /returned_coverage; move=> tree ht.
  rewrite returned_coordinate_cat; exact (hc tree ht).
qed.
