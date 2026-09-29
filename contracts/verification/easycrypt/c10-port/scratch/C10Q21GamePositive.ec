require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureComponents ExposureCoverage ExposurePartition ExposurePartitionGame ExposurePartitionHop ExposurePrivate ExposureWidths ForsRootDeterminism.
require import C10RawGrind LayerSignOpening SessionForestExtraction ForestRootWitness ExposureSupport ExposureReferences ExposureLog ExposureDriver ExposureAccounting IndependentWidths.
import RealOrder.
lemma checked_statement
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    size ExposureLog.entries<=qs0 /\ exposures_width ExposureLog.entries /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries)].
proof. exact (byte_exposure_partition A seed0 qs0). qed.
