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
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Physical,-Hybrid,-Shared,
    -Independent,-ExposureLog,-ProjectedMemo,-ProjectedSamples}) qr qs seed0 &m :
  (forall (V <: ByteClientOracle {-A}), islossless V.hash => islossless V.sign =>
    islossless A(V).run) =>
  0<=qr => 0<=qs => FullLimits.raw_cap{m}=qr => FullLimits.sign_cap{m}=qs =>
  pad (node KeygenInputs.public_seed{m})=seed0 =>
  Pr[RealGame(ByteContext(A)).run() @ &m : res] <=
    Pr[IndependentGame(ExposureContext(ByteLift(A))).run() @ &m :
      false /\ !public_node_collision Independent.rawhistory /\ !public_node_zero Independent.rawhistory /\
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory
        seed0 root0 ExposureLog.entries] +
    ((full_public_budget qr qs)*(full_public_budget qr qs-1))%r/2%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^128 +
    (full_public_budget qr qs)%r*(1%r/2%r)^256.
proof. exact (byte_exposure_partition_hop A qr qs seed0 &m). qed.
