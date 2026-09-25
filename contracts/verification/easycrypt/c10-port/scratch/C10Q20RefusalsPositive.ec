require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.

lemma refused_sign_keeps_log (O <: PrefixOracle {-FullSession,-ExposureLog}) entries0 calls0 :
  hoare [ExposureSession(O).sign :
    ExposureLog.entries=entries0 /\ FullSession.sign_calls=calls0 /\
    (FullSession.failed \/ FullSession.sign_limit<=calls0 \/ size message<>32) ==>
    res=None /\ ExposureLog.entries=entries0 /\ FullSession.sign_calls=calls0].
proof.
  proc; inline FullSession(O).sign; sp 4; rcondf 1; first by auto; smt().
  auto; smt().
qed.
