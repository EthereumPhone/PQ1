require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.
lemma checked_statement
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 :
  hoare [A(ExposureSession(Independent)).run :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries].
proof. exact (exposure_client_supported A seed0 root0). qed.
