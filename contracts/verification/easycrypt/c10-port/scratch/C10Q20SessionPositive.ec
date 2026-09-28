require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.
lemma checked_statement
  (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 qs0 :
  0<=qs0 =>
  hoare [ExposureDriver(A,Independent).run : seed=seed0 /\ root=root0 /\ qs=qs0 ==>
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ FullSession.sign_limit=qs0 /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof. exact (exposure_driver_history A seed0 root0 qs0). qed.
