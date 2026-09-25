require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.
lemma checked_statement
  (A <: FullClient {-FullSession,-ExposureLog}) (O <: PrefixOracle {-A,-FullSession,-ExposureLog}) :
  hoare [A(ExposureSession(O)).run :
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit ==>
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls FullSession.sign_limit].
proof. exact (exposure_client_accounting A O). qed.
