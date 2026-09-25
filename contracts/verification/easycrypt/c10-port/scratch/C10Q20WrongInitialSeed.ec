require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.
require import C10RawGrind LayerSignOpening SessionForestExtraction.
lemma checked_statement
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run :
    FullLimits.sign_cap=qs0 ==>
    size ExposureLog.entries<=qs0 /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_forest_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 (exposure_messages ExposureLog.entries))].
proof. exact (byte_exposure_forgery_accounted A seed0 qs0). qed.
