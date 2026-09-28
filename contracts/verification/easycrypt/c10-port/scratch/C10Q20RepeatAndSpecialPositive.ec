require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.

lemma repeated_messages_remain message (sig1 sig2 : raw_signature) :
  exposure_messages [(message,sig1);(message,sig2)]=[message;message] /\
  size [(message,sig1);(message,sig2)]=2 /\
  List.mem (exposure_messages [(message,sig1);(message,sig2)]) message.
proof. by rewrite /exposure_messages /=. qed.

lemma special_is_not_ordinary h seed root entries ht index value :
  !logged_fors_value h seed root entries ht 12 index value.
proof. rewrite /logged_fors_value; smt(). qed.

lemma literal_special_root h seed root message (signature : raw_signature) d :
  h.[hmsg_input seed root (pad signature.`1) message]=Some d =>
  logged_special_root h seed root [(message,signature)] (hypertree_index d) (nth [] signature.`2 12).
proof.
  move=> he; exists message signature d; smt(mem_head).
qed.
