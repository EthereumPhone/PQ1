require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import LayerRecoveryRecord LayerRecordExtraction VerifierLayerRecords HonestSubtreeMessages SubtreeOpeningCases.
require import SessionSubtreeExtraction ByteGameSubtreeExtraction ByteSubtreeOpeningHop VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement h s seed layer tree index message (signature : layer_signature) root :
  layer_width signature => 0<=index<512 =>
  
  layer_recovery_record h seed layer tree index message signature root =>
  !public_node_collision h => !public_node_zero h =>
  exists leaf, wots_verifier_opening h s seed layer tree index message leaf (signature.`1,signature.`2).
proof. exact (recorded_layer_extracts h s seed layer tree index message signature root). qed.
