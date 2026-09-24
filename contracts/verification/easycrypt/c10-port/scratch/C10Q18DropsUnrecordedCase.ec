require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import LayerRecoveryRecord LayerRecordExtraction VerifierLayerRecords HonestSubtreeMessages SubtreeOpeningCases.
require import SessionSubtreeExtraction ByteGameSubtreeExtraction ByteSubtreeOpeningHop VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement h s seed d (sig : raw_signature) root :
  signature_width sig => merkle_root_witness h s seed 1 0 root =>
  verifier_layer_records h seed d sig root =>
  !public_node_collision h => !public_node_zero h =>
  paired_layer_openings h s seed d sig.
proof. exact (recorded_verifier_subtree_cases h s seed d sig root). qed.
