require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import LayerRecoveryRecord LayerRecordExtraction VerifierLayerRecords HonestSubtreeMessages SubtreeOpeningCases.
require import SessionSubtreeExtraction ByteGameSubtreeExtraction ByteSubtreeOpeningHop VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-Independent}) seed0 :
  hoare [IndependentGame(ByteContext(A)).run : true ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_subtree_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof. exact (byte_game_subtree_extraction A seed0). qed.
