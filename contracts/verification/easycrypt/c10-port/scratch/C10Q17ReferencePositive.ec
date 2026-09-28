require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath.
require import RootCoverage RootSessionHistory TopVerifierOpening VerifierTopExtraction SessionTopExtraction ByteGameTopExtraction ByteTopOpeningHop.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement h s seed layer tree root target :
  merkle_root_witness h s seed layer tree root => 0<=target<512 =>
  exists leaf auth, rows_width 9 auth /\
    wots_root h s seed layer tree target leaf /\
    layer_path h seed layer tree target leaf auth root.
proof. exact (root_reference_at h s seed layer tree root target). qed.
