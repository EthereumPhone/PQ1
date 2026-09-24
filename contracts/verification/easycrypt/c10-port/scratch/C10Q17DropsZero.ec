require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath.
require import RootCoverage RootSessionHistory TopVerifierOpening VerifierTopExtraction SessionTopExtraction ByteGameTopExtraction ByteTopOpeningHop.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.
lemma checked_statement seed0 root0 message0 (sig0 : raw_signature) :
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res => public_node_collision Independent.rawhistory \/ verified_top_opening Independent.rawhistory Independent.secrethistory seed0 root0 message0 sig0].
proof. exact (verifier_extracts_top_opening seed0 root0 message0 sig0). qed.
