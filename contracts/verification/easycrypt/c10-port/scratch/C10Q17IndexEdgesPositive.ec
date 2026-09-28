require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath.
require import RootCoverage RootSessionHistory TopVerifierOpening VerifierTopExtraction SessionTopExtraction ByteGameTopExtraction ByteTopOpeningHop.
require import MemoNodeCollision PublicNodeZero SignerCoordinates.
import RealOrder.

lemma index_geometry_edges :
  0<=0<512 /\ 0<=511<512 /\ !(0<=512<512) /\
  262143 %/ 512=511 /\ (262143 %/512) %/512=0 /\
  signer_tree 262143 1=511 /\ signer_tree 262143 2=0.
proof. by rewrite /signer_tree; simplify. qed.
