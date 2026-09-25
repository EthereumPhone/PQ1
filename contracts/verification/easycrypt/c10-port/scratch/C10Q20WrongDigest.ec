require import AllCore List FMap IntDiv Distr StdOrder.
require import C10RawOracle C10Counter C10HashDomains PrefixGuess PrefixHybrid PrefixGames PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawLayer RawForest RawSigner RawSignature FullSession FullSessionCost FullPrefix ByteSession.
require import ProjectedBirthday ProjectedMemoOracle MerkleRootWitness WotsReferenceRoot LayerPath PersistentGrind.
require import ForsPrivateLeaves ForsOpening ForestOpening LayerRecordExtraction SubtreeOpeningCases VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero SignerCoordinates ForestWitness.
require import ExposureAccounting ExposureDriver ExposureForge ExposureGameHistory ExposureHistory ExposureLog ExposureReferences ExposureSessionHistory ExposureSupport.
import RealOrder.
require import C10RawGrind LayerSignOpening ForestRootWitness SessionForestExtraction.
lemma checked_statement h s seed root entries message signature d :
  exposures_supported h s seed root entries => List.mem entries (message,signature) =>
  
  accept_digest d /\ exists forest lower upper top,
    forest_root_witness h s seed (hypertree_index d) forest /\
    forest_opening h seed (hypertree_index d) d signature.`2 signature.`3 forest /\
    layer_opening h s seed 0 (hypertree_index d %/512) (hypertree_index d %%512)
      forest (nth ([],0,[]) signature.`4 0) lower /\
    merkle_root_witness h s seed 0 (hypertree_index d %/512) upper /\
    layer_opening h s seed 1 0 (hypertree_index d %/512)
      upper (nth ([],0,[]) signature.`4 1) top.
proof. exact (logged_digest_references h s seed root entries message signature d). qed.
