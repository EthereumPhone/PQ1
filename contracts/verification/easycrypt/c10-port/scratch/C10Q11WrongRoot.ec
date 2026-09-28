require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness IndependentWidths IndependentSignerWidth EncodedLayer EncodedSignature SignerEncodingCorrect ActualByteSignerCorrect.
import BS2Int.
lemma keygen_root_ready seed0 :
  hoare [RawKeygen(PreparationView(Independent)).root :
    seed=seed0 /\ layer=1 /\ tree=0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 1 res].
proof. exact (keygen_root_ready seed0). qed.
