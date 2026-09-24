require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness IndependentWidths IndependentSignerWidth EncodedLayer EncodedSignature SignerEncodingCorrect ActualByteSignerCorrect.
import BS2Int.

lemma count_boundaries : bs2int (bytes_to_bits (be 4 0))=0 /\
  bs2int (bytes_to_bits (be 4 4294967295))=4294967295.
proof. smt(encoded_count_value). qed.
