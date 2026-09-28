require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness IndependentWidths IndependentSignerWidth EncodedLayer EncodedSignature SignerEncodingCorrect ActualByteSignerCorrect.
import BS2Int.
lemma encoded_count_value c :
  bs2int (bytes_to_bits (be 4 c))=c.
proof. exact (encoded_count_value c). qed.
