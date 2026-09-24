require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness IndependentWidths IndependentSignerWidth EncodedLayer EncodedSignature SignerEncodingCorrect ActualByteSignerCorrect.
import BS2Int.
lemma total_actual_byte_signer_correct seed0 message0 :
  phoare [ActualByteSignerConstruction.run : seed=seed0 /\ message=message0 ==>
    res.`2<>None /\ byte_signature (oget res.`2) /\ res.`3] = 1%r.
proof. exact (total_actual_byte_signer_correct seed0 message0). qed.
