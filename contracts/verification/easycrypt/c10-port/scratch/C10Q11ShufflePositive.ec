require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10RawGrind C10HashDomains C10Bytes PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawSignature ByteSession.
require import MerkleRootWitness IndependentWidths IndependentSignerWidth EncodedLayer EncodedSignature SignerEncodingCorrect ActualByteSignerCorrect.
import BS2Int.

module ActualShuffle = {
  proc run() : raw_input * raw_input option * bool = {
    var result;
    result <@ ActualByteSignerConstruction.run(nseq 32 0,nseq 32 0,nseq 32 0,nseq 32 255);
    return result;
  }
}.
lemma actual_byte_component :
  phoare [ActualShuffle.run : true ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => byte_signature (oget res.`2) /\ res.`3)] = 1%r.
proof. proc; call (total_actual_byte_signer_correct (nseq 32 0) (nseq 32 0)); auto. qed.
