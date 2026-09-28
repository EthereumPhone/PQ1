require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import MerkleRootWitness SignerCoordinates SignerFinishState SignerFinishWitness SignerReturnedOpening SignerVerifierReplay ActualSignerCorrect.

module ActualShuffle = {
  proc run() : raw_input * raw_signature option * bool = {
    var result;
    result <@ ActualSignerConstruction(Independent).run(nseq 32 0,nseq 32 0,nseq 32 0,nseq 32 1);
    return result;
  }
}.
lemma actual_signer_component :
  phoare [ActualShuffle.run : true ==>
    (res.`2=None => !res.`3) /\ (res.`2<>None => res.`3)] = 1%r.
proof. proc; call (total_actual_signer_correct (nseq 32 0) (nseq 32 0)); auto. qed.
