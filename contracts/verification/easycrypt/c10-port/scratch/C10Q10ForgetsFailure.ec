require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import MerkleRootWitness SignerCoordinates SignerFinishState SignerFinishWitness SignerReturnedOpening SignerVerifierReplay ActualSignerCorrect.
lemma total_actual_signer_correct seed0 message0 :
  phoare [ActualSignerConstruction(Independent).run : seed=seed0 /\ message=message0 ==>
    res.`2<>None /\ res.`3] = 1%r.
proof. exact (total_actual_signer_correct seed0 message0). qed.
