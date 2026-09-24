require import AllCore List FMap IntDiv.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner.
require import MerkleRootWitness SignerCoordinates SignerFinishState SignerFinishWitness SignerReturnedOpening SignerVerifierReplay ActualSignerCorrect.

lemma wrong_projection (O <: PrefixOracle) :
  equiv [RawSigner(O).finish ~ SignerFinishWitness(O).finish :
    ={seed,randomizer,digest,shuffle,glob O} ==> res{1}=None /\ ={glob O}].
proof. exact (signer_finish_witness_projection O). qed.
