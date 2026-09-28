require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawSignature.
require import PathReplay RawForsPathReplay ForsPrivateLeaves.
require import ForsBuilderPrivate ForsKnownSecret ForsSignWitness ForsSignCorrect ForsSignRecord.

lemma wrong_signature (O <: PreparationOracle) :
  equiv [RawFors(O).sign ~ ForsSignWitness(O).sign :
    ={seed,ht,tree,target,glob O} ==>
    res{1} = (nseq 16 0,res{2}.`2) /\ ={glob O}].
proof. exact (fors_sign_witness_projection O). qed.
