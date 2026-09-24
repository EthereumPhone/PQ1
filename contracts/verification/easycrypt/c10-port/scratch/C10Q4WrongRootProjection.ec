require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.

lemma wrong_root (O <: PreparationOracle) :
  equiv[RawKeygen(O).root ~ RawMerkle(O).build :
    ={seed,layer,tree,glob O} ==> res{1} = nseq 16 0 /\ ={glob O}].
proof. exact (merkle_build_root_projection O). qed.
