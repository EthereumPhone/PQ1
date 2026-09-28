require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature RawWidths PathReplay PathInputs RawPathReplay RawForsPathReplay ForsLeafInputs.
require import ForsBuilderSecret ForsBuilderComparison MerkleBuilderComparison.

module MerkleComparisonExample = {
  proc run() : raw_input * raw_input * raw_input list = {
    var result;
    result <@ MerkleBuildCompare.run(nseq 32 0,0,0,0,nseq 16 0,nseq 9 (nseq 16 0));
    return result;
  }
}.
lemma actual_comparison :
  phoare [MerkleComparisonExample.run : true ==>
    rows_width 9 res.`3 /\ exists reference_leaf, size reference_leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair (nseq 32 0) 0 0)
        (reference_leaf,0,0) res.`3 /\
      (path_value Independent.rawhistory (merkle_pair (nseq 32 0) 0 0)
        (reference_leaf,0,0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 => (nseq 16 0) = reference_leaf \/
        path_input_collision Independent.rawhistory (merkle_pair (nseq 32 0) 0 0))] = 1%r.
proof.
  proc; call (total_actual_merkle_builder_comparison (nseq 32 0) 0 0 0 (nseq 16 0) (nseq 9 (nseq 16 0)));
    auto; smt(rows_zeros size_nseq).
qed.
