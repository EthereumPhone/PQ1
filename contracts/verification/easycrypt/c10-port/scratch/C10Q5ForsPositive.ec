require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature RawWidths PathReplay PathInputs RawPathReplay RawForsPathReplay ForsLeafInputs.
require import ForsBuilderSecret ForsBuilderComparison MerkleBuilderComparison.

module ForsComparisonExample = {
  proc run() : raw_input * raw_input * raw_input list = {
    var result;
    result <@ ForsBuildCompare.run(nseq 32 0,0,0,0,nseq 16 0,nseq 11 (nseq 16 0));
    return result;
  }
}.
lemma actual_comparison :
  phoare [ForsComparisonExample.run : true ==>
    rows_width 11 res.`3 /\ exists reference_secret reference_digest,
      size reference_secret = 16 /\
      Independent.rawhistory.[fors_leaf_input (nseq 32 0) 0 0 0 reference_secret] = Some reference_digest /\
      path_recorded Independent.rawhistory (fors_pair (nseq 32 0) 0 0)
        (node reference_digest,0,0) res.`3 /\
      (path_value Independent.rawhistory (fors_pair (nseq 32 0) 0 0)
        (node reference_digest,0,0) res.`3).`1 = res.`1 /\
      (res.`2 = res.`1 =>
        (nseq 16 0) = reference_secret \/
        fors_leaf_collision Independent.rawhistory (nseq 32 0) 0 0 0 \/
        path_input_collision Independent.rawhistory (fors_pair (nseq 32 0) 0 0))] = 1%r.
proof.
  proc; call (total_actual_fors_builder_comparison (nseq 32 0) 0 0 0 (nseq 16 0) (nseq 11 (nseq 16 0)));
    auto; smt(rows_zeros size_nseq).
qed.
