require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.

module ForsExample = {
  proc run() : raw_input * raw_input list = {
    var result;
    result <@ RawFors(PreparationView(Independent)).tree(nseq 32 0,0,0,2047);
    return result;
  }
}.
lemma actual_builder_reference :
  phoare [ForsExample.run : true ==>
    rows_width 11 res.`2 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (fors_pair (nseq 32 0) 0 0)
        (leaf,0,2047) res.`2 /\
      (path_value Independent.rawhistory (fors_pair (nseq 32 0) 0 0)
        (leaf,0,2047) res.`2).`1 = res.`1] = 1%r.
proof.
  proc; call (total_fors_tree_reference (nseq 32 0) 0 0 2047); auto.
qed.
