require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawFors.
require import RawSignature PathReplay RawPathReplay RawForsPathReplay.
require import RawBuilderReference TotalBuilderReference BuildRootProjection.

module MerkleExample = {
  proc run() : raw_input list * raw_input = {
    var result;
    result <@ RawMerkle(PreparationView(Independent)).build(nseq 32 0,0,0,511);
    return result;
  }
}.
lemma actual_builder_reference :
  phoare [MerkleExample.run : true ==>
    rows_width 9 res.`1 /\ exists leaf, size leaf = 16 /\
      path_recorded Independent.rawhistory (merkle_pair (nseq 32 0) 0 0)
        (leaf,0,511) res.`1 /\
      (path_value Independent.rawhistory (merkle_pair (nseq 32 0) 0 0)
        (leaf,0,511) res.`1).`1 = res.`2] = 1%r.
proof.
  proc; call (total_merkle_build_reference (nseq 32 0) 0 0 511); auto.
qed.
