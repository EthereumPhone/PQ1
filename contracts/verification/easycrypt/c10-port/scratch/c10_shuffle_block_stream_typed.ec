(* Exact operational shuffle correspondence to the paired representation.
   The oracle is arbitrary and its entire state is preserved. This does not
   identify that oracle with the supplied concrete-SHA model used in Lean. *)
require import AllCore List IntDiv.
require import C10Bytes C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
require import C10Representation.
require import C10AddressInputBridge C10CallerInputBridge.



op shuffle_finish n stream k order =
  foldr (fun i out => shuffle_swap out i
    (shuffle_choice (nth 0 stream (2 * max 0 (max 0 (n-1)-i)))
      (nth 0 stream (2 * max 0 (max 0 (n-1)-i)+1)) (i+1)))
    order (mkseq (fun j => j+1) k).




module PairedShuffle (O : PreparationOracle) = {
  proc derive(seed label : raw_input) : raw_input = {
    var d, result;
    result <- nseq 32 0;
    if (seed <> nseq 32 0) {
      d <@ O.hash(shuffle_seed_preimage seed label);
      result <- bits_to_bytes d;
    }
    return result;
  }
  proc permutation(seed : raw_input, n : int) : int list = {
    var order, stream, blk, d;
    order <- range 0 n;
    if (seed <> nseq 32 0 /\ 1 < n) {
      blk <- 0; stream <- [];
      while (blk < 4) {
        d <@ O.hash(shuffle_block_preimage seed blk);
        stream <- bits_to_bytes d ++ stream; blk <- blk+1;
      }
      order <- shuffle_order n stream;
    }
    return order;
  }
}.
