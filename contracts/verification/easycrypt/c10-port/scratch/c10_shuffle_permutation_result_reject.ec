(* Exact operational shuffle correspondence to the paired representation.
   The oracle is arbitrary and its entire state is preserved. This does not
   identify that oracle with the supplied concrete-SHA model used in Lean. *)
require import AllCore List IntDiv.
require import C10Bytes C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawShuffle.
require import C10Representation.
require import C10AddressInputBridge C10CallerInputBridge.

lemma shuffle_seed_common seed label :
  shuffle_tag ++ seed ++ label = shuffle_seed_preimage seed label.
proof. by rewrite /shuffle_tag /shuffle_seed_preimage.
qed.

lemma shuffle_block_common seed nonce : 0 <= nonce < 2^32 =>
  fisher_tag ++ seed ++ be 4 nonce = shuffle_block_preimage seed nonce.
proof. by move=> hn; rewrite /fisher_tag /shuffle_block_preimage (be4_common nonce hn).
qed.

op shuffle_finish n stream k order =
  foldr (fun i out => shuffle_swap out i
    (shuffle_choice (nth 0 stream (2 * max 0 (max 0 (n-1)-i)))
      (nth 0 stream (2 * max 0 (max 0 (n-1)-i)+1)) (i+1)))
    order (mkseq (fun j => j+1) k).

lemma shuffle_finish_zero n stream order :
  shuffle_finish n stream 0 order = order.
proof. by rewrite /shuffle_finish mkseq0.
qed.

lemma shuffle_finish_step n stream k order : 1 <= k =>
  shuffle_finish n stream k order = shuffle_finish n stream (k-1)
    (shuffle_swap order k
      (shuffle_choice (nth 0 stream (2 * max 0 (max 0 (n-1)-k)))
        (nth 0 stream (2 * max 0 (max 0 (n-1)-k)+1)) (k+1))).
proof.
  move=> hk; rewrite /shuffle_finish {1}(_: k=(k-1)+1) 1:/#.
  by rewrite mkseqS 1:/# foldr_rcons /=; smt().
qed.

lemma shuffle_finish_initial n stream : 1 <= n =>
  shuffle_finish n stream (n-1) (range 0 n) = shuffle_order n stream.
proof.
  move=> hn; rewrite /shuffle_finish /shuffle_order /range /mkseq /=.
  by rewrite (_: max 0 (n-1)=n-1) 1:/# map_id.
qed.

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
        stream <- stream ++ bits_to_bytes d; blk <- blk+1;
      }
      order <- rev (shuffle_order n stream);
    }
    return order;
  }
}.

lemma shuffle_derive_common (O <: PreparationOracle) :
  equiv [RawShuffle(O).derive ~ PairedShuffle(O).derive :
    ={arg, glob O} ==> ={res, glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + wp; call (_ : ={arg, glob O} ==> ={res, glob O}); first by sim.
    by auto; rewrite shuffle_seed_common.
  by auto.
qed.

lemma shuffle_permutation_common (O <: PreparationOracle) :
  equiv [RawShuffle(O).permutation ~ PairedShuffle(O).permutation :
    ={arg, glob O} /\ 0 <= n{1} <= 64 ==> ={res, glob O}].
proof.
  proc; sp 1 1; if; first by auto.
  + seq 3 3 : (={n, stream, glob O} /\ 1 < n{1} /\
      order{1} = range 0 n{1} /\ order{2} = range 0 n{2}).
    + while (={seed, n, stream, blk, glob O} /\ 0 <= blk{1} <= 4 /\
        1 < n{1} /\ order{1} = range 0 n{1} /\ order{2} = range 0 n{2}).
      + wp; call (_ : ={arg, glob O} ==> ={res, glob O}); first by sim.
        auto; move=> &1 &2 h.
        have hb : 0 <= blk{1} < 2^32 by rewrite caller_u32_size; smt().
        have hq := shuffle_block_common seed{1} blk{1} hb.
        smt().
      by auto; smt().
    wp 3 0.
    while{1} (={n, stream, glob O} /\ 1 < n{1} /\
      0 <= i{1} < n{1} /\ pos{1} + 2*i{1} = 2*(n{1}-1) /\
      shuffle_finish n{1} stream{1} i{1} order{1} = shuffle_order n{2} stream{2})
      i{1}.
    + move=> &m z; auto; move=> &hr [hinv hguard].
      have hi : 1 <= i{hr} by smt().
      have hp : 2 * max 0 (max 0 (n{hr}-1)-i{hr}) = pos{hr} by smt().
      have hs := shuffle_finish_step n{hr} stream{hr} i{hr} order{hr} hi.
      rewrite /shuffle_swap /shuffle_choice hp in hs.
      rewrite /= -hs; smt().
    by auto; smt(shuffle_finish_initial shuffle_finish_zero).
  by auto.
qed.
