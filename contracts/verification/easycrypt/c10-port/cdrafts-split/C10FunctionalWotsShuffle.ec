(* Exact four-block shuffle interpretation used by actual WOTS signing. *)
require import AllCore List FMap.
require import C10Bytes C10RawOracle C10Representation KeygenPrefixes.
require import C10FixedBackend C10FunctionalWots C10ShuffleBridge ShuffleBytes ShuffleSwap.

op functional_shuffle_stream f seed n =
  flatten (mkseq (fun i => bits_to_bytes (f (shuffle_block_preimage seed i))) n).
op functional_shuffle_steps seed = if seed = nseq 32 0 then 0 else 4.
op functional_shuffle_order f seed = if seed = nseq 32 0 then range 0 43
  else shuffle_order 43 (functional_shuffle_stream f seed 4).

lemma functional_shuffle_stream_zero f seed : functional_shuffle_stream f seed 0 = [].
proof. by rewrite /functional_shuffle_stream mkseq0. qed.

lemma functional_shuffle_stream_next f seed i : 0 <= i =>
  functional_shuffle_stream f seed (i+1) =
    functional_shuffle_stream f seed i ++ bits_to_bytes (f (shuffle_block_preimage seed i)).
proof. by move=> hi; rewrite /functional_shuffle_stream mkseqS 1:hi flatten_rcons. qed.

lemma functional_shuffle_stream_valid f seed n :
  all (fun b => 0 <= b < 256) (functional_shuffle_stream f seed n).
proof.
  rewrite /functional_shuffle_stream /mkseq; apply/allP => x /flatten_mapP [i [hi hx]].
  have hb := shuffle_bytes_valid (f (shuffle_block_preimage seed i)).
  move: hb => /allP; smt().
qed.

op functional_shuffle_fold stream indices order =
  foldr (fun i out => shuffle_swap out i
    (shuffle_choice (nth 0 stream (2 * max 0 (42-i)))
      (nth 0 stream (2 * max 0 (42-i)+1)) (i+1))) order indices.

lemma functional_shuffle_fold_perm stream indices order :
  all (fun b => 0 <= b < 256) stream =>
  all (fun i => 0 <= i < 43) indices => perm_eq order (range 0 43) =>
  perm_eq (functional_shuffle_fold stream indices order) (range 0 43).
proof.
  move=> hs; elim: indices => [|i indices ih] /=; first by rewrite /functional_shuffle_fold.
  move=> [hi hi'] ho.
  have hp := ih hi' ho.
  have hlen : size (functional_shuffle_fold stream indices order) = 43
    by smt(perm_eq_size size_range).
  have hlo := shuffle_nth_byte stream (2*max 0 (42-i)) hs.
  have hhi := shuffle_nth_byte stream (2*max 0 (42-i)+1) hs.
  have hj := shuffle_mulhi_range _ _ i hlo hhi _; first smt().
  have hswap := swap_put_permutation 0 (functional_shuffle_fold stream indices order) i
    (shuffle_choice (nth 0 stream (2*max 0 (42-i))) (nth 0 stream (2*max 0 (42-i)+1)) (i+1)) _ _.
  + smt().
  + move: hj; rewrite /shuffle_choice; smt().
  have he : functional_shuffle_fold stream (i::indices) order =
    shuffle_swap (functional_shuffle_fold stream indices order) i
      (shuffle_choice (nth 0 stream (2*max 0 (42-i)))
        (nth 0 stream (2*max 0 (42-i)+1)) (i+1)) by rewrite /functional_shuffle_fold.
  rewrite he /shuffle_swap.
  exact (perm_eq_trans _ _ _ hswap hp).
qed.

lemma functional_shuffle_order_perm f seed :
  perm_eq (functional_shuffle_order f seed) (range 0 43).
proof.
  rewrite /functional_shuffle_order; case (seed = nseq 32 0) => hs /=; first exact (perm_eq_refl _).
  have hi : all (fun i => 0 <= i < 43) (mkseq (fun i => i+1) 42).
  + apply/allP => i /mapP [j [hj ->]]; move: hj; rewrite mem_iota; smt().
  have hp := functional_shuffle_fold_perm (functional_shuffle_stream f seed 4)
    (mkseq (fun i => i+1) 42) (range 0 43) (functional_shuffle_stream_valid f seed 4) hi (perm_eq_refl _).
  by move: hp; rewrite /functional_shuffle_fold /shuffle_order /range /mkseq /= map_id.
qed.

lemma fixed_functional_shuffle f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 43 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_shuffle_order f seed0 /\ perm_eq res (range 0 43) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  proc; sp 1; if.
  + wp; while (
      seed = seed0 /\ n = 43 /\ seed0 <> nseq 32 0 /\ 0 <= blk <= 4 /\
      stream = functional_shuffle_stream f seed0 blk /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
      FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) blk) /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+blk).
    - exists* blk; elim* => b; wp.
      call (fixed_hash f (backend_history f h (mkseq (shuffle_block_preimage seed0) b))
        (shuffle_block_preimage seed0 b) (c+b)).
      auto; smt(functional_shuffle_stream_next backend_history_mkseqS).
    auto => />; rewrite functional_shuffle_stream_zero mkseq0 backend_history_nil
      /functional_shuffle_steps /functional_shuffle_order;
      smt(functional_shuffle_order_perm).
  auto => />; rewrite /functional_shuffle_steps /functional_shuffle_order mkseq0 backend_history_nil;
    smt(perm_eq_refl).
qed.

lemma fixed_functional_shuffle_lossless :
  islossless PairedShuffle(PreparationView(FixedPrefix)).permutation.
proof.
  proc; sp 1; if; last by auto.
  wp; while true (4-blk).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.
