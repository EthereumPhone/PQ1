(* Fixed-backend derivation and the forest's twelve-position permutation. *)
require import AllCore List FMap.
require import C10Bytes C10RawOracle RawShuffle KeygenPrefixes C10Representation.
require import C10FixedBackend C10FixedCallerBridge C10ShuffleBridge.
require import C10FunctionalWots C10FunctionalWotsShuffle C10PrivateCallerBridge.

op functional_derived_seed f seed label =
  if seed = nseq 32 0 then nseq 32 0 else bits_to_bytes (f (shuffle_seed_preimage seed label)).
op functional_derive_history f h seed label =
  if seed = nseq 32 0 then h else
    remember h (shuffle_seed_preimage seed label) (f (shuffle_seed_preimage seed label)).
op functional_derive_cost seed = if seed = nseq 32 0 then 0 else 1.

lemma fixed_functional_derive f h c key0 seed0 label0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).derive :
    seed = seed0 /\ label = label0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_derived_seed f seed0 label0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_derive_history f h seed0 label0 /\
    FixedBackend.calls = c+functional_derive_cost seed0].
proof.
  proc; sp 1; if.
  + wp; call (fixed_hash f h (shuffle_seed_preimage seed0 label0) c).
    auto; rewrite /functional_derived_seed /functional_derive_history /functional_derive_cost; smt().
  auto; rewrite /functional_derived_seed /functional_derive_history /functional_derive_cost; smt().
qed.

lemma fixed_functional_derive_lossless :
  islossless PairedShuffle(PreparationView(FixedPrefix)).derive.
proof. proc; sp 1; if; last by auto. wp; call fixed_hash_ll; auto. qed.

op functional_forest_order f seed = if seed = nseq 32 0 then range 0 12
  else shuffle_order 12 (functional_shuffle_stream f seed 4).

lemma fixed_functional_forest_shuffle_value f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 12 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_forest_order f seed0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  proc; sp 1; if.
  + wp; while (seed = seed0 /\ n = 12 /\ seed0 <> nseq 32 0 /\ 0 <= blk <= 4 /\
      stream = functional_shuffle_stream f seed0 blk /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
      FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) blk) /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+blk).
    - exists* blk; elim* => b; wp.
      call (fixed_hash f (backend_history f h (mkseq (shuffle_block_preimage seed0) b))
        (shuffle_block_preimage seed0 b) (c+b)).
      auto; smt(functional_shuffle_stream_next backend_history_mkseqS).
    auto => />; rewrite functional_shuffle_stream_zero mkseq0 backend_history_nil
      /functional_shuffle_steps /functional_forest_order; smt().
  auto => />; rewrite /functional_shuffle_steps /functional_forest_order mkseq0 backend_history_nil; smt().
qed.

lemma functional_shuffle_reverse :
  equiv[PairedShuffle(PreparationView(FixedPrefix)).permutation ~ RawShuffle(PreparationView(FixedPrefix)).permutation :
    ={arg,glob FixedPrefix} /\ 0 <= n{1} <= 64 ==> ={res,glob FixedPrefix}].
proof. symmetry; conseq (shuffle_permutation_common (PreparationView(FixedPrefix))); smt(). qed.

lemma paired_forest_shuffle_permutation :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation : n = 12 ==>
    perm_eq res (range 0 12)].
proof.
  conseq functional_shuffle_reverse
    (caller_shuffle_permutation (PreparationView(FixedPrefix)) 12).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},n{m}); smt().
  smt().
qed.

lemma fixed_functional_forest_shuffle f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 12 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_forest_order f seed0 /\ perm_eq res (range 0 12) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  conseq (fixed_functional_forest_shuffle_value f h c key0 seed0) paired_forest_shuffle_permutation; smt().
qed.
