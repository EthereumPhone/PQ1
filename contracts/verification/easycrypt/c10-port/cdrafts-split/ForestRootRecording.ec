(* Actual shuffled forest signing produces a complete retained reference. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawShuffle.
require import PersistentGrind AcceptedContexts MonotoneHistory RawCountRecorded ForsComponentHistory.
require import ForsRootWitness ForsRootRecording ForsReturnedRoot ForestRootWitness ForestRootPrefix.
require import ForestCoordinates ForestWitness RawForsPathReplay RawShufflePermutation.

lemma hash_records_histories x0 s0 h0 :
  hoare [Independent.hash :
    x=x0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    Independent.rawhistory.[x0]=Some res /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof. conseq (hash_records_input x0) (independent_hash_extends s0 h0); smt(). qed.

lemma forest_one_root_prefix seed0 ht0 tree0 target0 roots0 visited :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\ 0<=target0<2048 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited ==>
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 tree0 res.`3].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (raw_forest_one_root seed0 ht0 tree0 target0) (fors_one_extends RawForest s0 h0);
    smt(extends_refl forest_root_prefix_extends).
qed.

lemma forest_last_root_prefix seed0 ht0 roots0 visited :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=12 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited ==>
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots0 visited /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 12 res].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (fors_root_records_root seed0 ht0 12) (fors_root_extends RawFors s0 h0);
    smt(extends_refl forest_root_prefix_extends).
qed.

lemma raw_forest_sign_root seed0 ht0 digest0 :
  hoare [RawForest(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 ==>
    forest_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 res.`3].
proof.
  proc; seq 7 : (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (range 0 12)).
  + while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ 0<=step<=12 /\
      perm_eq order (range 0 12) /\
      forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (take step order)).
    - exists* order,step,roots; elim* => ord st ro.
      wp; call (forest_one_root_prefix seed0 ht0 (nth 0 ord st) (forest_index digest0 (nth 0 ord st)) ro (take st ord)).
      auto; smt(forest_index_range forest_root_prefix_step take_nth perm_eq_size size_range mem_nth perm_eq_mem mem_range).
    wp; call (raw_shuffle_permutation (PreparationView(Independent)) 12 independent_hash_ll).
    call (_ : true ==> true); first by conseq (shuffle_derive_lossless (PreparationView(Independent)) independent_hash_ll).
    auto; smt(forest_root_prefix_empty forest_root_prefix_complete take0).
  seq 1 : (seed=seed0 /\ ht=ht0 /\
    forest_root_prefix Independent.rawhistory Independent.secrethistory seed0 ht0 roots (range 0 12) /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 12 last).
  + exists* roots; elim* => ro; call (forest_last_root_prefix seed0 ht0 ro (range 0 12)); auto.
  exists* roots,last,Independent.rawhistory,Independent.secrethistory; elim* => roots0 lastroot0 h0 s0.
  seq 3 : (seed=seed0 /\ ht=ht0 /\
    RawSignature.rows_width 13 roots /\
    (forall t, 0<=t<12 => fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 t (nth (nseq 16 0) roots t)) /\
    fors_root_witness Independent.rawhistory Independent.secrethistory seed0 ht0 12 lastroot0 /\
    Independent.rawhistory.[forest_special_input seed0 ht0 lastroot0]=Some d /\
    nth (nseq 16 0) roots 12=node d).
  + wp; call (hash_records_histories (forest_special_input seed0 ht0 lastroot0) s0 h0).
    auto; rewrite /forest_special_input /fors_leaf_input;
      smt(extends_refl forest_root_prefix_extends fors_root_witness_extends forest_root_special).
  exists* roots,d,Independent.rawhistory,Independent.secrethistory; elim* => roots1 special h1 s1.
  call (hash_records_histories (forest_compress_input seed0 ht0 roots1) s1 h1).
  auto; rewrite /forest_compress_input;
    smt(extends_refl forest_root_compressed_extends).
qed.
