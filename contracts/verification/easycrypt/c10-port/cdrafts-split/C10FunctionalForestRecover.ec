(* Actual complete forest recovery: twelve normal paths, the root-as-secret
   thirteenth slot, then compression; arbitrary consistent initial history. *)
require import AllCore List FMap.
require import C10Bytes C10RawOracle RawKeygen RawForest KeygenPrefixes C10Representation.
require import C10FixedBackend C10FixedCallerBridge C10OuterCallerBridge.
require import C10TreeCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalForsRecovery.

op functional_forest_indices d = mkseq (forest_index d) 13.
op functional_forest_normal_roots f seed ht d secrets auths n =
  mkseq (fun t => fors_recover_value (interpreted_backend f) seed ht t (forest_index d t)
    (nth (nseq 16 0) secrets t) (nth [] auths t)) n.
op functional_forest_normal_history f h seed ht d secrets auths n =
  foldl (fun table t => functional_fors_recovery_history f table seed ht t (forest_index d t)
    (nth (nseq 16 0) secrets t) (nth [] auths t) 11) h (mkseq (fun t => t) n).
op functional_forest_last_query seed ht secrets =
  functional_fors_leaf_query seed ht 12 0 (nth (nseq 16 0) secrets 12).
op functional_forest_compression f seed ht d secrets auths =
  multi_preimage seed (address_words 0 ht 4 0 0 0 0)
    (rcons (functional_forest_normal_roots f seed ht d secrets auths 12)
      (node (f (functional_forest_last_query seed ht secrets)))).
op functional_forest_recovery_history f h seed ht d secrets auths =
  let last = functional_forest_last_query seed ht secrets in
  let comp = functional_forest_compression f seed ht d secrets auths in
  remember (remember (functional_forest_normal_history f h seed ht d secrets auths 12)
    last (f last)) comp (f comp).

lemma functional_forest_history_zero f h seed ht d secrets auths :
  functional_forest_normal_history f h seed ht d secrets auths 0 = h.
proof. by rewrite /functional_forest_normal_history mkseq0. qed.

lemma functional_forest_history_next f h seed ht d secrets auths t : 0 <= t =>
  functional_forest_normal_history f h seed ht d secrets auths (t+1) =
    functional_fors_recovery_history f
      (functional_forest_normal_history f h seed ht d secrets auths t)
      seed ht t (forest_index d t) (nth (nseq 16 0) secrets t) (nth [] auths t) 11.
proof. by move=> hn; rewrite /functional_forest_normal_history mkseqS 1:hn foldl_rcons. qed.

lemma functional_forest_roots_value f seed ht d secrets auths : backend_width f =>
  forest_recover_roots (interpreted_backend f) seed ht (functional_forest_indices d) secrets auths =
    rcons (functional_forest_normal_roots f seed ht d secrets auths 12)
      (node (f (functional_forest_last_query seed ht secrets))).
proof.
  move=> hf; rewrite /forest_recover_roots /functional_forest_indices /functional_forest_normal_roots -cats1.
  congr.
  + apply eq_in_mkseq => t hb; smt(nth_mkseq).
  by rewrite /functional_forest_last_query functional_fors_leaf 1:hf.
qed.

lemma fixed_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0 :
  hoare[CommonInputForest(FixedPrefix).recover :
    seed = seed0 /\ ht = ht0 /\ digest = d0 /\ secrets = secrets0 /\ auths = auths0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = forest_recover_value (interpreted_backend f) seed0 ht0 (functional_forest_indices d0) secrets0 auths0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_recovery_history f h seed0 ht0 d0 secrets0 auths0 /\
    FixedBackend.calls = c+146].
proof.
  proc.
  call (fixed_hash f
    (remember (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 12)
      (functional_forest_last_query seed0 ht0 secrets0) (f (functional_forest_last_query seed0 ht0 secrets0)))
    (functional_forest_compression f seed0 ht0 d0 secrets0 auths0) (c+145)).
  wp; call (fixed_hash f (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 12)
    (functional_forest_last_query seed0 ht0 secrets0) (c+144)).
  while (seed = seed0 /\ ht = ht0 /\ digest = d0 /\ secrets = secrets0 /\ auths = auths0 /\
    0 <= t <= 12 /\ roots = functional_forest_normal_roots f seed0 ht0 d0 secrets0 auths0 t /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 t /\
    FixedBackend.calls = c+12*t).
  + exists* t; elim* => t0; wp.
    call (fixed_functional_fors f (functional_forest_normal_history f h seed0 ht0 d0 secrets0 auths0 t0)
      (c+12*t0) key0 seed0 ht0 t0 (forest_index d0 t0)
      (nth (nseq 16 0) secrets0 t0) (nth [] auths0 t0)).
    auto => />; rewrite /functional_forest_normal_roots;
      smt(mkseqS functional_forest_history_next).
  auto => />; rewrite /functional_forest_normal_roots mkseq0 functional_forest_history_zero
    /functional_forest_last_query /functional_fors_leaf_query /functional_forest_compression
    /functional_forest_recovery_history /forest_recover_value /forest_compress_value;
    smt(functional_forest_roots_value interpreted_node).
qed.

lemma raw_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0 :
  equiv[RawForest(PreparationView(FixedPrefix)).recover ~ CommonInputForest(FixedPrefix).recover :
    ={seed,ht,digest,secrets,auths,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ digest{1} = d0 /\ secrets{1} = secrets0 /\ auths{1} = auths0 /\
    0 <= ht0 < 2^32 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = forest_recover_value (interpreted_backend f) seed0 ht0 (functional_forest_indices d0) secrets0 auths0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_forest_recovery_history f h seed0 ht0 d0 secrets0 auths0 /\
    FixedBackend.calls{1} = c+146].
proof.
  conseq (caller_forest_recover FixedPrefix) (_ : true ==> true)
    (fixed_functional_forest_recover f h c key0 seed0 ht0 d0 secrets0 auths0) => //; smt().
qed.

lemma raw_functional_forest_recover_lossless :
  islossless RawForest(PreparationView(FixedPrefix)).recover.
proof. exact (forest_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma common_functional_fors_recover_lossless :
  islossless CommonInputFors(FixedPrefix).recover.
proof.
  proc; while true (11-h).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  wp; call fixed_hash_ll; auto; smt().
qed.

lemma fixed_functional_forest_recover_lossless :
  islossless CommonInputForest(FixedPrefix).recover.
proof.
  proc; call fixed_hash_ll; wp; call fixed_hash_ll.
  while true (12-t).
  + move=> z; wp; call common_functional_fors_recover_lossless; auto; smt().
  auto; smt().
qed.
