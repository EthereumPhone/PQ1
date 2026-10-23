(* Exact fixed-backend history of XMSS construction, from actual catalog execution. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors RawMerkle.
require import C10Representation C10FixedBackend C10FixedCallerBridge C10CallerInputBridge C10PrivateCallerBridge.
require import C10TreeCallerBridge C10FunctionalWotsValue C10FunctionalWotsKeygen.
require import C10FunctionalBuildValue C10FunctionalBuildStack C10FunctionalBuildBackend C10FunctionalBuildHistory.
require import C10FunctionalMerkleBuild MerkleBuildWitness MerkleCatalogObserver DyadicStack StackProjection StackAlignment StackPowers CatalogStack NodeCatalog NodeCatalogDomain.

op functional_merkle_leaf_queries f key seed layer tree index =
  rcons (flatten (map (functional_keygen_queries f key seed layer tree index) (mkseq (fun i => i) 43)))
    (functional_keygen_compression f key seed layer tree index).

op functional_merkle_build_queries f key seed layer tree height index =
  if height = 0 then functional_merkle_leaf_queries f key seed layer tree index else
    [seed ++ address layer tree 2 0 0 height index ++
      pad (functional_merkle_node f key seed layer tree (height-1) (2*index)) ++
      pad (functional_merkle_node f key seed layer tree (height-1) (2*index+1))].

lemma functional_history_flatten f history (queries : int -> raw_input list) indices :
  backend_history f history (flatten (map queries indices)) =
    foldl (fun table i => backend_history f table (queries i)) history indices.
proof.
  rewrite /backend_history.
  elim indices history => [history|i indices ih history]; first by rewrite /=.
  by rewrite map_cons flatten_cons /= foldl_cat ih.
qed.

lemma functional_merkle_leaf_history_order f history key seed layer tree index :
  backend_history f history (functional_merkle_leaf_queries f key seed layer tree index) =
    remember (functional_keygen_history f history key seed layer tree index 43)
      (functional_keygen_compression f key seed layer tree index)
      (f (functional_keygen_compression f key seed layer tree index)).
proof.
  by rewrite /functional_merkle_leaf_queries backend_history_rcons functional_history_flatten
    /functional_keygen_history.
qed.

lemma fixed_builder_common_leaf_history f history0 key0 seed0 layer0 tree0 kp0 :
  hoare[CommonPrivateWots(FixedPrefix).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\ FixedPrefix.key = key0 /\
    FixedBackend.fn = f /\ FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = backend_history f history0 (functional_merkle_leaf_queries f key0 seed0 layer0 tree0 kp0) /\
    backend_consistent FixedBackend.history f].
proof.
  exists* FixedBackend.calls; elim* => c.
  conseq (fixed_functional_keygen f history0 c key0 seed0 layer0 tree0 kp0);
    smt(functional_merkle_leaf_history_order).
qed.

lemma fixed_builder_raw_leaf_history f history0 key0 seed0 layer0 tree0 kp0 :
  hoare[RawKeygen(PreparationView(FixedPrefix)).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\ FixedPrefix.key = key0 /\
    FixedBackend.fn = f /\ FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = backend_history f history0 (functional_merkle_leaf_queries f key0 seed0 layer0 tree0 kp0) /\
    backend_consistent FixedBackend.history f].
proof.
  conseq (caller_keygen_leaf FixedPrefix)
    (fixed_builder_common_leaf_history f history0 key0 seed0 layer0 tree0 kp0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},kp{m}); smt().
  smt().
qed.

lemma functional_merkle_leaf_history f initial history key seed layer tree catalog j value :
  backend_consistent initial f =>
  functional_catalog_history f initial history (functional_merkle_build_queries f key seed layer tree) catalog =>
  functional_catalog_history f initial
    (backend_history f history (functional_merkle_leaf_queries f key seed layer tree j))
    (functional_merkle_build_queries f key seed layer tree) catalog.[(0,j) <- value].
proof.
  move=> hc hh.
  have hs := functional_catalog_history_set f initial history
    (functional_merkle_build_queries f key seed layer tree) catalog 0 j value hc hh.
  by move: hs; rewrite /functional_merkle_build_queries /=.
qed.

lemma functional_merkle_pair_history f initial history key seed layer tree catalog stack j h current value :
  backend_consistent initial f =>
  functional_catalog_history f initial history (functional_merkle_build_queries f key seed layer tree) catalog =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = j+1 =>
  functional_merkle_forest f key seed layer tree stack (j+1-2^h) =>
  current = functional_merkle_node f key seed layer tree h (j %/ (2^h)) =>
  functional_catalog_history f initial
    (remember history (seed ++ address layer tree 2 0 0 (h+1) (j %/ (2^(h+1))) ++
        pad (head ([],0) stack).`1 ++ pad current)
      (f (seed ++ address layer tree 2 0 0 (h+1) (j %/ (2^(h+1))) ++
        pad (head ([],0) stack).`1 ++ pad current)))
    (functional_merkle_build_queries f key seed layer tree) catalog.[(h+1,j %/ (2^(h+1))) <- value].
proof.
  move=> hc hh ha hs he hm hf hv.
  have hp := functional_build_pair_children (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) stack (j+1) h current ha hs he hm hf hv.
  have hz : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hset := functional_catalog_history_set f initial history
    (functional_merkle_build_queries f key seed layer tree) catalog (h+1) (j %/ (2^(h+1))) value hc hh.
  move: hset; rewrite /functional_merkle_build_queries (_ : h+1 <> 0) 1:/# /= /backend_history /=.
  move: hp; rewrite /functional_merkle_node; smt().
qed.


lemma fixed_merkle_catalog_history f initial key0 seed0 layer0 tree0 :
  hoare[MerkleCatalogObserver(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ FixedBackend.history = initial ==>
    functional_merkle_catalog f key0 seed0 layer0 tree0 res.`3 /\
    functional_merkle_forest f key0 seed0 layer0 tree0 res.`2 512 /\
    functional_catalog_history f initial FixedBackend.history (functional_merkle_build_queries f key0 seed0 layer0 tree0) res.`3 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = kp /\
    functional_merkle_forest f key0 seed0 layer0 tree0 stack kp /\
    functional_merkle_catalog f key0 seed0 layer0 tree0 catalog /\ backend_consistent initial f /\
    functional_catalog_history f initial FixedBackend.history (functional_merkle_build_queries f key0 seed0 layer0 tree0) catalog).
  + wp; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
      FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = kp+1 /\
      functional_merkle_forest f key0 seed0 layer0 tree0 stack (kp+1-2^height) /\
      current = functional_merkle_node f key0 seed0 layer0 tree0 height (kp %/ (2^height)) /\
      functional_merkle_catalog f key0 seed0 layer0 tree0 catalog /\ backend_consistent initial f /\
    functional_catalog_history f initial FixedBackend.history (functional_merkle_build_queries f key0 seed0 layer0 tree0) catalog).
    - exists* stack, current, height, kp, FixedBackend.history; elim* => st0 cur0 h0 kp0 hist0.
      wp; call (fixed_builder_hash_history f hist0
        (seed0 ++ address layer0 tree0 2 0 0 (h0+1) (kp0 %/ (2^(h0+1))) ++
          pad (head ([],0) st0).`1 ++ pad cur0)).
      auto; move=> &hr hi.
      have hp := projected_carry_pop st0 [] h0.
      have hv := functional_merkle_pair_build f key0 seed0 layer0 tree0 st0 kp0 h0 cur0.
      smt(functional_merkle_catalog_set functional_merkle_pair_history).
    wp; exists* kp, FixedBackend.history; elim* => kp0 hist0.
    call (fixed_builder_raw_leaf_history f hist0 key0 seed0 layer0 tree0 kp0).
    auto; rewrite ?expr0 ?divz1.
    move=> &hr hi.
    have hv := functional_merkle_leaf_build f key0 seed0 layer0 tree0 kp0.
    have hp : forall st h current n,
      active_stack (map snd st) h =>
      (st = [] \/ (head ([],0) st).`2 <> h) =>
      stack_mass (map snd st)+2^h = n =>
      functional_merkle_forest f key0 seed0 layer0 tree0 st (n-2^h) =>
      current = functional_merkle_node f key0 seed0 layer0 tree0 h ((n-1) %/ (2^h)) =>
      increasing_stack (map snd ((current,h)::st)) /\
      functional_merkle_forest f key0 seed0 layer0 tree0 ((current,h)::st) n.
    - move=> st h current n ha hx hm hf hc.
      have hd := active_stack_alignment (map snd st) h n ha hm.
      have hz : 0 <= h by move: ha; rewrite /active_stack; smt().
      have hs := projected_carry_push st [] current h ha hx.
      split; first exact hs.
      rewrite /functional_merkle_forest.
      apply (functional_build_forest_push (interpreted_backend f) seed0 layer0 tree0 2 0 9
        (merkle_tree_leaves (interpreted_backend f) seed0 key0 layer0 tree0) st n current h hz hd).
      + by move: hc; rewrite /functional_merkle_node.
      by move: hf; rewrite /functional_merkle_forest.
    split; first by rewrite /caller_fields; move: hi; rewrite /tree_fields; smt(caller_u32_size).
    move=> hpre value history0 hvalue; split.
    - rewrite divz1; smt(carry_initial functional_merkle_catalog_set functional_merkle_leaf_history).
    move=> history1 cat current h st hx hin.
    have hpush := hp st h current (kp{hr}+1) _ _ _ _ _; first 5 by smt().
    move: hpush; rewrite /=; smt().
  auto; rewrite /functional_merkle_forest /functional_build_forest /functional_merkle_catalog;
    smt(functional_build_catalog_empty functional_catalog_history_empty).
qed.


lemma fixed_merkle_catalog_exact_history f initial key0 seed0 layer0 tree0 :
  hoare[MerkleCatalogObserver(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_catalog_complete (PreparationView(FixedPrefix)))
    (fixed_merkle_catalog_history f initial key0 seed0 layer0 tree0);
    smt(functional_catalog_history_complete stack_pow2_9).
qed.

lemma fixed_merkle_witness_history f initial key0 seed0 layer0 tree0 :
  hoare[MerkleBuildWitness(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_catalog_exact_history f initial key0 seed0 layer0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_merkle_raw_build_history f initial key0 seed0 layer0 tree0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_build_witness_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_witness_history f initial key0 seed0 layer0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.
