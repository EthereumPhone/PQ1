(* Exact fixed-backend history of FORS construction, from actual catalog execution. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors.
require import C10Representation C10FixedBackend C10FixedCallerBridge C10CallerInputBridge.
require import C10TreeCallerBridge C10FunctionalWotsValue C10FunctionalForsRecovery.
require import C10FunctionalBuildValue C10FunctionalBuildStack C10FunctionalBuildBackend C10FunctionalBuildHistory.
require import C10FunctionalForsBuild ForsBuildWitness ForsCatalogObserver DyadicStack StackProjection StackAlignment StackPowers CatalogStack NodeCatalog NodeCatalogDomain.

op functional_fors_build_queries f key seed ht tree height index =
  if height = 0 then
    [fors_private_preimage key ht tree index;
     seed ++ address 0 ht 3 tree 0 0 index ++
       pad (fors_secret_value (interpreted_backend f) key ht tree index)]
  else
    [seed ++ address 0 ht 3 tree 0 height index ++
      pad (functional_fors_node f key seed ht tree (height-1) (2*index)) ++
      pad (functional_fors_node f key seed ht tree (height-1) (2*index+1))].

lemma functional_fors_leaf_history f initial history key seed ht tree catalog j value :
  backend_consistent initial f =>
  functional_catalog_history f initial history (functional_fors_build_queries f key seed ht tree) catalog =>
  functional_catalog_history f initial
    (remember (remember history (fors_private_preimage key ht tree j) (f (fors_private_preimage key ht tree j)))
      (seed ++ address 0 ht 3 tree 0 0 j ++ pad (fors_secret_value (interpreted_backend f) key ht tree j))
      (f (seed ++ address 0 ht 3 tree 0 0 j ++ pad (fors_secret_value (interpreted_backend f) key ht tree j))))
    (functional_fors_build_queries f key seed ht tree) catalog.[(0,j) <- value].
proof.
  move=> hc hh.
  have hs := functional_catalog_history_set f initial history
    (functional_fors_build_queries f key seed ht tree) catalog 0 j value hc hh.
  by move: hs; rewrite /functional_fors_build_queries /backend_history /=.
qed.

lemma functional_fors_pair_history f initial history key seed ht tree catalog stack j h current value :
  backend_consistent initial f =>
  functional_catalog_history f initial history (functional_fors_build_queries f key seed ht tree) catalog =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = j+1 =>
  functional_fors_forest f key seed ht tree stack (j+1-2^h) =>
  current = functional_fors_node f key seed ht tree h (j %/ (2^h)) =>
  functional_catalog_history f initial
    (remember history (seed ++ address 0 ht 3 tree 0 (h+1) (j %/ (2^(h+1))) ++
        pad (head ([],0) stack).`1 ++ pad current)
      (f (seed ++ address 0 ht 3 tree 0 (h+1) (j %/ (2^(h+1))) ++
        pad (head ([],0) stack).`1 ++ pad current)))
    (functional_fors_build_queries f key seed ht tree) catalog.[(h+1,j %/ (2^(h+1))) <- value].
proof.
  move=> hc hh ha hs he hm hf hv.
  have hp := functional_build_pair_children (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) stack (j+1) h current ha hs he hm hf hv.
  have hz : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hset := functional_catalog_history_set f initial history
    (functional_fors_build_queries f key seed ht tree) catalog (h+1) (j %/ (2^(h+1))) value hc hh.
  move: hset; rewrite /functional_fors_build_queries (_ : h+1 <> 0) 1:/# /= /backend_history /=.
  move: hp; rewrite /functional_fors_node; smt().
qed.

lemma fixed_builder_fors_secret_history f history0 key0 ht0 tree0 i0 :
  hoare[PreparationView(FixedPrefix).fors : tail = fors_tail ht0 tree0 i0 /\
    fors_fields ht0 tree0 /\ 0 <= i0 < 2^32 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = history0 /\
    backend_consistent history0 f ==>
    node res = fors_secret_value (interpreted_backend f) key0 ht0 tree0 i0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember history0 (fors_private_preimage key0 ht0 tree0 i0)
      (f (fors_private_preimage key0 ht0 tree0 i0)) /\ backend_consistent FixedBackend.history f].
proof.
  proc; call (fixed_builder_derive_history f history0 key0 (fors_tag ++ fors_tail ht0 tree0 i0)); auto.
  move=> &m [ha [hf [hi [hw [hk [hfn [he hc]]]]]]].
  have hq := tree_fors_private_query ht0 tree0 i0 hf hi.
  rewrite hq functional_fors_private_prefix; smt(functional_fors_private).
qed.

lemma fixed_fors_catalog_history f initial key0 seed0 ht0 tree0 :
  hoare[ForsCatalogObserver(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\ FixedBackend.history = initial ==>
    functional_fors_catalog f key0 seed0 ht0 tree0 res.`3 /\
    functional_fors_forest f key0 seed0 ht0 tree0 res.`1 2048 /\
    functional_catalog_history f initial FixedBackend.history (functional_fors_build_queries f key0 seed0 ht0 tree0) res.`3 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = j /\
    functional_fors_forest f key0 seed0 ht0 tree0 stack j /\
    functional_fors_catalog f key0 seed0 ht0 tree0 catalog /\ backend_consistent initial f /\
    functional_catalog_history f initial FixedBackend.history (functional_fors_build_queries f key0 seed0 ht0 tree0) catalog).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
      FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = j+1 /\
      functional_fors_forest f key0 seed0 ht0 tree0 stack (j+1-2^height) /\
      current = functional_fors_node f key0 seed0 ht0 tree0 height (j %/ (2^height)) /\
      functional_fors_catalog f key0 seed0 ht0 tree0 catalog /\ backend_consistent initial f /\
    functional_catalog_history f initial FixedBackend.history (functional_fors_build_queries f key0 seed0 ht0 tree0) catalog).
    - exists* stack, current, height, j, FixedBackend.history; elim* => st0 cur0 h0 j0 hist0.
      wp; call (fixed_builder_hash_history f hist0
        (seed0 ++ address 0 ht0 3 tree0 0 (h0+1) (j0 %/ (2^(h0+1))) ++
          pad (head ([],0) st0).`1 ++ pad cur0)).
      auto; move=> &hr hi.
      have hp := projected_carry_pop st0 [] h0.
      have hv := functional_fors_pair_build f key0 seed0 ht0 tree0 st0 j0 h0 cur0.
      smt(functional_fors_catalog_set functional_fors_pair_history).
    wp; exists* j, FixedBackend.history; elim* => j0 hist0.
    call (fixed_builder_hash_history f
      (remember hist0 (fors_private_preimage key0 ht0 tree0 j0) (f (fors_private_preimage key0 ht0 tree0 j0))) (seed0 ++ address 0 ht0 3 tree0 0 0 j0 ++
      pad (fors_secret_value (interpreted_backend f) key0 ht0 tree0 j0))).
    wp; call (fixed_builder_fors_secret_history f hist0 key0 ht0 tree0 j0).
    auto; rewrite ?expr0 ?divz1.
    move=> &hr hi.
    have hv := functional_fors_leaf_build f key0 seed0 ht0 tree0 j0.
    have hp : forall st h current n,
      active_stack (map snd st) h =>
      (st = [] \/ (head ([],0) st).`2 <> h) =>
      stack_mass (map snd st)+2^h = n =>
      functional_fors_forest f key0 seed0 ht0 tree0 st (n-2^h) =>
      current = functional_fors_node f key0 seed0 ht0 tree0 h ((n-1) %/ (2^h)) =>
      increasing_stack (map snd ((current,h)::st)) /\
      functional_fors_forest f key0 seed0 ht0 tree0 ((current,h)::st) n.
    - move=> st h current n ha hx hm hf hc.
      have hd := active_stack_alignment (map snd st) h n ha hm.
      have hz : 0 <= h by move: ha; rewrite /active_stack; smt().
      have hs := projected_carry_push st [] current h ha hx.
      split; first exact hs.
      rewrite /functional_fors_forest.
      apply (functional_build_forest_push (interpreted_backend f) seed0 0 ht0 3 tree0 11
        (fors_tree_leaves (interpreted_backend f) seed0 key0 ht0 tree0) st n current h hz hd).
      + by move: hc; rewrite /functional_fors_node.
      by move: hf; rewrite /functional_fors_forest.
    split; first by smt(caller_u32_size).
    move=> hpre secret history hsecret; split; first by smt().
    move=> hhash value history0 hvalue; split.
    - rewrite divz1; smt(carry_initial functional_fors_catalog_set functional_fors_leaf_history).
    move=> history1 cat current h st hx hin.
    have hpush := hp st h current (j{hr}+1) _ _ _ _ _; first 5 by smt().
    move: hpush; rewrite /=; smt().
  auto; rewrite /functional_fors_forest /functional_build_forest /functional_fors_catalog;
    smt(functional_build_catalog_empty functional_catalog_history_empty).
qed.


lemma fixed_fors_catalog_exact_history f initial key0 seed0 ht0 tree0 :
  hoare[ForsCatalogObserver(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_catalog_complete (PreparationView(FixedPrefix)))
    (fixed_fors_catalog_history f initial key0 seed0 ht0 tree0);
    smt(functional_catalog_history_complete stack_pow2_11).
qed.

lemma fixed_fors_witness_history f initial key0 seed0 ht0 tree0 :
  hoare[ForsBuildWitness(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_fors_catalog_exact_history f initial key0 seed0 ht0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_fors_raw_tree_history f initial key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = initial /\ backend_consistent initial f ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_tree_witness_projection (PreparationView(FixedPrefix)))
    (fixed_fors_witness_history f initial key0 seed0 ht0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.
