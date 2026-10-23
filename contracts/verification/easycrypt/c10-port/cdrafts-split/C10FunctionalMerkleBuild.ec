(* Functional values of the actual XMSS builders under the fixed backend. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors RawMerkle.
require import C10Representation C10FixedBackend C10FixedCallerBridge.
require import C10CallerInputBridge C10PrivateCallerBridge C10TreeCallerBridge.
require import C10FunctionalWotsValue C10FunctionalWotsKeygen.
require import C10FunctionalBuildValue C10FunctionalBuildStack C10FunctionalBuildBackend C10FunctionalBuildOutside.
require import MerkleCatalogObserver MerkleBuildWitness MerkleCatalogAuth AuthSlots AuthPhase.
require import DyadicStack StackProjection StackAlignment StackPowers CatalogStack NodeCatalog.

op functional_merkle_node f key seed layer tree height index =
  functional_build_node (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) height index.
op functional_merkle_forest f key seed layer tree stack n =
  functional_build_forest (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) stack n.
op functional_merkle_catalog f key seed layer tree catalog =
  functional_build_catalog (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) catalog.

lemma fixed_builder_common_leaf_value f key0 seed0 layer0 tree0 kp0 :
  hoare[CommonPrivateWots(FixedPrefix).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\ FixedPrefix.key = key0 /\
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  exists* FixedBackend.history, FixedBackend.calls; elim* => hist c.
  conseq (fixed_functional_keygen f hist c key0 seed0 layer0 tree0 kp0); smt().
qed.

lemma fixed_builder_raw_leaf_value f key0 seed0 layer0 tree0 kp0 :
  hoare[RawKeygen(PreparationView(FixedPrefix)).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\ FixedPrefix.key = key0 /\
    FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (caller_keygen_leaf FixedPrefix)
    (fixed_builder_common_leaf_value f key0 seed0 layer0 tree0 kp0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},kp{m}); smt().
  smt().
qed.

lemma functional_merkle_leaf_build f key seed layer tree j : 0 <= j < 512 =>
  functional_merkle_node f key seed layer tree 0 j =
    wots_keygen_value (interpreted_backend f) seed key layer tree j.
proof.
  by move=> hj; rewrite /functional_merkle_node functional_build_node_zero /merkle_tree_leaves
    nth_mkseq 1:hj.
qed.

lemma functional_merkle_root_build_projection (O <: PreparationOracle) :
  equiv[RawKeygen(O).root ~ RawMerkle(O).build : ={seed,layer,tree,glob O} ==>
    res{1} = res{2}.`2 /\ ={glob O}].
proof.
  proc; while (={seed,layer,tree,kp,stack,glob O}).
  + wp; while (={seed,layer,tree,kp,current,height,stack,glob O}).
    - wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
      auto.
    wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
    auto.
  auto.
qed.

lemma functional_merkle_catalog_set f key seed layer tree catalog h i value :
  functional_merkle_catalog f key seed layer tree catalog =>
  value = functional_merkle_node f key seed layer tree h i =>
  functional_merkle_catalog f key seed layer tree catalog.[(h,i) <- value].
proof.
  rewrite /functional_merkle_catalog /functional_merkle_node.
  exact (functional_build_catalog_set (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) catalog h i value).
qed.

lemma functional_merkle_pair_build f key seed layer tree stack j h current :
  backend_width f => tree_fields layer tree => 0 <= j < 512 =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = j+1 =>
  functional_merkle_forest f key seed layer tree stack (j+1-2^h) =>
  current = functional_merkle_node f key seed layer tree h (j %/ (2^h)) =>
  node (f (seed ++ address layer tree 2 0 0 (h+1) (j %/ (2^(h+1))) ++
    pad (head ([],0) stack).`1 ++ pad current)) =
      functional_merkle_node f key seed layer tree (h+1) (j %/ (2^(h+1))) /\
  functional_merkle_forest f key seed layer tree (behead stack) (j+1-2^(h+1)).
proof.
  move=> hf hfields hj ha hs hh hm hforest hc.
  have hb := tree_stack_bounds stack h j _ ha hm; first by smt().
  have he := tree_pair_query seed layer tree 2 0 (h+1) (j %/ (2^(h+1)))
    (head ([],0) stack).`1 current hfields _ _ _ _; first 4 by smt(caller_u32_size).
  rewrite he interpreted_node 1:hf.
  have hv := functional_build_merge (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) stack (j+1) h current
    _ _ ha hs hh hm _ _; try by rewrite ?stack_pow2_9; smt().
qed.

lemma fixed_merkle_catalog_values f key0 seed0 layer0 tree0 :
  hoare[MerkleCatalogObserver(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    functional_merkle_catalog f key0 seed0 layer0 tree0 res.`3 /\
    functional_merkle_forest f key0 seed0 layer0 tree0 res.`2 512 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = kp /\
    functional_merkle_forest f key0 seed0 layer0 tree0 stack kp /\
    functional_merkle_catalog f key0 seed0 layer0 tree0 catalog).
  + wp; while (seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
      FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = kp+1 /\
      functional_merkle_forest f key0 seed0 layer0 tree0 stack (kp+1-2^height) /\
      current = functional_merkle_node f key0 seed0 layer0 tree0 height (kp %/ (2^height)) /\
      functional_merkle_catalog f key0 seed0 layer0 tree0 catalog).
    - exists* stack, current, height, kp; elim* => st0 cur0 h0 kp0.
      wp; call (fixed_builder_hash_value f
        (seed0 ++ address layer0 tree0 2 0 0 (h0+1) (kp0 %/ (2^(h0+1))) ++
          pad (head ([],0) st0).`1 ++ pad cur0)).
      auto; move=> &hr hi.
      have hp := projected_carry_pop st0 [] h0.
      have hv := functional_merkle_pair_build f key0 seed0 layer0 tree0 st0 kp0 h0 cur0.
      smt(functional_merkle_catalog_set).
    wp; exists* kp; elim* => kp0.
    call (fixed_builder_raw_leaf_value f key0 seed0 layer0 tree0 kp0).
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
    - rewrite divz1; smt(carry_initial functional_merkle_catalog_set).
    move=> history1 cat current h st hx hin.
    have hpush := hp st h current (kp{hr}+1) _ _ _ _ _; first 5 by smt().
    move: hpush; rewrite /=; smt().
  auto; rewrite /functional_merkle_forest /functional_build_forest /functional_merkle_catalog;
    smt(functional_build_catalog_empty).
qed.

lemma functional_merkle_forest_root f key seed layer tree stack :
  map snd stack = [9] => functional_merkle_forest f key seed layer tree stack 512 =>
  (head (nseq 16 0,0) stack).`1 = merkle_root_value (interpreted_backend f) seed key layer tree.
proof.
  move=> hs hf; rewrite /merkle_root_value.
  apply (functional_build_forest_root (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) stack) => //.
  by move: hf; rewrite /functional_merkle_forest stack_pow2_9.
qed.

lemma functional_merkle_catalog_path f key seed layer tree catalog auth target :
  0 <= target < 512 => functional_merkle_catalog f key seed layer tree catalog =>
  slots_saved catalog auth target 9 (captured_full 512 target) =>
  auth = merkle_auth_values (interpreted_backend f) seed key layer tree target.
proof.
  move=> htarg hc ha; rewrite /merkle_auth_values.
  apply (functional_build_catalog_auth (interpreted_backend f) seed layer tree 2 0 9
    (merkle_tree_leaves (interpreted_backend f) seed key layer tree) catalog auth target) => //.
  + by rewrite stack_pow2_9.
  by rewrite stack_pow2_9.
qed.


lemma fixed_merkle_catalog_root f key0 seed0 layer0 tree0 :
  hoare[MerkleCatalogObserver(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`2).`1 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    functional_merkle_catalog f key0 seed0 layer0 tree0 res.`3 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_catalog_complete (PreparationView(FixedPrefix)))
    (fixed_merkle_catalog_values f key0 seed0 layer0 tree0); smt(functional_merkle_forest_root).
qed.

lemma fixed_merkle_catalog_valid f key0 seed0 layer0 tree0 target0 :
  hoare[MerkleCatalogObserver(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ 0 <= target0 < 512 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`2).`1 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    res.`1 = merkle_auth_values (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fixed_merkle_catalog_root f key0 seed0 layer0 tree0)
    (merkle_catalog_auth (PreparationView(FixedPrefix)) target0); smt(functional_merkle_catalog_path).
qed.

lemma fixed_merkle_witness_root f key0 seed0 layer0 tree0 target0 :
  hoare[MerkleBuildWitness(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`2).`1 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_catalog_root f key0 seed0 layer0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_merkle_raw_build_root f key0 seed0 layer0 tree0 target0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`2 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_build_witness_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_witness_root f key0 seed0 layer0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_merkle_witness_valid f key0 seed0 layer0 tree0 target0 :
  hoare[MerkleBuildWitness(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ 0 <= target0 < 512 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`2).`1 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    res.`1 = merkle_auth_values (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_catalog_valid f key0 seed0 layer0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_merkle_raw_build_valid f key0 seed0 layer0 tree0 target0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ 0 <= target0 < 512 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`2 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    res.`1 = merkle_auth_values (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (merkle_build_witness_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_witness_valid f key0 seed0 layer0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},target{m}); smt().
  smt().
qed.

lemma functional_merkle_auth_outside f key seed layer tree target : 512 <= target =>
  merkle_auth_values f seed key layer tree target = nseq 9 (nseq 16 0).
proof.
  move=> ho; rewrite /merkle_auth_values.
  apply (functional_auth_outside f seed layer tree 2 0 9 (merkle_tree_leaves f seed key layer tree) target);
    rewrite ?stack_pow2_9 /merkle_tree_leaves ?size_mkseq; smt().
qed.

lemma fixed_merkle_raw_build f key0 seed0 layer0 tree0 target0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ target = target0 /\
    tree_fields layer0 tree0 /\ 0 <= target0 < 2^32 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`2 = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    res.`1 = merkle_auth_values (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  case (target0 < 512) => ht.
  + conseq (fixed_merkle_raw_build_valid f key0 seed0 layer0 tree0 target0); smt().
  conseq (fixed_merkle_raw_build_root f key0 seed0 layer0 tree0 target0)
    (functional_merkle_outside (PreparationView(FixedPrefix)) target0);
    smt(functional_merkle_auth_outside).
qed.


lemma fixed_merkle_raw_root f key0 seed0 layer0 tree0 :
  hoare[RawKeygen(PreparationView(FixedPrefix)).root :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (functional_merkle_root_build_projection (PreparationView(FixedPrefix)))
    (fixed_merkle_raw_build_root f key0 seed0 layer0 tree0 0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},0); smt().
  smt().
qed.
