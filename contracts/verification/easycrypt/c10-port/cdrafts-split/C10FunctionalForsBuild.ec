(* Functional values of the actual FORS stack and its proof-only catalog. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors.
require import C10Representation C10FixedBackend C10FixedCallerBridge C10CallerInputBridge.
require import C10TreeCallerBridge C10FunctionalWotsValue C10FunctionalForsRecovery.
require import C10FunctionalBuildValue C10FunctionalBuildStack C10FunctionalBuildBackend.
require import ForsCatalogObserver DyadicStack StackProjection StackAlignment StackPowers CatalogStack NodeCatalog.
require import ForsCatalogAuth ForsBuildWitness AuthSlots AuthPhase C10FunctionalBuildOutside.

op functional_fors_node f key seed ht tree height index =
  functional_build_node (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) height index.
op functional_fors_forest f key seed ht tree stack n =
  functional_build_forest (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) stack n.
op functional_fors_catalog f key seed ht tree catalog =
  functional_build_catalog (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) catalog.

lemma functional_fors_leaf_build f key seed ht tree j :
  backend_width f => fors_fields ht tree => 0 <= j < 2048 =>
  node (f (seed ++ address 0 ht 3 tree 0 0 j ++
    pad (fors_secret_value (interpreted_backend f) key ht tree j))) =
    functional_fors_node f key seed ht tree 0 j.
proof.
  move=> hf hfields hj.
  have hj32 : 0 <= j < 2^32 by smt(caller_u32_size).
  rewrite tree_fors_leaf_query 1:hfields 1:hj32.
  rewrite /functional_fors_node functional_fors_build_leaf 1:hj.
  exact (functional_fors_leaf f seed ht tree j
    (fors_secret_value (interpreted_backend f) key ht tree j) hf).
qed.

lemma functional_fors_forest_root f key seed ht tree stack :
  map snd stack = [11] => functional_fors_forest f key seed ht tree stack 2048 =>
  (head (nseq 16 0,0) stack).`1 = fors_root_value (interpreted_backend f) seed key ht tree.
proof.
  move=> hs hf; rewrite /fors_root_value.
  apply (functional_build_forest_root (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) stack) => //.
  by move: hf; rewrite /functional_fors_forest stack_pow2_11.
qed.

lemma functional_fors_catalog_path f key seed ht tree catalog auth target :
  0 <= target < 2048 => functional_fors_catalog f key seed ht tree catalog =>
  slots_saved catalog auth target 11 (captured_full 2048 target) =>
  auth = fors_auth_values (interpreted_backend f) seed key ht tree target.
proof.
  move=> htarg hc ha; rewrite /fors_auth_values.
  apply (functional_build_catalog_auth (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) catalog auth target) => //.
  + by rewrite stack_pow2_11.
  by rewrite stack_pow2_11.
qed.

lemma functional_fors_catalog_set f key seed ht tree catalog h i value :
  functional_fors_catalog f key seed ht tree catalog =>
  value = functional_fors_node f key seed ht tree h i =>
  functional_fors_catalog f key seed ht tree catalog.[(h,i) <- value].
proof.
  rewrite /functional_fors_catalog /functional_fors_node.
  exact (functional_build_catalog_set (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) catalog h i value).
qed.

lemma functional_fors_pair_build f key seed ht tree stack j h current :
  backend_width f => fors_fields ht tree => 0 <= j < 2048 =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = j+1 =>
  functional_fors_forest f key seed ht tree stack (j+1-2^h) =>
  current = functional_fors_node f key seed ht tree h (j %/ (2^h)) =>
  node (f (seed ++ address 0 ht 3 tree 0 (h+1) (j %/ (2^(h+1))) ++
    pad (head ([],0) stack).`1 ++ pad current)) =
      functional_fors_node f key seed ht tree (h+1) (j %/ (2^(h+1))) /\
  functional_fors_forest f key seed ht tree (behead stack) (j+1-2^(h+1)).
proof.
  move=> hf hfields hj ha hs hh hm hforest hc.
  have hb := tree_stack_bounds stack h j hj ha hm.
  have hg : tree_fields 0 ht by move: hfields; rewrite /fors_fields /tree_fields; smt(tree_u32_u64).
  have hkp : 0 <= tree < 2^32 by move: hfields; rewrite /fors_fields; smt().
  have he := tree_pair_query seed 0 ht 3 tree (h+1) (j %/ (2^(h+1)))
    (head ([],0) stack).`1 current hg _ hkp _ _; first 3 by smt(caller_u32_size).
  rewrite he interpreted_node 1:hf.
  have hv := functional_build_merge (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) stack (j+1) h current
    _ _ ha hs hh hm _ _; try by rewrite ?stack_pow2_11; smt().
qed.

lemma fixed_fors_catalog_values f key0 seed0 ht0 tree0 :
  hoare[ForsCatalogObserver(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    functional_fors_catalog f key0 seed0 ht0 tree0 res.`3 /\
    functional_fors_forest f key0 seed0 ht0 tree0 res.`1 2048 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = j /\
    functional_fors_forest f key0 seed0 ht0 tree0 stack j /\
    functional_fors_catalog f key0 seed0 ht0 tree0 catalog).
  + wp; while (seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
      FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = j+1 /\
      functional_fors_forest f key0 seed0 ht0 tree0 stack (j+1-2^height) /\
      current = functional_fors_node f key0 seed0 ht0 tree0 height (j %/ (2^height)) /\
      functional_fors_catalog f key0 seed0 ht0 tree0 catalog).
    - exists* stack, current, height, j; elim* => st0 cur0 h0 j0.
      wp; call (fixed_builder_hash_value f
        (seed0 ++ address 0 ht0 3 tree0 0 (h0+1) (j0 %/ (2^(h0+1))) ++
          pad (head ([],0) st0).`1 ++ pad cur0)).
      auto; move=> &hr hi.
      have hp := projected_carry_pop st0 [] h0.
      have hv := functional_fors_pair_build f key0 seed0 ht0 tree0 st0 j0 h0 cur0.
      smt(functional_fors_catalog_set).
    wp; exists* j; elim* => j0.
    call (fixed_builder_hash_value f (seed0 ++ address 0 ht0 3 tree0 0 0 j0 ++
      pad (fors_secret_value (interpreted_backend f) key0 ht0 tree0 j0))).
    wp; call (fixed_builder_fors_secret_value f key0 ht0 tree0 j0).
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
    - rewrite divz1; smt(carry_initial functional_fors_catalog_set).
    move=> history1 cat current h st hx hin.
    have hpush := hp st h current (j{hr}+1) _ _ _ _ _; first 5 by smt().
    move: hpush; rewrite /=; smt().
  auto; rewrite /functional_fors_forest /functional_build_forest /functional_fors_catalog;
    smt(functional_build_catalog_empty).
qed.

lemma fixed_fors_catalog_root f key0 seed0 ht0 tree0 :
  hoare[ForsCatalogObserver(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`1).`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    functional_fors_catalog f key0 seed0 ht0 tree0 res.`3 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_catalog_complete (PreparationView(FixedPrefix)))
    (fixed_fors_catalog_values f key0 seed0 ht0 tree0); smt(functional_fors_forest_root).
qed.

lemma fixed_fors_catalog_valid f key0 seed0 ht0 tree0 target0 :
  hoare[ForsCatalogObserver(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2048 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`1).`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fixed_fors_catalog_root f key0 seed0 ht0 tree0)
    (fors_catalog_auth (PreparationView(FixedPrefix)) target0); smt(functional_fors_catalog_path).
qed.

lemma fixed_fors_witness_root f key0 seed0 ht0 tree0 target0 :
  hoare[ForsBuildWitness(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`1).`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_fors_catalog_root f key0 seed0 ht0 tree0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_fors_raw_tree_root f key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_tree_witness_projection (PreparationView(FixedPrefix)))
    (fixed_fors_witness_root f key0 seed0 ht0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_fors_witness_valid f key0 seed0 ht0 tree0 target0 :
  hoare[ForsBuildWitness(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2048 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    (head (nseq 16 0,0) res.`1).`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_catalog_projection (PreparationView(FixedPrefix)))
    (fixed_fors_catalog_valid f key0 seed0 ht0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma fixed_fors_raw_tree_valid f key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2048 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  conseq (fors_tree_witness_projection (PreparationView(FixedPrefix)))
    (fixed_fors_witness_valid f key0 seed0 ht0 tree0 target0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},ht{m},tree{m},target{m}); smt().
  smt().
qed.

lemma functional_fors_auth_outside f key seed ht tree target : 2048 <= target =>
  fors_auth_values f seed key ht tree target = nseq 11 (nseq 16 0).
proof.
  move=> ho; rewrite /fors_auth_values.
  apply (functional_auth_outside f seed 0 ht 3 tree 11 (fors_tree_leaves f seed key ht tree) target);
    rewrite ?stack_pow2_11 /fors_tree_leaves ?size_mkseq; smt().
qed.

lemma fixed_fors_raw_tree f key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  case (target0 < 2048) => ht.
  + conseq (fixed_fors_raw_tree_valid f key0 seed0 ht0 tree0 target0); smt().
  conseq (fixed_fors_raw_tree_root f key0 seed0 ht0 tree0 target0)
    (functional_fors_outside (PreparationView(FixedPrefix)) target0);
    smt(functional_fors_auth_outside).
qed.

lemma fixed_fors_raw_root f key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).root :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof. proc; call (fixed_fors_raw_tree_root f key0 seed0 ht0 tree0 0); auto. qed.

lemma fixed_fors_raw_sign f key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\
    fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f ==>
    res = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; call (fixed_fors_raw_tree f key0 seed0 ht0 tree0 target0); wp.
  call (fixed_builder_fors_secret_value f key0 ht0 tree0 target0).
  auto; rewrite /fors_sign_values; smt().
qed.
