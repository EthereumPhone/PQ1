require import AllCore List IntDiv StdOrder C10Representation C10RawOracle DyadicStack StackProjection StackAlignment CatalogStack NodeGridIndex FMap KeygenPrefixes RawKeygen RawFors C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue NodeCatalog C10TreeCallerBridge C10FunctionalForsRecovery AuthSlots AuthPhase AuthCaptureSchedule RawMerkle StackPowers AuthCaptureIndex RawKeygenCost C10CallerInputBridge ForsCatalogObserver ForsCatalogAuth ForsBuildWitness C10PrivateCallerBridge C10FunctionalWotsKeygen MerkleCatalogObserver MerkleBuildWitness MerkleCatalogAuth NodeCatalogDomain.

op tree_level_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (height : int) (nodes : ((int list) list)) : ((int list) list) =
  (mkseq (fun i => (tree_pair_value hash_fn seed (address_words layer tree kind kp 0 (height) (i)) (nth (nseq 16 0) nodes (2 * i)) (nth (nseq 16 0) nodes (2 * i)))) (2 ^ (max 0 (total_height - height)))).

op tree_nodes_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (rounds : int) (values : ((int list) list)) : ((int list) list) =
  (foldr (fun i nodes => (tree_level_value hash_fn seed layer tree kind kp total_height (i + 1) nodes)) values (rev (mkseq (fun i => i) rounds))).

op tree_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (values : ((int list) list)) : (int list) =
  (nth (nseq 16 0) (tree_nodes_value hash_fn seed layer tree kind kp total_height total_height values) 0).

op tree_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (values : ((int list) list)) (index0 : int) : ((int list) list) =
  (mkseq (fun height => (nth (nseq 16 0) (tree_nodes_value hash_fn seed layer tree kind kp total_height height values) (max 0 (if ((index0 %/ (2 ^ height)) %% 2) = 0 then ((index0 %/ (2 ^ height)) + 1) else ((index0 %/ (2 ^ height)) - 1))))) total_height).

op fors_tree_leaves (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) : ((int list) list) =
  (mkseq (fun i => (fors_leaf_value hash_fn seed ht tree (i) (fors_secret_value hash_fn secret ht tree (i)))) 2048).

op fors_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) : (int list) =
  (tree_root_value hash_fn seed 0 ht 3 tree 11 (fors_tree_leaves hash_fn seed secret ht tree)).

op fors_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : ((int list) list) =
  (tree_auth_values hash_fn seed 0 ht 3 tree 11 (fors_tree_leaves hash_fn seed secret ht tree) leaf).

op fors_sign_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : ((int list) * ((int list) list)) =
  ((fors_secret_value hash_fn secret ht tree leaf), (fors_auth_values hash_fn seed secret ht tree leaf)).

op merkle_tree_leaves (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) : ((int list) list) =
  (mkseq (fun i => (wots_keygen_value hash_fn seed secret layer tree (i))) 512).

op merkle_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) : (int list) =
  (tree_root_value hash_fn seed layer tree 2 0 9 (merkle_tree_leaves hash_fn seed secret layer tree)).

op merkle_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (index0 : int) : ((int list) list) =
  (tree_auth_values hash_fn seed layer tree 2 0 9 (merkle_tree_leaves hash_fn seed secret layer tree) index0).

op merkle_build_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (index0 : int) : (((int list) list) * (int list)) =
  ((merkle_auth_values hash_fn seed secret layer tree index0), (merkle_root_value hash_fn seed secret layer tree)).

(* Shared construction recurrences; these do not specify oracle scheduling. *)


import IntOrder.

lemma functional_build_fold f seed layer tree kind kp total leaves n :
  tree_nodes_value f seed layer tree kind kp total n leaves =
    foldl (fun nodes i => tree_level_value f seed layer tree kind kp total (i+1) nodes)
      leaves (mkseq (fun i => i) n).
proof. by rewrite /tree_nodes_value -foldl_rev revK. qed.

lemma functional_build_zero f seed layer tree kind kp total leaves :
  tree_nodes_value f seed layer tree kind kp total 0 leaves = leaves.
proof. by rewrite functional_build_fold mkseq0. qed.

lemma functional_build_next f seed layer tree kind kp total leaves n : 0 <= n =>
  tree_nodes_value f seed layer tree kind kp total (n+1) leaves =
    tree_level_value f seed layer tree kind kp total (n+1)
      (tree_nodes_value f seed layer tree kind kp total n leaves).
proof. by move=> hn; rewrite !functional_build_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_level_size f seed layer tree kind kp total height nodes :
  size (tree_level_value f seed layer tree kind kp total height nodes) =
    2^(max 0 (total-height)).
proof.
  rewrite /tree_level_value size_mkseq.
  have hp : 0 < 2^(max 0 (total-height)) by apply expr_gt0.
  smt().
qed.

lemma functional_build_size f seed layer tree kind kp total leaves n :
  0 <= total => 0 <= n => size leaves = 2^total =>
  size (tree_nodes_value f seed layer tree kind kp total n leaves) =
    2^(max 0 (total-n)).
proof.
  move=> ht hn hl; case (n=0) => hz.
  + by rewrite hz functional_build_zero hl; congr; smt().
  have hs : n=(n-1)+1 by ring.
  by rewrite hs functional_build_next 1:/# functional_level_size; congr; ring.
qed.

lemma functional_auth_size f seed layer tree kind kp total leaves target : 0 <= total =>
  size (tree_auth_values f seed layer tree kind kp total leaves target) = total.
proof. by move=> ht; rewrite /tree_auth_values size_mkseq; smt(). qed.

lemma functional_level_nth f seed layer tree kind kp total height nodes i :
  0 <= i < 2^(max 0 (total-height)) =>
  nth (nseq 16 0) (tree_level_value f seed layer tree kind kp total height nodes) i =
    tree_pair_value f seed (address_words layer tree kind kp 0 height i)
      (nth (nseq 16 0) nodes (2*i)) (nth (nseq 16 0) nodes (2*i+1)).
proof. by move=> hi; rewrite /tree_level_value nth_mkseq 1:hi. qed.

lemma functional_root_value f seed layer tree kind kp total leaves :
  tree_root_value f seed layer tree kind kp total leaves =
    nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total total leaves) 0.
proof. by rewrite /tree_root_value. qed.

lemma functional_sibling_outside q b :
  b %% 2 = 0 => b <= q => b <= (if q %% 2 = 0 then q+1 else q-1).
proof. smt(). qed.

lemma functional_sibling_inside q b :
  b %% 2 = 0 => 0 <= q < b =>
  0 <= (if q %% 2 = 0 then q+1 else q-1) < b.
proof.
  have := modz_ge0 q 2; have := ltz_pmod q 2.
  have := modz_ge0 b 2; have := ltz_pmod b 2.
  have := divz_eq q 2; have := divz_eq b 2; smt().
qed.

lemma functional_power_even n : 0 < n => (2^n) %% 2 = 0.
proof. by move=> hn; rewrite (_ : n=(n-1)+1) 1:/# exprS 1:/# modzMr. qed.

lemma functional_auth_nth f seed layer tree kind kp total leaves target h :
  0 <= h < total =>
  nth (nseq 16 0) (tree_auth_values f seed layer tree kind kp total leaves target) h =
    nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total h leaves)
      (max 0 (if (target %/ (2^h)) %% 2 = 0 then target %/ (2^h)+1
              else target %/ (2^h)-1)).
proof. by move=> hh; rewrite /tree_auth_values nth_mkseq 1:hh. qed.

lemma functional_auth_outside_nth f seed layer tree kind kp total leaves target h :
  0 <= h < total => size leaves = 2^total => 2^total <= target =>
  nth (nseq 16 0) (tree_auth_values f seed layer tree kind kp total leaves target) h =
    nseq 16 0.
proof.
  move=> hh hl ht.
  have hp : 0 < 2^h by apply expr_gt0.
  have he : 2^(total-h)*2^h = 2^total by rewrite -exprD_nneg 1,2:/#; congr; ring.
  have hq : 2^(total-h) <= target %/ (2^h) by rewrite lez_divRL 1:hp he.
  have hb := functional_power_even (total-h) _; first by smt().
  have hs := functional_sibling_outside (target %/ (2^h)) (2^(total-h)) hb hq.
  rewrite functional_auth_nth 1:hh nth_out; first last.
  + done.
  rewrite functional_build_size 1,2:/# 1:hl; smt().
qed.

lemma functional_auth_outside f seed layer tree kind kp total leaves target :
  0 <= total => size leaves = 2^total => 2^total <= target =>
  tree_auth_values f seed layer tree kind kp total leaves target = nseq total (nseq 16 0).
proof.
  move=> hh hl ht; apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_auth_size 1:hh size_nseq; smt().
  move=> h; rewrite functional_auth_size 1:hh => hi.
  have hv := functional_auth_outside_nth f seed layer tree kind kp total leaves target h hi hl ht.
  by rewrite hv nth_nseq; smt().
qed.

(* Shared node values attached to each live interval of the actual tree stack. *)



import IntOrder.

op functional_build_node f seed layer tree kind kp total leaves height index =
  nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total height leaves) index.

op functional_build_forest f seed layer tree kind kp total leaves (stack : (raw_input*int) list) n =
  with stack = [] => n = 0
  with stack = entry :: rest =>
    0 <= entry.`2 /\ 2^(entry.`2) %| n /\
    entry.`1 = functional_build_node f seed layer tree kind kp total leaves
      entry.`2 ((n-1) %/ (2^(entry.`2))) /\
    functional_build_forest f seed layer tree kind kp total leaves rest (n-2^(entry.`2)).

lemma functional_build_node_zero f seed layer tree kind kp total leaves i :
  functional_build_node f seed layer tree kind kp total leaves 0 i = nth (nseq 16 0) leaves i.
proof. by rewrite /functional_build_node functional_build_zero. qed.

lemma functional_build_node_next f seed layer tree kind kp total leaves h i :
  0 <= h < total => 0 <= i < 2^(total-(h+1)) =>
  functional_build_node f seed layer tree kind kp total leaves (h+1) i =
    tree_pair_value f seed (address_words layer tree kind kp 0 (h+1) i)
      (functional_build_node f seed layer tree kind kp total leaves h (2*i))
      (functional_build_node f seed layer tree kind kp total leaves h (2*i+1)).
proof.
  move=> hh hi; rewrite /functional_build_node functional_build_next 1:/#.
  by rewrite functional_level_nth 1:/#.
qed.

lemma functional_build_forest_push f seed layer tree kind kp total leaves stack n current h :
  0 <= h => 2^h %| n =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  functional_build_forest f seed layer tree kind kp total leaves ((current,h)::stack) n.
proof. by rewrite /=. qed.

lemma functional_build_forest_pop f seed layer tree kind kp total leaves stack n h :
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  stack <> [] => (head ([],0) stack).`2 = h =>
  0 <= h /\
  (head ([],0) stack).`1 = functional_build_node f seed layer tree kind kp total leaves
    h ((n-2^h-1) %/ (2^h)) /\
  functional_build_forest f seed layer tree kind kp total leaves (behead stack) (n-2^(h+1)).
proof.
  case stack => //= entry rest.
  move=> [#] hh hd hv hr he.
  have hp : 2^(h+1) = 2*2^h by rewrite exprS 1:/#; ring.
  smt().
qed.

lemma functional_build_forest_root f seed layer tree kind kp total leaves stack :
  0 <= total => map snd stack = [total] =>
  functional_build_forest f seed layer tree kind kp total leaves stack (2^total) =>
  (head (nseq 16 0,0) stack).`1 = tree_root_value f seed layer tree kind kp total leaves.
proof.
  case stack => //= entry rest; case rest => [|next tail] //=.
  move=> hh he hf.
  have hp := pow2_pos total hh.
  have hi : (2^total-1) %/ (2^total) = 0 by apply pdiv_small; smt().
  rewrite /tree_root_value /functional_build_node; smt().
qed.

lemma functional_build_pair_children f seed layer tree kind kp total leaves stack n h current :
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = n =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  (head ([],0) stack).`1 = functional_build_node f seed layer tree kind kp total leaves
    h (2*((n-1) %/ (2^(h+1)))) /\
  current = functional_build_node f seed layer tree kind kp total leaves
    h (2*((n-1) %/ (2^(h+1)))+1).
proof.
  move=> ha hs hh hm hf hc.
  have [ha' hm'] := projected_carry_pop stack [] h ha hs hh.
  have hd := active_stack_alignment (map snd (behead stack)) (h+1) n ha' _; first by smt().
  have [hz [hl hr]] := functional_build_forest_pop f seed layer tree kind kp total leaves stack n h hf hs hh.
  have hi := aligned_pair_indices n h hz hd.
  smt().
qed.

lemma functional_build_merge f seed layer tree kind kp total leaves stack n h current :
  0 <= total => 0 < n <= 2^total =>
  active_stack (map snd stack) h => stack <> [] => (head ([],0) stack).`2 = h =>
  stack_mass (map snd stack)+2^h = n =>
  functional_build_forest f seed layer tree kind kp total leaves stack (n-2^h) =>
  current = functional_build_node f seed layer tree kind kp total leaves h ((n-1) %/ (2^h)) =>
  tree_pair_value f seed (address_words layer tree kind kp 0 (h+1) ((n-1) %/ (2^(h+1))))
    (head ([],0) stack).`1 current =
      functional_build_node f seed layer tree kind kp total leaves (h+1) ((n-1) %/ (2^(h+1))) /\
  functional_build_forest f seed layer tree kind kp total leaves (behead stack) (n-2^(h+1)).
proof.
  move=> ht hn ha hs hh hm hf hc.
  have hb := projected_carry_height_bound stack [] h n total ht ha hs hh hm _; first by smt().
  have [ha' hm'] := projected_carry_pop stack [] h ha hs hh.
  have hd := active_stack_alignment (map snd (behead stack)) (h+1) n ha' _; first by smt().
  have [hz [hl hr]] := functional_build_forest_pop f seed layer tree kind kp total leaves stack n h hf hs hh.
  have hi := aligned_pair_indices n h hz hd.
  have hp := dyadic_index_range (n-1) (h+1) total _ _; first 2 by smt().
  split; last exact hr.
  rewrite functional_build_node_next 1:hb 1:hp hl hc; smt().
qed.

(* Fixed-backend value contracts retain arbitrary consistent prior history. *)







lemma fixed_builder_hash_value f x0 :
  hoare[FixedBackend.hash : x = x0 /\ FixedBackend.fn = f /\
    backend_consistent FixedBackend.history f ==>
    res = f x0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f].
proof.
  proc; sp 1; if; auto => />; rewrite /backend_consistent;
    smt(get_setE get_set_sameE domE).
qed.

lemma fixed_builder_derive_value f key0 tail0 :
  hoare[FixedPrefix.derive : tail = tail0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    backend_consistent FixedBackend.history f ==>
    res = f (key0 ++ tail0) /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    backend_consistent FixedBackend.history f].
proof. proc; call (fixed_builder_hash_value f (key0 ++ tail0)); auto. qed.

lemma fixed_builder_fors_secret_value f key0 ht0 tree0 i0 :
  hoare[PreparationView(FixedPrefix).fors : tail = fors_tail ht0 tree0 i0 /\
    fors_fields ht0 tree0 /\ 0 <= i0 < 2^32 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    backend_consistent FixedBackend.history f ==>
    node res = fors_secret_value (interpreted_backend f) key0 ht0 tree0 i0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    backend_consistent FixedBackend.history f].
proof.
  proc; call (fixed_builder_derive_value f key0 (fors_tag ++ fors_tail ht0 tree0 i0)); auto.
  move=> &m [ha [hf [hi [hw [hk [hfn hc]]]]]].
  have he := tree_fors_private_query ht0 tree0 i0 hf hi.
  rewrite he functional_fors_private_prefix; smt(functional_fors_private).
qed.

op functional_build_catalog f seed layer tree kind kp total leaves (catalog : node_catalog) =
  forall height index value, catalog.[(height,index)] = Some value =>
    value = functional_build_node f seed layer tree kind kp total leaves height index.

lemma functional_build_catalog_empty f seed layer tree kind kp total leaves :
  functional_build_catalog f seed layer tree kind kp total leaves empty.
proof. rewrite /functional_build_catalog; smt(emptyE). qed.

lemma functional_build_catalog_set f seed layer tree kind kp total leaves catalog height index value :
  functional_build_catalog f seed layer tree kind kp total leaves catalog =>
  value = functional_build_node f seed layer tree kind kp total leaves height index =>
  functional_build_catalog f seed layer tree kind kp total leaves catalog.[(height,index) <- value].
proof. rewrite /functional_build_catalog; smt(get_setE). qed.

lemma functional_build_catalog_get f seed layer tree kind kp total leaves catalog height index :
  functional_build_catalog f seed layer tree kind kp total leaves catalog =>
  (height,index) \in catalog =>
  catalog_grid catalog height index = functional_build_node f seed layer tree kind kp total leaves height index.
proof. rewrite /functional_build_catalog /catalog_grid; smt(domE). qed.

lemma functional_fors_build_leaf f key seed ht tree i : 0 <= i < 2048 =>
  functional_build_node (interpreted_backend f) seed 0 ht 3 tree 11
    (fors_tree_leaves (interpreted_backend f) seed key ht tree) 0 i =
    fors_leaf_value (interpreted_backend f) seed ht tree i
      (fors_secret_value (interpreted_backend f) key ht tree i).
proof. by move=> hi; rewrite functional_build_node_zero /fors_tree_leaves nth_mkseq 1:hi. qed.

lemma functional_build_catalog_auth f seed layer tree kind kp total leaves catalog auth target :
  0 <= total => 0 <= target < 2^total =>
  functional_build_catalog f seed layer tree kind kp total leaves catalog =>
  slots_saved catalog auth target total (captured_full (2^total) target) =>
  auth = tree_auth_values f seed layer tree kind kp total leaves target.
proof.
  move=> ht hi hc hslots.
  move: hslots; rewrite /slots_saved.
  move=> [hs ha].
  apply (eq_from_nth []).
  + by rewrite hs /tree_auth_values size_mkseq; smt().
  move=> h; rewrite hs => hh.
  have hr := pair_capture_final total target h hh hi.
  have he := ha h hh _; first by rewrite /captured_full.
  have hv : nth [] auth h = functional_build_node f seed layer tree kind kp total leaves
      h (sibling_index (target %/ (2^h))) by move: hc; rewrite /functional_build_catalog; smt().
  have hq : 0 <= target %/ (2^h) by rewrite divz_ge0; smt(pow2_pos).
  have hb : 0 <= sibling_index (target %/ (2^h)) by rewrite /sibling_index; smt().
  rewrite /tree_auth_values nth_mkseq 1:hh hv /functional_build_node /sibling_index.
  rewrite /=; congr; move: hb; rewrite /sibling_index; smt().
qed.

(* Actual native builders preserve zero authentication slots outside their tree. *)



import IntOrder.

lemma functional_outside_parent inside outside h total :
  0 <= h <= total => 0 <= inside < 2^total => 2^total <= outside =>
  inside %/ (2^h) <> outside %/ (2^h).
proof.
  move=> hh hi ho.
  have hr := dyadic_index_range inside h total hh hi.
  have hp := pow2_pos h _; first by smt().
  have he : 2^(total-h)*2^h = 2^total by rewrite -exprD_nneg 1,2:/#; congr; ring.
  have hq : 2^(total-h) <= outside %/ (2^h) by rewrite lez_divRL 1:hp he.
  smt().
qed.

lemma functional_fors_outside (O <: PreparationOracle) target0 :
  hoare[RawFors(O).tree : target = target0 /\ 2048 <= target0 ==>
    res.`2 = nseq 11 (nseq 16 0)].
proof.
  proc; while (target = target0 /\ 2048 <= target0 /\ auth = nseq 11 (nseq 16 0) /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = j).
  + wp; while (target = target0 /\ 2048 <= target0 /\ auth = nseq 11 (nseq 16 0) /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = j+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &m hi.
      have hb := projected_carry_height_bound stack{m} [] height{m} (j{m}+1) 11.
      have hd : j{m} %/ (2^(height{m}+1)) <> target0 %/ (2^(height{m}+1)).
      + apply (functional_outside_parent j{m} target0 (height{m}+1) 11); smt(stack_pow2_11).
      have hc := fors_capture_parent j{m} target0 height{m}.
      have hp := projected_carry_pop stack{m} [] height{m}.
      smt(stack_pow2_11).
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &m hi; split; first by smt(carry_initial).
    move=> auth0 h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have he : st = [] \/ (head ([],0) st).`2 <> h by smt().
    have hp := projected_carry_push st [] [] h ha he.
    move: hp; rewrite /=; smt().
  auto; smt().
qed.

lemma functional_merkle_outside (O <: PreparationOracle) target0 :
  hoare[RawMerkle(O).build : target = target0 /\ 512 <= target0 ==>
    res.`1 = nseq 9 (nseq 16 0)].
proof.
  proc; while (target = target0 /\ 512 <= target0 /\ keep = nseq 9 (nseq 16 0) /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = kp).
  + wp; while (target = target0 /\ 512 <= target0 /\ keep = nseq 9 (nseq 16 0) /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = kp+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &m hi.
      have hb := projected_carry_height_bound stack{m} [] height{m} (kp{m}+1) 9.
      have hd : kp{m} %/ (2^(height{m}+1)) <> target0 %/ (2^(height{m}+1)).
      + apply (functional_outside_parent kp{m} target0 (height{m}+1) 9); smt(stack_pow2_9).
      have hc := merkle_capture_parent kp{m} target0 height{m}.
      have hp := projected_carry_pop stack{m} [] height{m}.
      smt(stack_pow2_9).
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &m hi; split; first by smt(carry_initial).
    move=> h keep0 st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have he : st = [] \/ (head ([],0) st).`2 <> h by smt().
    have hp := projected_carry_push st [] [] h ha he.
    move: hp; rewrite /=; smt().
  auto; smt().
qed.

(* Exact calls and termination of the actual fixed-backend builders.
   These properties hold for arbitrary prior history; value consistency is
   separately required by the functional correspondence contracts. *)




lemma fixed_builder_hash_count c :
  hoare[PreparationView(FixedPrefix).hash : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_wots_count c :
  hoare[PreparationView(FixedPrefix).wots : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedPrefix.derive FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_fors_count c :
  hoare[PreparationView(FixedPrefix).fors : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedPrefix.derive FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_leaf_count c :
  hoare[RawKeygen(PreparationView(FixedPrefix)).leaf : FixedBackend.calls = c ==>
    FixedBackend.calls = c+345].
proof.
  proc; call (fixed_builder_hash_count (c+344)); wp.
  while (0 <= i <= 43 /\ FixedBackend.calls = c+8*i).
  + wp; while (0 <= j <= 7 /\ FixedBackend.calls = c+8*i+1+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (fixed_builder_hash_count (c+8*i0+1+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (fixed_builder_wots_count (c+8*i0)); auto; smt().
  auto; smt().
qed.

lemma fixed_builder_fors_tree_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).tree : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6143].
proof.
  proc; while (0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ FixedBackend.calls = c+3*j-size stack).
  + wp; while (0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      FixedBackend.calls = c+3*j+2-size stack).
    - exists* j, stack; elim* => j0 st0; wp.
      call (fixed_builder_hash_count (c+3*j0+2-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* j, stack; elim* => j0 st0.
    call (fixed_builder_hash_count (c+3*j0+1-size st0)); wp.
    call (fixed_builder_fors_count (c+3*j0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by ring.
    move=> hc; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls j st hx hin.
  have hs : map snd st = [11] by smt(stack_power_singleton stack_pow2_11).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_fors_root_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).root : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6143].
proof. proc; call (fixed_builder_fors_tree_count c); auto. qed.

lemma fixed_builder_fors_sign_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).sign : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6144].
proof.
  proc; call (fixed_builder_fors_tree_count (c+1)); wp.
  call (fixed_builder_fors_count c); auto; smt().
qed.

lemma fixed_builder_merkle_root_count c :
  hoare[RawKeygen(PreparationView(FixedPrefix)).root : FixedBackend.calls = c ==>
    FixedBackend.calls = c+177151].
proof.
  proc; while (0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ FixedBackend.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      FixedBackend.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0; wp.
      call (fixed_builder_hash_count (c+346*kp0+345-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (fixed_builder_leaf_count (c+346*kp0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls kp st hx hin.
  have hs : map snd st = [9] by smt(stack_power_singleton stack_pow2_9).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_merkle_build_count c :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build : FixedBackend.calls = c ==>
    FixedBackend.calls = c+177151].
proof.
  proc; while (0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ FixedBackend.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      FixedBackend.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0; wp.
      call (fixed_builder_hash_count (c+346*kp0+345-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (fixed_builder_leaf_count (c+346*kp0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls kp st hx hin.
  have hs : map snd st = [9] by smt(stack_power_singleton stack_pow2_9).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_wots_ll : islossless PreparationView(FixedPrefix).wots.
proof. proc; call fixed_derive_ll; auto. qed.

lemma fixed_builder_fors_ll : islossless PreparationView(FixedPrefix).fors.
proof. proc; call fixed_derive_ll; auto. qed.

lemma fixed_builder_fors_tree_ll : islossless RawFors(PreparationView(FixedPrefix)).tree.
proof. exact (fors_tree_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_fors_ll). qed.

lemma fixed_builder_fors_root_ll : islossless RawFors(PreparationView(FixedPrefix)).root.
proof. proc; call fixed_builder_fors_tree_ll; auto. qed.

lemma fixed_builder_fors_sign_ll : islossless RawFors(PreparationView(FixedPrefix)).sign.
proof. proc; call fixed_builder_fors_tree_ll; wp; call fixed_builder_fors_ll; auto. qed.

lemma fixed_builder_merkle_root_ll : islossless RawKeygen(PreparationView(FixedPrefix)).root.
proof. exact (root_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_wots_ll). qed.

lemma fixed_builder_merkle_build_ll : islossless RawMerkle(PreparationView(FixedPrefix)).build.
proof. exact (merkle_build_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_wots_ll). qed.

(* Functional values of the actual FORS stack and its proof-only catalog. *)








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

(* Functional values of the actual XMSS builders under the fixed backend. *)









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

(* Exact history maps for tree construction. Query membership describes every
   new mapping, including repeated/preexisting inputs; it does not claim a
   chronology for the map. Actual call counts and Raw/CommonInput execution
   equivalence are separate contracts. *)



op functional_history_exact (f : raw_input -> digest) (initial history : (raw_input,digest) fmap)
  (queried : raw_input -> bool) =
  forall x, history.[x] = if queried x then Some (f x) else initial.[x].

op functional_catalog_queried (queries : int -> int -> raw_input list) (catalog : node_catalog) x =
  exists height index, (height,index) \in catalog /\ x \in queries height index.

op functional_catalog_history f initial history queries catalog =
  functional_history_exact f initial history (functional_catalog_queried queries catalog).

op functional_tree_queried (queries : int -> int -> raw_input list) total x =
  exists height index, node_due (2^total) height index /\ x \in queries height index.

lemma functional_history_empty f initial :
  functional_history_exact f initial initial (fun _ => false).
proof. by rewrite /functional_history_exact. qed.

lemma functional_history_consistent f initial history queried :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  backend_consistent history f.
proof. rewrite /backend_consistent /functional_history_exact; smt(). qed.

lemma functional_history_remember f initial history queried q :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  functional_history_exact f initial (remember history q (f q)) (fun x => queried x \/ x = q).
proof.
  rewrite /functional_history_exact /backend_consistent /remember;
    smt(get_setE domE).
qed.

lemma functional_history_queries f initial history queried qs :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  functional_history_exact f initial (backend_history f history qs) (fun x => queried x \/ x \in qs).
proof.
  elim qs history queried => [history queried|q qs ih history queried].
  + by rewrite backend_history_nil /functional_history_exact /=.
  move=> hc he.
  have hs := functional_history_remember f initial history queried q hc he.
  have ht := ih (remember history q (f q)) (fun x => queried x \/ x = q) hc hs.
  move: ht; rewrite /backend_history /= /functional_history_exact; smt().
qed.

lemma functional_catalog_queried_set queries catalog height index value x :
  functional_catalog_queried queries catalog.[(height,index) <- value] x <=>
    functional_catalog_queried queries catalog x \/ x \in queries height index.
proof. rewrite /functional_catalog_queried; smt(mem_set). qed.

lemma functional_catalog_history_empty f initial queries :
  functional_catalog_history f initial initial queries empty.
proof.
  rewrite /functional_catalog_history /functional_history_exact /functional_catalog_queried;
    smt(mem_empty).
qed.

lemma functional_catalog_history_set f initial history queries catalog height index value :
  backend_consistent initial f => functional_catalog_history f initial history queries catalog =>
  functional_catalog_history f initial (backend_history f history (queries height index))
    queries catalog.[(height,index) <- value].
proof.
  move=> hc he; rewrite /functional_catalog_history.
  have hs := functional_history_queries f initial history (functional_catalog_queried queries catalog)
    (queries height index) hc he.
  move: hs; rewrite /functional_history_exact; smt(functional_catalog_queried_set).
qed.

lemma functional_catalog_history_complete f initial history queries catalog total :
  catalog_exact catalog (2^total) => functional_catalog_history f initial history queries catalog =>
  functional_history_exact f initial history (functional_tree_queried queries total).
proof.
  rewrite /catalog_exact /functional_catalog_history /functional_history_exact
    /functional_catalog_queried /functional_tree_queried; smt().
qed.

lemma functional_history_preserves f initial history queried x :
  backend_consistent initial f => functional_history_exact f initial history queried =>
  x \in initial => history.[x] = initial.[x].
proof. rewrite /backend_consistent /functional_history_exact; smt(domE). qed.

lemma fixed_builder_hash_history f history0 x0 :
  hoare[FixedBackend.hash : x = x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = f x0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember history0 x0 (f x0) /\
    backend_consistent FixedBackend.history f].
proof.
  exists* FixedBackend.calls; elim* => c.
  conseq (fixed_hash f history0 x0 c); smt().
qed.

lemma fixed_builder_derive_history f history0 key0 tail0 :
  hoare[FixedPrefix.derive : tail = tail0 /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = history0 /\ backend_consistent history0 f ==>
    res = f (key0 ++ tail0) /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember history0 (key0 ++ tail0) (f (key0 ++ tail0)) /\
    backend_consistent FixedBackend.history f].
proof. proc; call (fixed_builder_hash_history f history0 (key0 ++ tail0)); auto. qed.

(* Exact fixed-backend history of FORS construction, from actual catalog execution. *)







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

(* Exact fixed-backend history of XMSS construction, from actual catalog execution. *)







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

(* Combined contracts on actual callers: values, exact history maps, frames and calls. *)








lemma fixed_fors_build_effects f initial c key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  conseq (fixed_fors_raw_tree_history f initial key0 seed0 ht0 tree0)
    (fixed_builder_fors_tree_count c); smt().
qed.

lemma fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).tree :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  conseq (fixed_fors_raw_tree f key0 seed0 ht0 tree0 target0)
    (fixed_fors_build_effects f initial c key0 seed0 ht0 tree0); smt().
qed.

lemma fixed_functional_fors_root f initial c key0 seed0 ht0 tree0 :
  hoare[RawFors(PreparationView(FixedPrefix)).root :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6143].
proof.
  proc; call (fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 0); auto; smt().
qed.

lemma fixed_merkle_build_effects f initial c key0 seed0 layer0 tree0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq (fixed_merkle_raw_build_history f initial key0 seed0 layer0 tree0)
    (fixed_builder_merkle_build_count c); smt().
qed.

lemma fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0 :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq (fixed_merkle_raw_build f key0 seed0 layer0 tree0 target0)
    (fixed_merkle_build_effects f initial c key0 seed0 layer0 tree0); rewrite /merkle_build_value; smt().
qed.

lemma fixed_functional_merkle_root f initial c key0 seed0 layer0 tree0 :
  hoare[RawKeygen(PreparationView(FixedPrefix)).root :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    functional_history_exact f initial FixedBackend.history
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+177151].
proof.
  conseq (functional_merkle_root_build_projection (PreparationView(FixedPrefix)))
    (fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 0).
  + move=> &m hm; exists FixedBackend.calls{m} FixedBackend.fn{m} FixedBackend.history{m}
      FixedPrefix.key{m} (seed{m},layer{m},tree{m},0); smt().
  rewrite /merkle_build_value; smt().
qed.

lemma fixed_builder_fors_secret_full f initial c key0 ht0 tree0 target0 :
  hoare[PreparationView(FixedPrefix).fors :
    tail = fors_tail ht0 tree0 target0 /\ fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\
    backend_width f /\ FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    node res = fors_secret_value (interpreted_backend f) key0 ht0 tree0 target0 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\
    FixedBackend.history = remember initial (fors_private_preimage key0 ht0 tree0 target0)
      (f (fors_private_preimage key0 ht0 tree0 target0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+1].
proof.
  conseq (fixed_builder_fors_secret_history f initial key0 ht0 tree0 target0)
    (fixed_builder_fors_count c); smt().
qed.

lemma fixed_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0 :
  hoare[RawFors(PreparationView(FixedPrefix)).sign :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ FixedBackend.history = initial /\
    backend_consistent initial f /\ FixedBackend.calls = c ==>
    res = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) FixedBackend.history
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key = key0 /\ FixedBackend.fn = f /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+6144].
proof.
  proc; call (fixed_functional_fors_build f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) (c+1) key0 seed0 ht0 tree0 target0); wp.
  call (fixed_builder_fors_secret_full f initial c key0 ht0 tree0 target0).
  auto; rewrite /fors_sign_values; smt().
qed.

lemma raw_functional_fors_build f initial c key0 seed0 ht0 tree0 target0 :
  equiv[RawFors(PreparationView(FixedPrefix)).tree ~ CommonInputFors(FixedPrefix).tree :
    ={seed,ht,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1}.`1 = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    res{1}.`2 = fors_auth_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6143].
proof.
  conseq (caller_fors_tree FixedPrefix)
    (fixed_functional_fors_build f initial c key0 seed0 ht0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_fors_root f initial c key0 seed0 ht0 tree0 :
  equiv[RawFors(PreparationView(FixedPrefix)).root ~ CommonInputFors(FixedPrefix).root :
    ={seed,ht,tree,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = fors_root_value (interpreted_backend f) seed0 key0 ht0 tree0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6143].
proof.
  conseq (caller_fors_root FixedPrefix)
    (fixed_functional_fors_root f initial c key0 seed0 ht0 tree0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0 :
  equiv[RawFors(PreparationView(FixedPrefix)).sign ~ CommonInputFors(FixedPrefix).sign :
    ={seed,ht,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\
    fors_fields ht0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = fors_sign_values (interpreted_backend f) seed0 key0 ht0 tree0 target0 /\
    functional_history_exact f (remember initial (fors_private_preimage key0 ht0 tree0 target0) (f (fors_private_preimage key0 ht0 tree0 target0))) FixedBackend.history{1}
      (functional_tree_queried (functional_fors_build_queries f key0 seed0 ht0 tree0) 11) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+6144].
proof.
  conseq (caller_fors_sign FixedPrefix)
    (fixed_functional_fors_sign f initial c key0 seed0 ht0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0 :
  equiv[RawMerkle(PreparationView(FixedPrefix)).build ~ CommonInputMerkle(FixedPrefix).build :
    ={seed,layer,tree,target,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    target{1} = target0 /\ 0 <= target0 < 2^32 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = merkle_build_value (interpreted_backend f) seed0 key0 layer0 tree0 target0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+177151].
proof.
  conseq (caller_merkle_build FixedPrefix)
    (fixed_functional_merkle_build f initial c key0 seed0 layer0 tree0 target0) (_ : true ==> true) => //; smt().
qed.

lemma raw_functional_merkle_root f initial c key0 seed0 layer0 tree0 :
  equiv[RawKeygen(PreparationView(FixedPrefix)).root ~ CommonInputMerkle(FixedPrefix).root :
    ={seed,layer,tree,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\
    tree_fields layer0 tree0 /\ backend_width f /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = initial /\
    backend_consistent initial f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = merkle_root_value (interpreted_backend f) seed0 key0 layer0 tree0 /\
    functional_history_exact f initial FixedBackend.history{1}
      (functional_tree_queried (functional_merkle_build_queries f key0 seed0 layer0 tree0) 9) /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+177151].
proof.
  conseq (caller_keygen_root FixedPrefix)
    (fixed_functional_merkle_root f initial c key0 seed0 layer0 tree0) (_ : true ==> true) => //; smt().
qed.

lemma common_functional_fors_tree_lossless : islossless CommonInputFors(FixedPrefix).tree.
proof.
  proc; while true (2048-j).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_hash_ll; wp; call fixed_derive_ll; auto; smt(size_ge0).
  auto; smt().
qed.

lemma common_functional_fors_root_lossless : islossless CommonInputFors(FixedPrefix).root.
proof. proc; call common_functional_fors_tree_lossless; auto. qed.

lemma common_functional_fors_sign_lossless : islossless CommonInputFors(FixedPrefix).sign.
proof. proc; call common_functional_fors_tree_lossless; wp; call fixed_derive_ll; auto. qed.

lemma common_functional_merkle_build_lossless : islossless CommonInputMerkle(FixedPrefix).build.
proof.
  proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_functional_keygen_lossless; auto; smt(size_ge0).
  auto; smt().
qed.

lemma common_functional_merkle_root_lossless : islossless CommonInputMerkle(FixedPrefix).root.
proof.
  proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call fixed_hash_ll; auto; smt(size_behead size_ge0 size_eq0).
    wp; call fixed_functional_keygen_lossless; auto; smt(size_ge0).
  auto; smt().
qed.
