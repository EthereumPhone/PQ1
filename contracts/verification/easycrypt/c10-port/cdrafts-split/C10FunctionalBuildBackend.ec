(* Fixed-backend value contracts retain arbitrary consistent prior history. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors C10FixedBackend.
require import C10Representation C10FixedCallerBridge C10FunctionalWotsValue NodeCatalog.
require import C10TreeCallerBridge C10FunctionalForsRecovery.
require import C10FunctionalBuildStack.
require import AuthSlots AuthPhase AuthCaptureSchedule DyadicStack.

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
