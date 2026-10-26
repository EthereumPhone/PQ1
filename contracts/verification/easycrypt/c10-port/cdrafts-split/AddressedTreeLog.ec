(* WOTS and Merkle parent queries share one canonical suffix. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import AddressedWotsLog AddressedLeafQueries WotsCatalogOracle.
require import PersistentGrind AcceptedContexts AddressedWotsCanonicity AddressedMerkleCanonicity.

op canonical_tree_input h s seed x = canonical_wots_input h s seed x \/ canonical_merkle_input h s seed x.

lemma canonical_tree_merkle_member h s seed x :
  canonical_merkle_input h s seed x => canonical_tree_input h s seed x.
proof. rewrite /canonical_tree_input; smt(). qed.

lemma canonical_tree_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_tree_input h s seed x => canonical_tree_input h' s' seed x.
proof. rewrite /canonical_tree_input; smt(canonical_wots_input_extends canonical_merkle_input_extends). qed.

op canonical_tree_log h s seed base queries =
  exists inputs, queries=base++inputs /\ all (canonical_tree_input h s seed) inputs.

lemma canonical_tree_log_empty h s seed base : canonical_tree_log h s seed base base.
proof. rewrite /canonical_tree_log; exists []; by rewrite cats0. qed.

lemma canonical_tree_list_extends h h' s s' seed inputs :
  extends h h' => extends s s' => all (canonical_tree_input h s seed) inputs =>
  all (canonical_tree_input h' s' seed) inputs.
proof.
  move=> hh hs hall; apply/allP => x hx.
  apply (canonical_tree_input_extends h h' s s' seed x hh hs).
  by move: hall; rewrite allP; apply.
qed.

lemma canonical_tree_log_extends h h' s s' seed base queries :
  extends h h' => extends s s' => canonical_tree_log h s seed base queries =>
  canonical_tree_log h' s' seed base queries.
proof.
  move=> hh hs [inputs [hq hall]]; exists inputs.
  smt(canonical_tree_list_extends).
qed.

lemma canonical_tree_log_push h s seed base queries x :
  canonical_tree_log h s seed base queries => canonical_tree_input h s seed x =>
  canonical_tree_log h s seed base (rcons queries x).
proof.
  move=> [inputs [hq hall]] hx; exists (rcons inputs x).
  rewrite -!cats1 all_cat /=; smt(catA).
qed.

lemma canonical_tree_log_compose h s seed base middle queries :
  canonical_tree_log h s seed base middle => canonical_tree_log h s seed middle queries =>
  canonical_tree_log h s seed base queries.
proof.
  move=> [xs [hm hx]] [ys [hq hy]]; exists (xs++ys).
  rewrite all_cat; smt(catA).
qed.

lemma canonical_tree_log_push_extends h h' s s' seed base queries x :
  extends h h' => extends s s' =>
  canonical_tree_log h s seed base queries => canonical_tree_input h s seed x =>
  canonical_tree_log h' s' seed base (rcons queries x).
proof.
  move=> hh hs hl hx.
  exact (canonical_tree_log_extends h h' s s' seed base (rcons queries x) hh hs
    (canonical_tree_log_push h s seed base queries x hl hx)).
qed.

lemma hash_keeps_canonical_tree_log seed base queries :
  hoare [Independent.hash :
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base queries].
proof.
  proc; sp 1; if; auto; smt(canonical_tree_log_extends extends_insert extends_refl).
qed.

lemma derive_keeps_canonical_tree_log seed base queries :
  hoare [Independent.derive :
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed base queries].
proof.
  proc; if; auto; smt(canonical_tree_log_extends extends_insert extends_refl).
qed.

lemma hash_appends_canonical_tree_log seed0 base :
  hoare [Independent.hash :
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
    canonical_tree_input Independent.rawhistory Independent.secrethistory seed0 x ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; sp 1; if; auto;
    smt(canonical_tree_log_push_extends extends_insert extends_refl).
qed.

lemma derive_preserves_current_tree_log seed0 base :
  hoare [Independent.derive :
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (derive_keeps_canonical_tree_log seed0 base queries); smt().
qed.

lemma canonical_tree_log_of_wots h s seed base queries :
  canonical_wots_log h s seed base queries => canonical_tree_log h s seed base queries.
proof.
  move=> [inputs [hq hi]]; exists inputs; split; first exact hq.
  apply/allP => x hx; rewrite /canonical_tree_input; left; move: hi; rewrite allP; smt().
qed.

lemma leaf_keeps_fixed_tree_log seed0 base queries :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base queries].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (keygen_leaf_extends RawKeygen s0 h0); smt(extends_refl canonical_tree_log_extends).
qed.

lemma leaf_appends_canonical_tree_log seed0 layer0 tree0 kp0 base :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    wots_address_valid layer0 tree0 kp0 0 0 /\
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_tree_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (raw_leaf_canonical_queries seed0 layer0 tree0 kp0 queries)
    (leaf_keeps_fixed_tree_log seed0 base queries);
    smt(canonical_wots_log_empty canonical_tree_log_of_wots canonical_tree_log_compose).
qed.
