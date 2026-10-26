(* FORS canonical query suffixes survive both actual memo-table extensions. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts AddressedForsCanonicity.

op canonical_fors_log h s seed base queries =
  exists inputs, queries=base++inputs /\ all (canonical_fors_input h s seed) inputs.

lemma canonical_fors_log_empty h s seed base : canonical_fors_log h s seed base base.
proof. rewrite /canonical_fors_log; exists []; by rewrite cats0. qed.

lemma canonical_fors_list_extends h h' s s' seed inputs :
  extends h h' => extends s s' => all (canonical_fors_input h s seed) inputs =>
  all (canonical_fors_input h' s' seed) inputs.
proof.
  move=> hh hs hall; apply/allP => x hx.
  apply (canonical_fors_input_extends h h' s s' seed x hh hs).
  by move: hall; rewrite allP; apply.
qed.

lemma canonical_fors_log_extends h h' s s' seed base queries :
  extends h h' => extends s s' => canonical_fors_log h s seed base queries =>
  canonical_fors_log h' s' seed base queries.
proof.
  move=> hh hs [inputs [hq hall]]; exists inputs.
  smt(canonical_fors_list_extends).
qed.

lemma canonical_fors_log_push h s seed base queries x :
  canonical_fors_log h s seed base queries => canonical_fors_input h s seed x =>
  canonical_fors_log h s seed base (rcons queries x).
proof.
  move=> [inputs [hq hall]] hx; exists (rcons inputs x).
  rewrite -!cats1 all_cat /=; smt(catA).
qed.

lemma canonical_fors_log_compose h s seed base middle queries :
  canonical_fors_log h s seed base middle => canonical_fors_log h s seed middle queries =>
  canonical_fors_log h s seed base queries.
proof.
  move=> [xs [hm hx]] [ys [hq hy]]; exists (xs++ys).
  rewrite all_cat; smt(catA).
qed.

lemma canonical_fors_log_push_extends h h' s s' seed base queries x :
  extends h h' => extends s s' =>
  canonical_fors_log h s seed base queries => canonical_fors_input h s seed x =>
  canonical_fors_log h' s' seed base (rcons queries x).
proof.
  move=> hh hs hl hx.
  exact (canonical_fors_log_extends h h' s s' seed base (rcons queries x) hh hs
    (canonical_fors_log_push h s seed base queries x hl hx)).
qed.

lemma hash_keeps_canonical_fors_log seed base queries :
  hoare [Independent.hash :
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base queries].
proof.
  proc; sp 1; if; auto; smt(canonical_fors_log_extends extends_insert extends_refl).
qed.

lemma derive_keeps_canonical_fors_log seed base queries :
  hoare [Independent.derive :
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed base queries].
proof.
  proc; if; auto; smt(canonical_fors_log_extends extends_insert extends_refl).
qed.

lemma hash_appends_canonical_fors_log seed0 base :
  hoare [Independent.hash :
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries /\
    canonical_fors_input Independent.rawhistory Independent.secrethistory seed0 x ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; sp 1; if; auto;
    smt(canonical_fors_log_push_extends extends_insert extends_refl).
qed.

lemma derive_preserves_current_fors_log seed0 base :
  hoare [Independent.derive :
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_fors_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  exists* Independent.queries; elim* => queries.
  conseq (derive_keeps_canonical_fors_log seed0 base queries); smt().
qed.

