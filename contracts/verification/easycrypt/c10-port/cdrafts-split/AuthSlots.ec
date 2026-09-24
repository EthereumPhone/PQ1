(* Saved authentication slots and completion flags are persistent catalog facts. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawFors NodeCatalog NodeGridPath.

op slots_saved (c : node_catalog) (auth : raw_input list) target total (ready : int -> bool) =
  size auth = total /\ forall level, 0 <= level < total => ready level =>
    c.[(level,sibling_index (target %/ (2^level)))] = Some (nth [] auth level).
op slots_flags (kept : bool list) total (ready : int -> bool) =
  size kept = total /\ forall level, 0 <= level < total => nth false kept level = ready level.

lemma slots_saved_extends c c' auth target total ready :
  catalog_extends c c' => slots_saved c auth target total ready =>
  slots_saved c' auth target total ready.
proof. rewrite /catalog_extends /slots_saved; smt(domE). qed.

lemma slots_saved_equiv c auth target total ready ready' :
  (forall level, 0 <= level < total => ready level = ready' level) =>
  slots_saved c auth target total ready => slots_saved c auth target total ready'.
proof. rewrite /slots_saved; smt(). qed.

lemma slots_flags_equiv kept total ready ready' :
  (forall level, 0 <= level < total => ready level = ready' level) =>
  slots_flags kept total ready => slots_flags kept total ready'.
proof. rewrite /slots_flags; smt(). qed.

lemma slots_saved_put c auth target total ready height value :
  slots_saved c auth target total ready => 0 <= height < total =>
  c.[(height,sibling_index (target %/ (2^height)))] = Some value =>
  slots_saved c (put auth height value) target total (fun level => ready level \/ level = height).
proof.
  rewrite /slots_saved; move=> [hs ha] hh hv.
  rewrite size_put; split; first exact hs.
  move=> level hl hd; rewrite nth_put 1:/#; smt().
qed.

lemma slots_flags_put kept total ready height :
  slots_flags kept total ready => 0 <= height < total =>
  slots_flags (put kept height true) total (fun level => ready level \/ level = height).
proof.
  rewrite /slots_flags; move=> [hs hk] hh.
  rewrite size_put; split; first exact hs.
  move=> level hl; rewrite nth_put 1:/#; smt().
qed.

lemma slots_saved_complete c auth target total ready :
  0 <= total => slots_saved c auth target total ready =>
  (forall level, 0 <= level < total => ready level) =>
  auth = grid_auth (catalog_grid c) target total.
proof.
  move=> ht hp hd; move: hp; rewrite /slots_saved; move=> [hs ha].
  apply (eq_from_nth []) => //.
  + rewrite /grid_auth size_mkseq; smt().
  move=> level hl; rewrite /grid_auth nth_mkseq 1:/# /catalog_grid.
  have hh := ha level _ _; smt(oget_some).
qed.
