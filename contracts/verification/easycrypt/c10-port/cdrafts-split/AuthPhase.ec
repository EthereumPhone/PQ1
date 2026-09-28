require import AllCore List FMap IntDiv.
require import C10RawOracle DyadicStack StackAlignment NodeCatalog NodeCatalogDomain.
require import AuthCaptureSchedule AuthSlots CatalogStack.

op captured_full n target level = target_pair_edge target level <= n.

lemma target_pair_positive target level :
  0 <= target => 0 <= level => 0 < target_pair_edge target level.
proof.
  move=> ht hl; rewrite /target_pair_edge.
  apply node_edge_positive; first by smt().
  rewrite divz_ge0; smt(pow2_pos).
qed.

lemma slots_initial target total :
  0 <= target => 0 <= total =>
  slots_saved empty (nseq total (nseq 16 0)) target total (captured_full 0 target) /\
  slots_flags (nseq total false) total (captured_full 0 target).
proof.
  move=> ht hh.
  have hn : forall level, 0 <= level < total => !captured_full 0 target level.
  + move=> level hl; have hp := target_pair_positive target level ht _; first by smt().
    rewrite /captured_full; smt().
  split.
  + rewrite /slots_saved size_nseq; smt().
  rewrite /slots_flags size_nseq; split; first by smt().
  move=> level hl; rewrite nth_nseq; smt().
qed.

lemma slots_phase_start c c' auth kept target total n :
  catalog_extends c c' =>
  slots_saved c auth target total (captured_full n target) =>
  slots_flags kept total (captured_full n target) =>
  slots_saved c' auth target total (pair_captured (n+1) 0 target) /\
  slots_flags kept total (pair_captured (n+1) 0 target).
proof.
  move=> he hs hk.
  have hs' := slots_saved_extends c c' auth target total (captured_full n target) he hs.
  have heq : forall level, 0 <= level < total =>
    captured_full n target level = pair_captured (n+1) 0 target level
    by rewrite /captured_full; smt(pair_capture_start).
  split.
  + exact (slots_saved_equiv c' auth target total _ _ heq hs').
  exact (slots_flags_equiv kept total _ _ heq hk).
qed.

lemma slots_phase_finish (stack : (raw_input*int) list) c auth kept target total height n :
  active_stack (map snd stack) height =>
  (stack = [] \/ (head ([],0) stack).`2 <> height) =>
  stack_mass (map snd stack) + 2^height = n =>
  slots_saved c auth target total (pair_captured n height target) =>
  slots_flags kept total (pair_captured n height target) =>
  slots_saved c auth target total (captured_full n target) /\
  slots_flags kept total (captured_full n target).
proof.
  move=> ha hx hn hs hk.
  have hx' := projected_no_carry stack [] height hx.
  have heq : forall level, 0 <= level < total =>
    pair_captured n height target level = captured_full n target level.
  + move=> level hl; rewrite /captured_full.
    have hp := pair_capture_finish (map snd stack) height n target level _ ha hx' hn;
      smt().
  split.
  + exact (slots_saved_equiv c auth target total _ _ heq hs).
  exact (slots_flags_equiv kept total _ _ heq hk).
qed.

lemma saved_phase_start c c' auth target total n :
  catalog_extends c c' =>
  slots_saved c auth target total (captured_full n target) =>
  slots_saved c' auth target total (pair_captured (n+1) 0 target).
proof.
  move=> he hs.
  have hs' := slots_saved_extends c c' auth target total (captured_full n target) he hs.
  have heq : forall level, 0 <= level < total =>
    captured_full n target level = pair_captured (n+1) 0 target level
    by rewrite /captured_full; smt(pair_capture_start).
  exact (slots_saved_equiv c' auth target total _ _ heq hs').
qed.

lemma saved_phase_finish (stack : (raw_input*int) list) c auth target total height n :
  active_stack (map snd stack) height =>
  (stack = [] \/ (head ([],0) stack).`2 <> height) =>
  stack_mass (map snd stack) + 2^height = n =>
  slots_saved c auth target total (pair_captured n height target) =>
  slots_saved c auth target total (captured_full n target).
proof.
  move=> ha hx hn hs.
  have hx' := projected_no_carry stack [] height hx.
  have heq : forall level, 0 <= level < total =>
    pair_captured n height target level = captured_full n target level.
  + move=> level hl; rewrite /captured_full.
    have hp := pair_capture_finish (map snd stack) height n target level _ ha hx' hn;
      smt().
  exact (slots_saved_equiv c auth target total _ _ heq hs).
qed.
