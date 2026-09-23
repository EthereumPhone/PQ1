(* One actual merge advances exactly the target's captured sibling slot. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawFors DyadicStack StackProjection StackAlignment CatalogStack.
require import NodeCatalog CatalogForest AuthCaptureValue AuthCaptureSchedule AuthSlots AuthSteps AuthStepInvariant.

lemma capture_merge_context (stack : (raw_input*int) list) height n total :
  0 <= total => active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n => n <= 2^total =>
  0 <= height < total /\ 2^(height+1) %| n.
proof.
  move=> ht ha hs hh hm hn.
  have hb := projected_carry_height_bound stack [] height n total ht ha hs hh hm hn.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs hh.
  have he : stack_mass (map snd (behead stack)) + 2^(height+1) = n by smt().
  have hd := active_stack_alignment (map snd (behead stack)) (height+1) n ha' he.
  smt().
qed.

lemma canonical_capture_advance c c' stack current auth target height n total :
  0 <= total => active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n => n <= 2^total =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  slots_saved c auth target total (fun level => pair_captured n height target level) =>
  catalog_extends c c' =>
  slots_saved c' (canonical_auth auth target height ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current) target total
    (fun level => pair_captured n (height+1) target level).
proof.
  move=> ht ha hs hh hm hn hf hc hslots he.
  have [hb hd] := capture_merge_context stack height n total ht ha hs hh hm hn.
  have hv := catalog_selected_sibling c stack current height n target ha hs hh hm hf hc.
  have hp := canonical_auth_saved c auth target height ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current n total hb hd _ hslots hv; first by trivial.
  exact (slots_saved_extends c c' _ target total _ he hp).
qed.

lemma merkle_capture_advance c c' stack current auth kept target height n total :
  0 <= total => active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n => n <= 2^total =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  slots_saved c auth target total (fun level => pair_captured n height target level) =>
  slots_flags kept total (fun level => pair_captured n height target level) =>
  catalog_extends c c' =>
  let arrays = merkle_slots_step auth kept target height ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current in
    slots_saved c' arrays.`1 target total (fun level => pair_captured n (height+1) target level) /\
    slots_flags arrays.`2 total (fun level => pair_captured n (height+1) target level).
proof.
  move=> ht ha hs hh hm hn hf hc hslots hflags he.
  have [hb hd] := capture_merge_context stack height n total ht ha hs hh hm hn.
  have hp := canonical_capture_advance c c' stack current auth target height n total
    ht ha hs hh hm hn hf hc hslots he.
  have hk := canonical_flags_match kept target height ((n-1) %/ (2^(height+1))) n total
    hb hd _ hflags; first by trivial.
  have hx := merkle_slots_canonical auth kept target height ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current n total hb hd _ hflags; first by trivial.
  rewrite hx; smt().
qed.

lemma fors_capture_advance c c' stack current auth target height n total :
  0 <= total => active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n => n <= 2^total =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  slots_saved c auth target total (fun level => pair_captured n height target level) =>
  catalog_extends c c' =>
  slots_saved c' (fors_slots_step auth target height ((n-1) %/ (2^(height+1)))
    (head ([],0) stack).`1 current) target total
    (fun level => pair_captured n (height+1) target level).
proof.
  move=> ht ha hs hh hm hn hf hc hslots he.
  have hz : 0 <= height by move: ha; rewrite /active_stack; smt().
  rewrite fors_slots_canonical 1:hz.
  exact (canonical_capture_advance c c' stack current auth target height n total
    ht ha hs hh hm hn hf hc hslots he).
qed.
