require import AllCore List FMap IntDiv.
require import C10RawOracle RawFors DyadicStack StackProjection StackAlignment.
require import NodeCatalog NodeGridIndex CatalogForest AuthCaptureIndex.

op target_sibling target height = sibling_index (target %/ (2^height)).
op selected_sibling target height parent (left current : raw_input) =
  if 2*parent = target_sibling target height then left else current.

lemma catalog_selected_sibling c stack current height n target :
  active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  (n-1) %/ (2^(height+1)) = target %/ (2^(height+1)) =>
  c.[(height,target_sibling target height)] = Some
    (selected_sibling target height ((n-1) %/ (2^(height+1)))
      (head ([],0) stack).`1 current).
proof.
  move=> ha hs hh hm hf hc hparent.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs hh.
  have hmass : stack_mass (map snd (behead stack)) + 2^(height+1) = n by smt().
  have hdiv := active_stack_alignment (map snd (behead stack)) (height+1) n ha' hmass.
  have hz : 0 <= height by move: ha; rewrite /active_stack; smt().
  have [hright hleftindex] := aligned_pair_indices n height hz hdiv.
  have [hz' [hleft hrest]] := forest_pop c stack n height hf hs hh.
  have ht := dyadic_index_step target height hz.
  have hsib := sibling_pair_membership (target %/ (2^height))
    ((n-1) %/ (2^(height+1))).
  rewrite /target_sibling /selected_sibling; smt().
qed.
