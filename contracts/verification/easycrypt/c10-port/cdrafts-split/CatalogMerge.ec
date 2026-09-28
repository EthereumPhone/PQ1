require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen DyadicStack StackProjection StackAlignment.
require import NodeCatalog NodeCatalogDomain NodeGridIndex CatalogForest.

lemma catalog_merge_recorded h f c stack current height n d :
  active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n =>
  catalog_partial c n height => catalog_sound h f c =>
  forest_references c stack (n-2^height) =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  h.[f (height+1) ((n-1) %/ (2^(height+1))) (head ([],0) stack).`1 current] = Some d =>
  let c' = c.[(height+1,(n-1) %/ (2^(height+1))) <- node d] in
    catalog_sound h f c' /\
    forest_references c' (behead stack) (n-2^(height+1)) /\
    c'.[(height+1,(n-1) %/ (2^(height+1)))] = Some (node d).
proof.
  move=> ha hs hh hm hp hsound hf hcur hd.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs hh.
  have hm'' : stack_mass (map snd (behead stack)) + 2^(height+1) = n by smt().
  have hdiv := active_stack_alignment (map snd (behead stack)) (height+1) n ha' hm''.
  have hz : 0 <= height by move: ha; rewrite /active_stack; smt().
  have hnonneg := increasing_nonnegative (map snd stack) _;
    first by move: ha; rewrite /active_stack; smt().
  have hn : 0 < n by smt(stack_mass_nonnegative pow2_pos).
  have hindex : 0 <= (n-1) %/ (2^(height+1)).
  + rewrite divz_ge0; smt(pow2_pos).
  have hnew := catalog_partial_fresh c n height hz hdiv hp.
  have hext := catalog_extension_fresh c (height+1,(n-1) %/ (2^(height+1))) (node d) hnew.
  have [hz' [hleft hrest]] := forest_pop c stack n height hf hs hh.
  have [hri hli] := aligned_pair_indices n height hz hdiv.
  have hlink : catalog_link h f
    c.[(height+1,(n-1) %/ (2^(height+1))) <- node d]
    (height+1) ((n-1) %/ (2^(height+1))).
  + rewrite /catalog_link; exists (head ([],0) stack).`1 current d.
    rewrite !get_setE; smt().
  have hsound' := catalog_sound_insert h h f c (height+1)
    ((n-1) %/ (2^(height+1))) (node d) _ hsound hnew _ hindex _;
    try by rewrite /PersistentGrind.extends.
  + smt().
  + smt().
  have hforest' := forest_references_extends c
    c.[(height+1,(n-1) %/ (2^(height+1))) <- node d]
    (behead stack) (n-2^(height+1)) hext hrest.
  smt(get_set_sameE).
qed.
