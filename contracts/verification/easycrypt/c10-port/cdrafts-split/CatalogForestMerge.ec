(* Catalog and forest references are preserved for arbitrary oracle outputs. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain CatalogForest.

lemma catalog_forest_merge c stack height n value :
  active_stack (map snd stack) height => stack <> [] =>
  (head ([],0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n =>
  catalog_partial c n height => forest_references c stack (n-2^height) =>
  let c' = c.[(height+1,(n-1) %/ (2^(height+1))) <- value] in
    catalog_extends c c' /\
    forest_references c' (behead stack) (n-2^(height+1)) /\
    c'.[(height+1,(n-1) %/ (2^(height+1)))] = Some value.
proof.
  move=> ha hs hh hm hp hf.
  have [ha' hm'] := projected_carry_pop stack [] height ha hs hh.
  have he : stack_mass (map snd (behead stack)) + 2^(height+1) = n by smt().
  have hd := active_stack_alignment (map snd (behead stack)) (height+1) n ha' he.
  have hz : 0 <= height by move: ha; rewrite /active_stack; smt().
  have hnew := catalog_partial_fresh c n height hz hd hp.
  have hext := catalog_extension_fresh c (height+1,(n-1) %/ (2^(height+1))) value hnew.
  have [hz' [hl hr]] := forest_pop c stack n height hf hs hh.
  have hforest := forest_references_extends c
    c.[(height+1,(n-1) %/ (2^(height+1))) <- value]
    (behead stack) (n-2^(height+1)) hext hr.
  smt(get_set_sameE).
qed.
