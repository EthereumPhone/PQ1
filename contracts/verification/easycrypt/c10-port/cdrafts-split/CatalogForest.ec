(* Each live stack node names its actual catalog entry and covered leaf interval. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle DyadicStack NodeCatalog NodeGridIndex.

op forest_references (c : node_catalog) (stack : (raw_input*int) list) n =
  with stack = [] => n = 0
  with stack = entry :: rest =>
    0 <= entry.`2 /\ 2^(entry.`2) %| n /\
    c.[(entry.`2,(n-1) %/ (2^(entry.`2)))] = Some entry.`1 /\
    forest_references c rest (n-2^(entry.`2)).

lemma forest_references_extends c c' stack n :
  catalog_extends c c' => forest_references c stack n =>
  forest_references c' stack n.
proof.
  move=> he; elim: stack n => //= entry rest ih n.
  move=> [#] hh hd hv hr.
  have hv' : c'.[(entry.`2,(n-1) %/ (2^(entry.`2)))] = Some entry.`1
    by move: he; rewrite /catalog_extends; smt(domE).
  have hr' := ih (n-2^(entry.`2)) hr.
  smt().
qed.

lemma forest_push c stack n current height :
  0 <= height => 2^height %| n =>
  c.[(height,(n-1) %/ (2^height))] = Some current =>
  forest_references c stack (n-2^height) =>
  forest_references c ((current,height)::stack) n.
proof. by rewrite /=. qed.

lemma forest_pop c stack n height :
  forest_references c stack (n-2^height) =>
  stack <> [] => (head ([],0) stack).`2 = height =>
  0 <= height /\
  c.[(height,(n-2^height-1) %/ (2^height))] = Some (head ([],0) stack).`1 /\
  forest_references c (behead stack) (n-2^(height+1)).
proof.
  case stack => //= entry rest.
  move=> [#] hh hd hv hr he.
  have hp : 2^(height+1) = 2*2^height by rewrite exprS 1:/#; ring.
  smt().
qed.

lemma forest_leaf_insert c stack n value :
  (0,n) \notin c => forest_references c stack n =>
  forest_references c.[(0,n) <- value] stack n /\
  c.[(0,n) <- value].[(0,n)] = Some value.
proof.
  move=> hf hs.
  have he := catalog_extension_fresh c (0,n) value hf.
  have hp := forest_references_extends c c.[(0,n) <- value] stack n he hs.
  smt(get_set_sameE).
qed.

lemma forest_singleton_root c stack height default :
  0 <= height => map snd stack = [height] =>
  forest_references c stack (2^height) =>
  (head (default,0) stack).`1 = catalog_grid c height 0.
proof.
  case stack => //= entry rest.
  case rest => [|next tail] //=.
  move=> hh he hf.
  have hp := pow2_pos height hh.
  have hi : (2^height-1) %/ (2^height) = 0 by apply pdiv_small; smt().
  rewrite /catalog_grid; smt(oget_some).
qed.
