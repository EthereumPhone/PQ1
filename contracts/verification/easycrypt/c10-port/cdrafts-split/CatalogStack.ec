require import AllCore List FMap IntDiv.
require import C10RawOracle DyadicStack StackProjection StackAlignment NodeCatalog NodeCatalogDomain.

lemma projected_catalog_pop ['a] (stack : ('a*int) list) (default : 'a) h n c value :
  active_stack (map snd stack) h => stack <> [] => (head (default,0) stack).`2 = h =>
  stack_mass (map snd stack) + 2^h = n => 0 < n =>
  catalog_partial c n h =>
  active_stack (map snd (behead stack)) (h+1) /\
  stack_mass (map snd (behead stack)) + 2^(h+1) = n /\
  catalog_partial c.[(h+1,(n-1) %/ (2^(h+1))) <- value] n (h+1).
proof.
  move=> ha hs hh hm hn hc.
  have [hp he] := projected_carry_pop stack default h ha hs hh.
  have hm' : stack_mass (map snd (behead stack)) + 2^(h+1) = n by smt().
  have hd := active_stack_alignment (map snd (behead stack)) (h+1) n hp hm'.
  have hz : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hn' := catalog_partial_next c n h value hn hz hd hc.
  smt().
qed.

lemma projected_no_carry ['a] (stack : ('a*int) list) (default : 'a) h :
  (stack = [] \/ (head (default,0) stack).`2 <> h) =>
  map snd stack = [] \/ head 0 (map snd stack) <> h.
proof. case stack => //= x rest; smt(). qed.

lemma projected_catalog_finish ['a] (stack : ('a*int) list) (default : 'a) h n c :
  active_stack (map snd stack) h =>
  (stack = [] \/ (head (default,0) stack).`2 <> h) =>
  stack_mass (map snd stack) + 2^h = n =>
  catalog_partial c n h => catalog_exact c n.
proof.
  move=> ha hx hn hc.
  have hx' : map snd stack = [] \/ head 0 (map snd stack) <> h.
  + exact (projected_no_carry stack default h hx).
  exact (catalog_partial_finish c (map snd stack) h n ha hx' hn hc).
qed.

lemma projected_carry_height_bound ['a] (stack : ('a*int) list) (default : 'a) height n total :
  0 <= total => active_stack (map snd stack) height =>
  stack <> [] => (head (default,0) stack).`2 = height =>
  stack_mass (map snd stack) + 2^height = n => n <= 2^total =>
  0 <= height < total.
proof.
  move=> ht ha hs hh hm hn.
  have [ha' hm'] := projected_carry_pop stack default height ha hs hh.
  have hz : 0 <= height by move: ha; rewrite /active_stack; smt().
  have hnonneg : 0 <= stack_mass (map snd (behead stack)).
  + apply stack_mass_nonnegative; apply increasing_nonnegative.
    move: ha'; rewrite /active_stack; smt().
  have hpow : 2^(height+1) <= 2^total by smt().
  have hle : height+1 <= total.
  + apply (StdOrder.IntOrder.ler_weexpn2r 2); smt().
  smt().
qed.
