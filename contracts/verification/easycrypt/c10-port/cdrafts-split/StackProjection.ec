require import AllCore List DyadicStack.

lemma projected_carry_pop ['a] (stack : ('a * int) list) (default : 'a) h :
  active_stack (map snd stack) h => stack <> [] => (head (default,0) stack).`2 = h =>
  active_stack (map snd (behead stack)) (h+1) /\
  stack_mass (map snd stack) + 2^h = stack_mass (map snd (behead stack)) + 2^(h+1).
proof.
  case stack => //= x rest.
  move=> hs he.
  have hc := carry_pop (x.`2 :: map snd rest) h hs _ _;
    smt().
qed.

lemma projected_carry_push ['a] (stack : ('a * int) list) (default current : 'a) h :
  active_stack (map snd stack) h =>
  (stack = [] \/ (head (default,0) stack).`2 <> h) =>
  increasing_stack (map snd ((current,h)::stack)).
proof.
  case stack => /=.
  + rewrite /active_stack /=; smt().
  move=> x rest hs he.
  have hc := carry_push (x.`2 :: map snd rest) h hs _; first by smt().
  by move: hc; rewrite /=.
qed.
