(* Physical public-query budget for the deployed 512-leaf top subtree. *)
require import AllCore List Distr IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrindCost KeygenPrefixes RawKeygen.

op valid_stack (stack : (raw_input * int) list) =
  all (fun (item : raw_input * int) => size item.`1 = 16) stack.

lemma valid_stack_tail stack : valid_stack stack => valid_stack (behead stack).
proof. by case stack => // item rest; rewrite /valid_stack /=; smt(). qed.
lemma valid_stack_head stack : valid_stack stack =>
  size (head (nseq 16 0,0) stack).`1 = 16.
proof. by case stack => [|item rest]; rewrite /valid_stack /=; smt(size_nseq). qed.

lemma root_public_cost q0 :
  hoare[RawKeygen(PreparationView(Independent)).root : size Independent.queries = q0 ==>
    q0 <= size Independent.queries <= q0 + 155135 /\ size res = 16].
proof.
  proc; while (0 <= kp <= 512 /\ size stack <= kp /\ (0 < kp => stack <> []) /\
    valid_stack stack /\ size Independent.queries = q0+303*kp-size stack).
  + wp; while (0 <= kp < 512 /\ size stack <= kp /\ valid_stack stack /\
      size current = 16 /\ size Independent.queries = q0+303*kp+302-size stack).
    - exists* kp, stack; elim* => kp0 st0.
      wp; call (independent_hash_count (q0+303*kp0+302-size st0)); auto.
      smt(node_width size_behead size_ge0 valid_stack_tail).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (leaf_public_cost (q0+303*kp0-size st0)); auto.
    rewrite /valid_stack /=; smt(size_ge0).
  auto; rewrite /valid_stack /=; smt(size_ge0 size_eq0 valid_stack_head).
qed.

lemma leaf_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots => islossless RawKeygen(O).leaf.
proof.
  move=> hh hw; proc; call hh.
  while true (43-i).
  + move=> z; wp; while true (7-j).
    - move=> z'; wp; call hh; auto; smt().
    wp; call hw; auto; smt().
  auto; smt().
qed.

lemma root_lossless (O <: PreparationOracle) :
  islossless O.hash => islossless O.wots => islossless RawKeygen(O).root.
proof.
  move=> hh hw; proc; while true (512-kp).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_ge0 size_eq0).
    wp; call (leaf_lossless O hh hw); auto; smt(size_ge0).
  auto; smt().
qed.
