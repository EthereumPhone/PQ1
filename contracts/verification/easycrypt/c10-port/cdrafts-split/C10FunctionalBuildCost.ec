(* Exact calls and termination of the actual fixed-backend builders.
   These properties hold for arbitrary prior history; value consistency is
   separately required by the functional correspondence contracts. *)
require import AllCore List IntDiv.
require import C10RawOracle KeygenPrefixes RawKeygen RawKeygenCost RawFors RawMerkle.
require import C10FixedBackend DyadicStack StackProjection StackPowers.

lemma fixed_builder_hash_count c :
  hoare[PreparationView(FixedPrefix).hash : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_wots_count c :
  hoare[PreparationView(FixedPrefix).wots : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedPrefix.derive FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_fors_count c :
  hoare[PreparationView(FixedPrefix).fors : FixedBackend.calls = c ==>
    FixedBackend.calls = c+1].
proof. proc; inline FixedPrefix.derive FixedBackend.hash; auto; smt(). qed.

lemma fixed_builder_leaf_count c :
  hoare[RawKeygen(PreparationView(FixedPrefix)).leaf : FixedBackend.calls = c ==>
    FixedBackend.calls = c+345].
proof.
  proc; call (fixed_builder_hash_count (c+344)); wp.
  while (0 <= i <= 43 /\ FixedBackend.calls = c+8*i).
  + wp; while (0 <= j <= 7 /\ FixedBackend.calls = c+8*i+1+j).
    - exists* i, j; elim* => i0 j0; wp.
      call (fixed_builder_hash_count (c+8*i0+1+j0)); auto; smt().
    wp; exists* i; elim* => i0; call (fixed_builder_wots_count (c+8*i0)); auto; smt().
  auto; smt().
qed.

lemma fixed_builder_fors_tree_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).tree : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6143].
proof.
  proc; while (0 <= j <= 2048 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = j /\ FixedBackend.calls = c+3*j-size stack).
  + wp; while (0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = j+1 /\
      FixedBackend.calls = c+3*j+2-size stack).
    - exists* j, stack; elim* => j0 st0; wp.
      call (fixed_builder_hash_count (c+3*j0+2-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* j, stack; elim* => j0 st0.
    call (fixed_builder_hash_count (c+3*j0+1-size st0)); wp.
    call (fixed_builder_fors_count (c+3*j0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by ring.
    move=> hc; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls j st hx hin.
  have hs : map snd st = [11] by smt(stack_power_singleton stack_pow2_11).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_fors_root_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).root : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6143].
proof. proc; call (fixed_builder_fors_tree_count c); auto. qed.

lemma fixed_builder_fors_sign_count c :
  hoare[RawFors(PreparationView(FixedPrefix)).sign : FixedBackend.calls = c ==>
    FixedBackend.calls = c+6144].
proof.
  proc; call (fixed_builder_fors_tree_count (c+1)); wp.
  call (fixed_builder_fors_count c); auto; smt().
qed.

lemma fixed_builder_merkle_root_count c :
  hoare[RawKeygen(PreparationView(FixedPrefix)).root : FixedBackend.calls = c ==>
    FixedBackend.calls = c+177151].
proof.
  proc; while (0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ FixedBackend.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      FixedBackend.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0; wp.
      call (fixed_builder_hash_count (c+346*kp0+345-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (fixed_builder_leaf_count (c+346*kp0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls kp st hx hin.
  have hs : map snd st = [9] by smt(stack_power_singleton stack_pow2_9).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_merkle_build_count c :
  hoare[RawMerkle(PreparationView(FixedPrefix)).build : FixedBackend.calls = c ==>
    FixedBackend.calls = c+177151].
proof.
  proc; while (0 <= kp <= 512 /\ increasing_stack (map snd stack) /\
    stack_mass (map snd stack) = kp /\ FixedBackend.calls = c+346*kp-size stack).
  + wp; while (0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack) + 2^height = kp+1 /\
      FixedBackend.calls = c+346*kp+345-size stack).
    - exists* kp, stack; elim* => kp0 st0; wp.
      call (fixed_builder_hash_count (c+346*kp0+345-size st0)); auto;
        smt(projected_carry_pop size_behead size_eq0 size_ge0).
    wp; exists* kp, stack; elim* => kp0 st0.
    call (fixed_builder_leaf_count (c+346*kp0-size st0)); auto => />; rewrite expr0.
    move=> hn he hi hj; split; first by smt(increasing_nonnegative).
    move=> h st hx hh hs hb hm.
    have ha : active_stack (map snd st) h by rewrite /active_stack; smt().
    have hp := projected_carry_push st [] [] h ha _; first by smt().
    move: hp; rewrite /=; smt().
  auto; move=> &hr hi.
  split; first by rewrite /=; smt().
  move=> calls kp st hx hin.
  have hs : map snd st = [9] by smt(stack_power_singleton stack_pow2_9).
  have hz : size st = 1 by smt(size_map).
  smt().
qed.

lemma fixed_builder_wots_ll : islossless PreparationView(FixedPrefix).wots.
proof. proc; call fixed_derive_ll; auto. qed.

lemma fixed_builder_fors_ll : islossless PreparationView(FixedPrefix).fors.
proof. proc; call fixed_derive_ll; auto. qed.

lemma fixed_builder_fors_tree_ll : islossless RawFors(PreparationView(FixedPrefix)).tree.
proof. exact (fors_tree_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_fors_ll). qed.

lemma fixed_builder_fors_root_ll : islossless RawFors(PreparationView(FixedPrefix)).root.
proof. proc; call fixed_builder_fors_tree_ll; auto. qed.

lemma fixed_builder_fors_sign_ll : islossless RawFors(PreparationView(FixedPrefix)).sign.
proof. proc; call fixed_builder_fors_tree_ll; wp; call fixed_builder_fors_ll; auto. qed.

lemma fixed_builder_merkle_root_ll : islossless RawKeygen(PreparationView(FixedPrefix)).root.
proof. exact (root_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_wots_ll). qed.

lemma fixed_builder_merkle_build_ll : islossless RawMerkle(PreparationView(FixedPrefix)).build.
proof. exact (merkle_build_lossless (PreparationView(FixedPrefix)) fixed_hash_ll fixed_builder_wots_ll). qed.
