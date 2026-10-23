(* Actual native builders preserve zero authentication slots outside their tree. *)
require import AllCore List IntDiv StdOrder.
require import C10RawOracle KeygenPrefixes RawKeygen RawFors RawMerkle.
require import DyadicStack StackProjection StackPowers CatalogStack NodeGridIndex AuthCaptureIndex.
import IntOrder.

lemma functional_outside_parent inside outside h total :
  0 <= h <= total => 0 <= inside < 2^total => 2^total <= outside =>
  inside %/ (2^h) <> outside %/ (2^h).
proof.
  move=> hh hi ho.
  have hr := dyadic_index_range inside h total hh hi.
  have hp := pow2_pos h _; first by smt().
  have he : 2^(total-h)*2^h = 2^total by rewrite -exprD_nneg 1,2:/#; congr; ring.
  have hq : 2^(total-h) <= outside %/ (2^h) by rewrite lez_divRL 1:hp he.
  smt().
qed.

lemma functional_fors_outside (O <: PreparationOracle) target0 :
  hoare[RawFors(O).tree : target = target0 /\ 2048 <= target0 ==>
    res.`2 = nseq 11 (nseq 16 0)].
proof.
  proc; while (target = target0 /\ 2048 <= target0 /\ auth = nseq 11 (nseq 16 0) /\
    0 <= j <= 2048 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = j).
  + wp; while (target = target0 /\ 2048 <= target0 /\ auth = nseq 11 (nseq 16 0) /\
      0 <= j < 2048 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = j+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &m hi.
      have hb := projected_carry_height_bound stack{m} [] height{m} (j{m}+1) 11.
      have hd : j{m} %/ (2^(height{m}+1)) <> target0 %/ (2^(height{m}+1)).
      + apply (functional_outside_parent j{m} target0 (height{m}+1) 11); smt(stack_pow2_11).
      have hc := fors_capture_parent j{m} target0 height{m}.
      have hp := projected_carry_pop stack{m} [] height{m}.
      smt(stack_pow2_11).
    wp; call (_ : true ==> true); first by trivial.
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &m hi; split; first by smt(carry_initial).
    move=> auth0 h st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have he : st = [] \/ (head ([],0) st).`2 <> h by smt().
    have hp := projected_carry_push st [] [] h ha he.
    move: hp; rewrite /=; smt().
  auto; smt().
qed.

lemma functional_merkle_outside (O <: PreparationOracle) target0 :
  hoare[RawMerkle(O).build : target = target0 /\ 512 <= target0 ==>
    res.`1 = nseq 9 (nseq 16 0)].
proof.
  proc; while (target = target0 /\ 512 <= target0 /\ keep = nseq 9 (nseq 16 0) /\
    0 <= kp <= 512 /\ increasing_stack (map snd stack) /\ stack_mass (map snd stack) = kp).
  + wp; while (target = target0 /\ 512 <= target0 /\ keep = nseq 9 (nseq 16 0) /\
      0 <= kp < 512 /\ active_stack (map snd stack) height /\
      stack_mass (map snd stack)+2^height = kp+1).
    - wp; call (_ : true ==> true); first by trivial.
      auto; move=> &m hi.
      have hb := projected_carry_height_bound stack{m} [] height{m} (kp{m}+1) 9.
      have hd : kp{m} %/ (2^(height{m}+1)) <> target0 %/ (2^(height{m}+1)).
      + apply (functional_outside_parent kp{m} target0 (height{m}+1) 9); smt(stack_pow2_9).
      have hc := merkle_capture_parent kp{m} target0 height{m}.
      have hp := projected_carry_pop stack{m} [] height{m}.
      smt(stack_pow2_9).
    wp; call (_ : true ==> true); first by trivial.
    auto; rewrite expr0.
    move=> &m hi; split; first by smt(carry_initial).
    move=> h keep0 st hx hin.
    have ha : active_stack (map snd st) h by smt().
    have he : st = [] \/ (head ([],0) st).`2 <> h by smt().
    have hp := projected_carry_push st [] [] h ha he.
    move: hp; rewrite /=; smt().
  auto; smt().
qed.
