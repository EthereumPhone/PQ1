(* Structural arithmetic of a binary-carry treehash stack. *)
require import AllCore List StdOrder.
import IntOrder.

op stack_mass (heights : int list) =
  with heights = [] => 0
  with heights = h :: rest => 2^h + stack_mass rest.

op increasing_stack (heights : int list) =
  with heights = [] => true
  with heights = h :: rest =>
    0 <= h /\ all (fun x => h < x) rest /\ increasing_stack rest.

lemma pow2_mono lo hi : 0 <= lo <= hi => 2^lo <= 2^hi.
proof. move=> hh; apply (ler_weexpn2l 2) => //. qed.

lemma pow2_pos h : 0 <= h => 0 < 2^h.
proof. by move=> _; apply expr_gt0. qed.

lemma increasing_nonnegative heights :
  increasing_stack heights => all (fun h => 0 <= h) heights.
proof. by elim: heights => //= h rest ih; smt(). qed.

lemma stack_mass_nonnegative heights :
  all (fun h => 0 <= h) heights => 0 <= stack_mass heights.
proof. elim: heights => //= h rest ih; smt(pow2_pos). qed.

lemma stack_mass_zero heights :
  all (fun h => 0 <= h) heights => stack_mass heights = 0 => heights = [].
proof.
  case heights => //= h rest.
  smt(pow2_pos stack_mass_nonnegative).
qed.

lemma stack_mass_bounded heights lo hi :
  0 <= lo <= hi =>
  increasing_stack heights =>
  all (fun h => lo <= h < hi) heights =>
  stack_mass heights <= 2^hi - 2^lo.
proof.
  elim: heights lo hi => [lo hi | h rest ih lo hi] /=.
  + move=> hh; smt(pow2_mono).
  move=> hr ho hb.
  have hh : 0 <= h by smt().
  have hn : 0 <= h+1 <= hi by smt().
  have ht : increasing_stack rest by smt().
  have hb' : all (fun x => h+1 <= x < hi) rest.
  + move: ho hb; rewrite !allP; smt().
  have hm := ih (h+1) hi hn ht hb'.
  have he : 2^(h+1) = 2*2^h by rewrite exprS 1:hh; ring.
  have hl : 2^lo <= 2^h by apply pow2_mono; smt().
  smt().
qed.

lemma stack_mass_member heights h :
  all (fun x => 0 <= x) heights => h \in heights =>
  2^h <= stack_mass heights.
proof.
  elim: heights => //= x rest ih.
  smt(stack_mass_nonnegative pow2_pos).
qed.

lemma stack_mass_member_unique heights h :
  all (fun x => 0 <= x) heights => h \in heights =>
  stack_mass heights = 2^h => heights = [h].
proof.
  case heights => //= x rest.
  move=> [hx hr] hm he.
  case (x = h) => eqxh.
  + have hz : stack_mass rest = 0 by smt().
    have -> := stack_mass_zero rest hr hz; smt().
  have hm' : h \in rest by smt().
  have hl := stack_mass_member rest h hr hm'.
  smt(pow2_pos).
qed.

lemma stack_power_singleton heights height :
  0 <= height => increasing_stack heights =>
  stack_mass heights = 2^height => heights = [height].
proof.
  move=> hh hs hm.
  have hn := increasing_nonnegative heights hs.
  have hex : exists h, h \in heights /\ height <= h.
  + case (all (fun h => 0 <= h < height) heights) => hb.
    - have hbnd := stack_mass_bounded heights 0 height _ hs hb; first by smt().
      move: hbnd; rewrite expr0; smt().
    move: hn hb; rewrite !allP; smt().
  elim hex => h [hin hge].
  have hz : 0 <= h by move: hn; rewrite allP; smt().
  have hpow := stack_mass_member heights h hn hin.
  have hle : h <= height by apply (ler_weexpn2r 2) => //; smt().
  have he : h = height by smt().
  apply (stack_mass_member_unique heights height hn); smt().
qed.

op active_stack (heights : int list) h =
  0 <= h /\ increasing_stack heights /\ all (fun x => h <= x) heights.

lemma carry_pop heights h :
  active_stack heights h => heights <> [] => head 0 heights = h =>
  active_stack (behead heights) (h+1) /\
  stack_mass heights + 2^h = stack_mass (behead heights) + 2^(h+1).
proof.
  case heights => //= x rest.
  rewrite /active_stack /=.
  move=> ha he.
  have hp : 2^(h+1) = 2*2^h by rewrite exprS 1:/#; ring.
  move: ha; rewrite !allP; smt().
qed.

lemma carry_push heights h :
  active_stack heights h => (heights = [] \/ head 0 heights <> h) =>
  increasing_stack (h::heights).
proof.
  case heights => //= x rest; rewrite /active_stack /=.
  smt().
qed.

lemma carry_initial heights :
  increasing_stack heights => active_stack heights 0.
proof. rewrite /active_stack; smt(increasing_nonnegative). qed.
