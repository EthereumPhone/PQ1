(* Address alignment forced by a binary-carry stack. *)
require import AllCore List IntDiv StdOrder DyadicStack.
import IntOrder.

lemma stack_mass_divisible heights h :
  0 <= h => all (fun x => h <= x) heights =>
  2^h %| stack_mass heights.
proof.
  move=> hh; elim: heights => //= x rest ih.
  move=> [hx hr].
  apply dvdzD; last exact (ih hr).
  apply dvdz_exp2l; smt().
qed.

lemma active_stack_alignment heights h n :
  active_stack heights h => stack_mass heights + 2^h = n =>
  2^h %| n.
proof.
  move=> ha <-; move: ha; rewrite /active_stack => [#] hh hs hb.
  apply dvdzD; last by apply dvdzz.
  exact (stack_mass_divisible heights h hh hb).
qed.

lemma finished_stack_remainder heights h n :
  active_stack heights h => (heights = [] \/ head 0 heights <> h) =>
  stack_mass heights + 2^h = n => n %% (2^(h+1)) = 2^h.
proof.
  move=> ha hx <-.
  have hi := carry_push heights h ha hx.
  have hh : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hb : all (fun x => h+1 <= x) heights.
  + move: hi; rewrite /= allP; smt().
  have hd := stack_mass_divisible heights (h+1) _ hb; first by smt().
  rewrite dvdz_modzDl 1:hd pmod_small //.
  have hp := pow2_pos h hh.
  rewrite exprS 1:hh; smt().
qed.

lemma finished_stack_maximal heights h n level :
  active_stack heights h => (heights = [] \/ head 0 heights <> h) =>
  stack_mass heights + 2^h = n =>
  0 <= level => 2^level %| n => level <= h.
proof.
  move=> ha hx hn hl hd.
  have hh : 0 <= h by move: ha; rewrite /active_stack; smt().
  have hr := finished_stack_remainder heights h n ha hx hn.
  case (level <= h) => // hnle.
  have hp : 2^(h+1) %| 2^level by apply dvdz_exp2l; smt().
  have hz := dvdz_trans (2^level) (2^(h+1)) n hp hd.
  move: hz; rewrite /(%|) hr; smt(pow2_pos).
qed.
