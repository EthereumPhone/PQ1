(* Monotone prior-history resource allowance. *)
require import AllCore List StdOrder StdBigop.
require import C10Counter GrindTail GrindExhaustion.
import RealOrder Bigreal BRA.

lemma exhaustion_charge_mono q1 q2 :
  q1 <= q2 => exhaustion_charge q1 <= exhaustion_charge q2.
proof.
  move=> hq; rewrite /exhaustion_charge; apply RealOrder.ler_add; first by [].
  rewrite /revisit_charge; apply Bigreal.ler_sum => i _.
  have hp : 0%r <= (1%r/2%r)^128 by apply expr_ge0; smt().
  apply ler_wpmul2r => //; rewrite le_fromint; smt().
qed.
