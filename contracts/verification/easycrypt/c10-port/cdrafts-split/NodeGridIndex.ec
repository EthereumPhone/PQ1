require import AllCore IntDiv StdOrder DyadicStack.
import IntOrder.

lemma dyadic_index_step target height :
  0 <= height => target %/ (2^(height+1)) = (target %/ (2^height)) %/ 2.
proof.
  move=> hh; rewrite exprS 1:hh mulrC divzMr //; smt(pow2_pos).
qed.

lemma dyadic_index_range target height total :
  0 <= height <= total => 0 <= target < 2^total =>
  0 <= target %/ (2^height) < 2^(total-height).
proof.
  move=> hh ht.
  have hp := pow2_pos height _; first by smt().
  have he : 2^total = 2^(total-height)*2^height.
  + rewrite -exprD_nneg 1,2:/#; smt().
  rewrite divz_ge0 1:hp ltz_divLR 1:hp -he; smt().
qed.

lemma child_index_cases index :
  index %% 2 = 0 \/ index %% 2 = 1.
proof. have := modz_ge0 index 2; have := ltz_pmod index 2; smt(). qed.

lemma child_index_even index :
  index %% 2 = 0 => index = 2*(index %/ 2).
proof. have := divz_eq index 2; smt(). qed.

lemma child_index_odd index :
  index %% 2 <> 0 => index = 2*(index %/ 2)+1.
proof. have := divz_eq index 2; have := child_index_cases index; smt(). qed.

lemma aligned_pair_indices n height :
  0 <= height => 2^(height+1) %| n =>
  (n-1) %/ (2^height) = 2*((n-1) %/ (2^(height+1)))+1 /\
  (n-2^height-1) %/ (2^height) = 2*((n-1) %/ (2^(height+1))).
proof.
  move=> hh hd.
  have hp := pow2_pos height hh.
  have he : 2^(height+1) = 2*2^height by rewrite exprS.
  have hn := divzK (2^(height+1)) n hd.
  pose q := n %/ (2^(height+1)).
  have hn' : n = q*(2*2^height) by smt().
  have hparent : (n-1) %/ (2^(height+1)) = q-1.
  + rewrite he (_ : n-1 = (q-1)*(2*2^height)+(2*2^height-1)) 1:/#.
    rewrite edivz_eq // ger0_norm; smt().
  rewrite hparent.
  have hr : (n-1) %/ (2^height) = 2*q-1.
  + rewrite (_ : n-1 = (2*q-1)*2^height+(2^height-1)) 1:/#.
    rewrite edivz_eq // ger0_norm; smt().
  have hl : (n-2^height-1) %/ (2^height) = 2*q-2.
  + rewrite (_ : n-2^height-1 = (2*q-2)*2^height+(2^height-1)) 1:/#.
    rewrite edivz_eq // ger0_norm; smt().
  smt().
qed.
