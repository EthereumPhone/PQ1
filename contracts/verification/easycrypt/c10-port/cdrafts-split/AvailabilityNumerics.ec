(* Native real-arithmetic bounds. These arguments do not import or assume a
   theorem from the separate Lean probability project. *)
require import AllCore IntDiv StdOrder Ring.
require import C10Counter WotsAcceptanceMass WotsRejectDomain GrindTail.
require import ByteRAvailability ByteTotalAvailability FullRBound FullSessionCost FullPrefix.
import RField RealOrder.

lemma rejection_linear_bound p n : 0%r<=p<=1%r => 0<=n =>
  (1%r-p)^n * (1%r+n%r*p) <= 1%r.
proof.
  move=> hp; elim/natind: n => [n hn|n hn ih] hn0.
  + have -> : n=0 by smt().
    by rewrite expr0 /=.
  have hq : 0%r <= (1%r-p)^n by apply expr_ge0; smt().
  have hpoly : (1%r-p)*(1%r+(n+1)%r*p) <= 1%r+n%r*p.
  + rewrite fromintD /=; smt().
  have hm : (1%r-p)^n * ((1%r-p)*(1%r+(n+1)%r*p)) <=
    (1%r-p)^n * (1%r+n%r*p) by apply ler_wpmul2l; smt().
  rewrite exprSr 1:hn -mulrA; smt().
qed.

lemma rejection_block_half p k : 0%r<=p<=1%r => 0<=k => 1%r<=k%r*p =>
  (1%r-p)^k <= 1%r/2%r.
proof.
  move=> hp hk hkp; have h := rejection_linear_bound p k hp hk.
  have hq : 0%r<=(1%r-p)^k by apply expr_ge0; smt().
  smt().
qed.

lemma wots_acceptance_lower : 1%r/30720%r <= wots_acceptance_mass.
proof.
  rewrite wots_acceptance_mass_value (_ : 129=128+1) 1:// exprSr 1://
    (_ : 128=2*2*2*2*2*2*2) 1:// !exprM !expr2.
  smt().
qed.

lemma wots_signing_tail : (1%r-wots_acceptance_mass)^signing_budget <= (1%r/2%r)^320.
proof.
  have hp := wots_acceptance_mass_bounds.
  have h1 : (1%r-wots_acceptance_mass)^signing_budget <=
      (1%r-1%r/30720%r)^signing_budget.
  + apply ler_pexp; rewrite /signing_budget; smt(wots_acceptance_lower).
  have h2 : (1%r-1%r/30720%r)^signing_budget <=
      (1%r-1%r/30720%r)^(30720*320).
  + apply ler_wiexpn2l; rewrite /signing_budget; smt().
  have h3 : ((1%r-1%r/30720%r)^30720)^320 <= (1%r/2%r)^320.
  + apply ler_pexp; first by smt().
    split; first by apply expr_ge0; smt().
    move=> _; apply (rejection_block_half (1%r/30720%r) 30720); smt().
  rewrite exprM in h2; smt().
qed.

lemma wots_signing_domain_charge : wots_domain_charge signing_budget <= (1%r/2%r)^64.
proof.
  have h := wots_signing_tail.
  have he : (2^256)%r * (1%r/2%r)^320 = (1%r/2%r)^64.
  + rewrite -fromintXn 1:// (_ : 320=256+64) 1:// exprD_nneg //.
    by rewrite mulrA -exprMn 1:// (_ : 2%r*(1%r/2%r)=1%r) 1:// expr1z /=.
  rewrite /wots_domain_charge -he; apply ler_wpmul2l; smt(IntOrder.expr_gt0).
qed.

lemma r_acceptance_fraction : (1%r/2%r)^11=1%r/2048%r.
proof.
  rewrite (_ : 11=8+2+1) 1:// !exprD_nneg // expr1
    (_ : 8=2*2*2) 1:// !exprM !expr2; field; smt().
qed.

lemma r_signing_tail : reject_mass^signing_budget <= (1%r/2%r)^64.
proof.
  have hb : reject_mass^2048 <= 1%r/2%r.
  + rewrite /reject_mass r_acceptance_fraction.
    apply (rejection_block_half (1%r/2048%r) 2048); smt().
  have hm : reject_mass^signing_budget <= reject_mass^(2048*64).
  + apply ler_wiexpn2l; rewrite /reject_mass ?r_acceptance_fraction /signing_budget; smt().
  have hp : (reject_mass^2048)^64 <= (1%r/2%r)^64.
  + apply ler_pexp; first by smt().
    have hn : 0%r<=reject_mass^2048 by apply expr_ge0; smt(reject_positive).
    smt().
  rewrite exprM in hm; smt().
qed.

lemma r_availability_numerical :
  byte_r_availability_charge (2^32) (2^20) <= (1%r/2%r)^39.
proof.
  have ht := r_signing_tail; move: ht.
  rewrite /byte_r_availability_charge /full_r_sign_cost /full_public_budget /signing_budget.
  rewrite (_ : 256=2*2*2*2*2*2*2*2) 1://
    (_ : 128=2*2*2*2*2*2*2) 1:// (_ : 64=2*2*2*2*2*2) 1://
    (_ : 39=32+4+2+1) 1:// (_ : 20=16+4) 1://
    (_ : 32=2*2*2*2*2) 1:// (_ : 16=2*2*2*2) 1:// (_ : 4=2*2) 1://.
  rewrite !IntID.exprD_nneg // !IntID.exprM !IntID.expr2
    !exprD_nneg // !exprM !expr2 expr1.
  smt().
qed.

lemma total_availability_numerical :
  byte_total_availability_charge (2^32) (2^20) <= (1%r/2%r)^38.
proof.
  have hr := r_availability_numerical; have hw := wots_signing_domain_charge.
  have he : (1%r/2%r)^39+(1%r/2%r)^64 <= (1%r/2%r)^38.
  + rewrite (_ : 64=2*2*2*2*2*2) 1:// (_ : 39=38+1) 1:// exprSr 1://
      (_ : 38=32+4+2) 1:// !exprD_nneg //
      (_ : 32=2*2*2*2*2) 1:// (_ : 4=2*2) 1:// !exprM !expr2.
    smt().
  rewrite /byte_total_availability_charge; smt().
qed.
