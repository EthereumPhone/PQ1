(* Illustrative model budgets, not deployment policy or claimed attack cost.
   Each inequality is checked by the native real-arithmetic prover. *)
require import AllCore StdOrder StdBigop Ring.
require import C10Counter RawWrapperCost WrapperPrefixBound WrapperWotsCandidateBudget.
require import PoolCoverageBound WrapperNumericalBound.
import RField RealOrder Bigreal Bigreal.BRA.

lemma wrapper_empty_numerical :
  wrapper_physical_euf_charge 0 0 < (1%r/2%r)^78.
proof.
  rewrite /wrapper_physical_euf_charge /wrapper_independent_euf_charge
    /wrapper_total_public_budget /wrapper_public_budget /signing_budget
    /wrapper_wots_candidate_budget /coverage_charge.
  rewrite (big_int_recr 12) 1:// /=.
  rewrite (big_int_recr 11) 1:// /=.
  rewrite (big_int_recr 10) 1:// /=.
  rewrite (big_int_recr 9) 1:// /=.
  rewrite (big_int_recr 8) 1:// /=.
  rewrite (big_int_recr 7) 1:// /=.
  rewrite (big_int_recr 6) 1:// /=.
  rewrite (big_int_recr 5) 1:// /=.
  rewrite (big_int_recr 4) 1:// /=.
  rewrite (big_int_recr 3) 1:// /=.
  rewrite (big_int_recr 2) 1:// /=.
  rewrite big_int1 /=.
  try rewrite (_ : 348=256+64+16+8+4) 1://.
  try rewrite (_ : 330=256+64+8+2) 1://.
  try rewrite (_ : 312=256+32+16+8) 1://.
  try rewrite (_ : 294=256+32+4+2) 1://.
  try rewrite (_ : 276=256+16+4) 1://.
  try rewrite (_ : 258=256+2) 1://.
  try rewrite (_ : 240=128+64+32+16) 1://.
  try rewrite (_ : 222=128+64+16+8+4+2) 1://.
  try rewrite (_ : 204=128+64+8+4) 1://.
  try rewrite (_ : 186=128+32+16+8+2) 1://.
  try rewrite (_ : 168=128+32+8) 1://.
  try rewrite (_ : 150=128+16+4+2) 1://.
  try rewrite (_ : 129=128+1) 1://.
  try rewrite (_ : 78=64+8+4+2) 1://.
  try rewrite (_ : 45=32+8+4+1) 1://.
  try rewrite (_ : 44=32+8+4) 1://.
  try rewrite (_ : 12=8+4) 1://.
  try rewrite (_ : 11=8+2+1) 1://.
  try rewrite (_ : 10=8+2) 1://.
  try rewrite (_ : 9=8+1) 1://.
  try rewrite (_ : 7=4+2+1) 1://.
  try rewrite (_ : 6=4+2) 1://.
  try rewrite (_ : 5=4+1) 1://.
  try rewrite (_ : 3=2+1) 1://.
  rewrite !IntID.exprD_nneg // !exprD_nneg //.
  try rewrite (_ : 256=2*2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 128=2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 64=2*2*2*2*2*2) 1://.
  try rewrite (_ : 32=2*2*2*2*2) 1://.
  try rewrite (_ : 16=2*2*2*2) 1://.
  try rewrite (_ : 8=2*2*2) 1://.
  try rewrite (_ : 4=2*2) 1://.
  rewrite !IntID.exprM !IntID.expr2 !exprM !expr2 !expr1.
  smt().
qed.

lemma wrapper_illustrative_numerical :
  wrapper_physical_euf_charge 50000 50000 < (1%r/2%r)^45.
proof.
  rewrite /wrapper_physical_euf_charge /wrapper_independent_euf_charge
    /wrapper_total_public_budget /wrapper_public_budget /signing_budget
    /wrapper_wots_candidate_budget /coverage_charge.
  rewrite (big_int_recr 12) 1:// /=.
  rewrite (big_int_recr 11) 1:// /=.
  rewrite (big_int_recr 10) 1:// /=.
  rewrite (big_int_recr 9) 1:// /=.
  rewrite (big_int_recr 8) 1:// /=.
  rewrite (big_int_recr 7) 1:// /=.
  rewrite (big_int_recr 6) 1:// /=.
  rewrite (big_int_recr 5) 1:// /=.
  rewrite (big_int_recr 4) 1:// /=.
  rewrite (big_int_recr 3) 1:// /=.
  rewrite (big_int_recr 2) 1:// /=.
  rewrite big_int1 /=.
  try rewrite (_ : 348=256+64+16+8+4) 1://.
  try rewrite (_ : 330=256+64+8+2) 1://.
  try rewrite (_ : 312=256+32+16+8) 1://.
  try rewrite (_ : 294=256+32+4+2) 1://.
  try rewrite (_ : 276=256+16+4) 1://.
  try rewrite (_ : 258=256+2) 1://.
  try rewrite (_ : 240=128+64+32+16) 1://.
  try rewrite (_ : 222=128+64+16+8+4+2) 1://.
  try rewrite (_ : 204=128+64+8+4) 1://.
  try rewrite (_ : 186=128+32+16+8+2) 1://.
  try rewrite (_ : 168=128+32+8) 1://.
  try rewrite (_ : 150=128+16+4+2) 1://.
  try rewrite (_ : 129=128+1) 1://.
  try rewrite (_ : 78=64+8+4+2) 1://.
  try rewrite (_ : 45=32+8+4+1) 1://.
  try rewrite (_ : 44=32+8+4) 1://.
  try rewrite (_ : 12=8+4) 1://.
  try rewrite (_ : 11=8+2+1) 1://.
  try rewrite (_ : 10=8+2) 1://.
  try rewrite (_ : 9=8+1) 1://.
  try rewrite (_ : 7=4+2+1) 1://.
  try rewrite (_ : 6=4+2) 1://.
  try rewrite (_ : 5=4+1) 1://.
  try rewrite (_ : 3=2+1) 1://.
  rewrite !IntID.exprD_nneg // !exprD_nneg //.
  try rewrite (_ : 256=2*2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 128=2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 64=2*2*2*2*2*2) 1://.
  try rewrite (_ : 32=2*2*2*2*2) 1://.
  try rewrite (_ : 16=2*2*2*2) 1://.
  try rewrite (_ : 8=2*2*2) 1://.
  try rewrite (_ : 4=2*2) 1://.
  rewrite !IntID.exprM !IntID.expr2 !exprM !expr2 !expr1.
  smt().
qed.

lemma wrapper_mixed_numerical :
  wrapper_physical_euf_charge 1000000 1000 < (1%r/2%r)^45.
proof.
  rewrite /wrapper_physical_euf_charge /wrapper_independent_euf_charge
    /wrapper_total_public_budget /wrapper_public_budget /signing_budget
    /wrapper_wots_candidate_budget /coverage_charge.
  rewrite (big_int_recr 12) 1:// /=.
  rewrite (big_int_recr 11) 1:// /=.
  rewrite (big_int_recr 10) 1:// /=.
  rewrite (big_int_recr 9) 1:// /=.
  rewrite (big_int_recr 8) 1:// /=.
  rewrite (big_int_recr 7) 1:// /=.
  rewrite (big_int_recr 6) 1:// /=.
  rewrite (big_int_recr 5) 1:// /=.
  rewrite (big_int_recr 4) 1:// /=.
  rewrite (big_int_recr 3) 1:// /=.
  rewrite (big_int_recr 2) 1:// /=.
  rewrite big_int1 /=.
  try rewrite (_ : 348=256+64+16+8+4) 1://.
  try rewrite (_ : 330=256+64+8+2) 1://.
  try rewrite (_ : 312=256+32+16+8) 1://.
  try rewrite (_ : 294=256+32+4+2) 1://.
  try rewrite (_ : 276=256+16+4) 1://.
  try rewrite (_ : 258=256+2) 1://.
  try rewrite (_ : 240=128+64+32+16) 1://.
  try rewrite (_ : 222=128+64+16+8+4+2) 1://.
  try rewrite (_ : 204=128+64+8+4) 1://.
  try rewrite (_ : 186=128+32+16+8+2) 1://.
  try rewrite (_ : 168=128+32+8) 1://.
  try rewrite (_ : 150=128+16+4+2) 1://.
  try rewrite (_ : 129=128+1) 1://.
  try rewrite (_ : 78=64+8+4+2) 1://.
  try rewrite (_ : 45=32+8+4+1) 1://.
  try rewrite (_ : 44=32+8+4) 1://.
  try rewrite (_ : 12=8+4) 1://.
  try rewrite (_ : 11=8+2+1) 1://.
  try rewrite (_ : 10=8+2) 1://.
  try rewrite (_ : 9=8+1) 1://.
  try rewrite (_ : 7=4+2+1) 1://.
  try rewrite (_ : 6=4+2) 1://.
  try rewrite (_ : 5=4+1) 1://.
  try rewrite (_ : 3=2+1) 1://.
  rewrite !IntID.exprD_nneg // !exprD_nneg //.
  try rewrite (_ : 256=2*2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 128=2*2*2*2*2*2*2) 1://.
  try rewrite (_ : 64=2*2*2*2*2*2) 1://.
  try rewrite (_ : 32=2*2*2*2*2) 1://.
  try rewrite (_ : 16=2*2*2*2) 1://.
  try rewrite (_ : 8=2*2*2) 1://.
  try rewrite (_ : 4=2*2) 1://.
  rewrite !IntID.exprM !IntID.expr2 !exprM !expr2 !expr1.
  smt().
qed.

