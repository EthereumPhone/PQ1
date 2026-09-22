(* Bounded NPRF hypertree signing. A failed layer returns no signature;
   the remaining layer slots perform no cryptographic work. This uses the
   existing sampled-key model and is not a Rust extraction. *)
require import AllCore List Distr IntDiv BinaryTrees MerkleTrees.
require import C10BoundedHypertree C10BoundedSigning XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedGrind XMSSMT_C_Scheme.

(* A mutant replaces failure with an empty signature. *)
module ReleasePartial = {
  proc sign(sk : skWOTS list list list * pseed * adrs, m : msgFLSLXMSSMTTW, idx : index) = {
    var result : sigFLSLXMSSMTTWC option;
    result <@ BoundedHypertree.sign(sk, m, idx);
    return if result = None then Some [] else result;
  }
}.
lemma mutant_always_releases :
  hoare[ReleasePartial.sign : true ==> res <> None].
proof.
  proc; call (_ : true ==> true); first by conseq bounded_hypertree_sign_ll.
  by auto; smt().
qed.
lemma mutant_rejects_exhaustion :
  hoare[ReleasePartial.sign :
    !prefix_hit sk.`2
      (set_kpidx (set_typeidx
        (set_ltidx sk.`3 0 (Index.val idx %/ l')) chtype) (Index.val idx %% l')) m
    ==> res = None].
proof.
  proc; call bounded_hypertree_first_failure.
  by auto.
qed.
