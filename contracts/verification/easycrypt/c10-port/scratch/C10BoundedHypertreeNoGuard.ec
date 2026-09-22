(* Bounded NPRF hypertree signing. A failed layer returns no signature;
   the remaining layer slots perform no cryptographic work. This uses the
   existing sampled-key model and is not a Rust extraction. *)
require import AllCore List Distr IntDiv BinaryTrees MerkleTrees.
require import C10BoundedHypertree C10BoundedSigning XmssmtCC_All.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES.
import WOTS_C_Real WOTS_C_Scheme C10BoundedGrind XMSSMT_C_Scheme.

(* Dropping successful-result conditioning would assert that exhaustion
   still returns a signature. The checked relation cannot establish that. *)
lemma erased_success_guard :
  equiv[FL_SL_XMSS_MT_C_ES_NPRF.sign ~ BoundedHypertree.sign :
    ={sk, m, idx} ==> res{2} = Some res{1}].
proof.
  conseq total_bounded_hypertree_sign.
  + by trivial.
  by trivial.
qed.
