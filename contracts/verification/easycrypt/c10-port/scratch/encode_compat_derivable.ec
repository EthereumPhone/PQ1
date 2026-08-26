(* DISCRIMINATING CONTROL for the 2026-08-25 change making `encode_msgWOTS_C` a
   DEFINITION (cdrafts-split/WOTS_C_Real.ec).  Polarity MUST-PASS.

   It proves the capstone premise `hencb` WITH NO HYPOTHESES.  That is derivable
   ONLY because the op has a body: under the previous abstract declaration
   `op encode_msgWOTS_C : pseed -> adrs -> dgstblock -> cntr -> EmsgWOTS.emsgWOTS.`
   this file CANNOT compile, because nothing in the closure relates the op to
   `encode_msgWOTS o ThC`.  Verified BOTH WAYS on 2026-08-25 -- see
   scratch/encode-compat/TWO_SIDED.txt for the RED leg's exact error.

   So this control DELETES INFORMATION in the required sense: revert the body and
   it goes RED for the declared reason.  It is not a restatement of the definition;
   it is the exact premise text the headline family used to carry. *)
require import AllCore.
require import SPHINCS_PLUS.
require import WOTS_C_Real.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.

lemma ENCODE_COMPAT_IS_DERIVABLE :
  forall (p : pseed) (a : adrs) (x : dgstblock) (cc : cntr),
    encode_msgWOTS_C p a x cc = encode_msgWOTS (ThC p a x cc).
proof. by move=> p a x cc; rewrite /encode_msgWOTS_C. qed.
