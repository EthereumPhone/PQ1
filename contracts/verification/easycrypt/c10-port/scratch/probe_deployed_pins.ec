(* PROBE (not a control): are the deployed-parameter PREMISES of
   EUFCMA_SPHINCS_PLUS_C10_CHARGED_QWIRED_TIGHT_AT_DEPLOYED_PARAMS actually DERIVABLE
   in that lemma's own scope, from the axioms n_val/len_val/k_val in SPHINCS_PLUS.ec?
   Imports copied verbatim from GprocChargedQWired.ec. *)
require import AllCore.
require import SPHINCS_PLUS.
require import C10DeployedInstance.
require import WOTS_C_Real WOTS_C_Scheme XMSSMT_C_Scheme WOTS_C_Interactive.
import FSSLXMTWES.
import FSSLXMTWES.WTWES.
import WOTS_C_Real.
import WOTS_C_Scheme.
import EmsgWOTS.
import XMSSMT_C_Scheme.
import WOTS_C_Interactive.

lemma PROBE_n   : n   = c10_n.   proof. by rewrite n_val   /c10_n.   qed.
lemma PROBE_len : len = c10_len. proof. by rewrite len_val /c10_len. qed.
lemma PROBE_k   : k   = c10_k.   proof. by rewrite k_val   /c10_k.   qed.
