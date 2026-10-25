/- The actual sequential wrapper model composed with the shared functional
   release signer and raw verifier. Source lifting, callback noninterference
   and physical effects remain the existing explicit boundaries. -/
import Extracted.SecureWrapperBridge
import Extracted.SecureWrapperCost
import Extracted.C10FunctionalSigner

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalSignerValues
open Extracted.C10FunctionalSignatureBytes Extracted.C10FunctionalSigner

namespace secure_wrapper_model
noncomputable section

/-- A normal release retains its exact shared bytes, both actual signer
    calls, successful raw verification, and the two-sign/one-verify charge.
    The initial trace may already contain arbitrary events. -/
theorem wrapper_functional_release (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (before out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress
      {before with backend := firmwareBackend b} = .ok (.Ok sig,out)) :
    ∃ opt sha shb,
      _root_.sphincs_c10.hypertree.release_sign_inner sk.sk_seed sk.pk_seed sk.pk_root
        msg (some opt) () sha = .ok sig ∧
      _root_.sphincs_c10.hypertree.release_sign_inner sk.sk_seed sk.pk_seed sk.pk_root
        msg (some opt) () shb = .ok sig ∧
      (do let words ← signerResult suppliedBackend (byteInts (pad16Pure sk.pk_seed).val)
            (byteInts (pad16Pure sk.pk_root).val) (byteInts sk.sk_seed.val)
            (byteInts opt.val) (byteInts msg.val)
          .ok (encodeWords words)) = .ok (signatureBytes sig) ∧
      Extracted.C10FunctionalVerifier.verifierResult suppliedBackend
        (byteInts (pad16Pure sk.pk_seed).val) (byteInts (pad16Pure sk.pk_root).val)
        (byteInts msg.val) (word_decode (signatureBytes sig)) = true ∧
      traceCallCost 1 0 out.trace = traceCallCost 1 0 before.trace + 2 ∧
      traceCallCost 0 1 out.trace = traceCallCost 0 1 before.trace + 1 := by
  obtain ⟨opt,sha,shb,prior,actual,expected,_,_,_,ha,hb,hv,_⟩ :=
    wrapper_entry_success_certificate sk msg progress _ out sig h
  change _root_.sphincs_c10.hypertree.release_sign_inner
    sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) () sha = .ok sig at ha
  change _root_.sphincs_c10.hypertree.release_sign_inner
    sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) () shb = .ok sig at hb
  change _root_.sphincs_c10.hypertree.verify sk.pk_seed sk.pk_root msg sig = .ok true at hv
  have bytes := extracted_signer_bytes sk.sk_seed msg sk.pk_seed sk.pk_root (some opt) () sha
  rw [ha] at bytes
  obtain ⟨v,he,hvalue⟩ := WP.spec_imp_exists
    (Extracted.C10FunctionalVerifier.decoded_verifier_result sk.pk_seed sk.pk_root msg sig)
  rw [hv] at he
  cases he
  have counts := wrapper_entry_success_call_counts sk msg progress _ out sig h
  exact ⟨opt,sha,shb,ha,hb,bytes.symm,hvalue.symm,counts⟩

/-- Refusal is a normal result, whereas dependency failure/divergence lacks
    final effects. The existing call bound covers both normal outcomes. -/
theorem wrapper_functional_call_bounds (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (before out : Effects)
    (result : Aeneas.Std.core.result.Result Signature Unit)
    (h : production.c10_sign_verified_with_progress sk msg progress
      {before with backend := firmwareBackend b} = .ok (result,out)) :
    traceCallCost 1 0 before.trace ≤ traceCallCost 1 0 out.trace ∧
    traceCallCost 1 0 out.trace ≤ traceCallCost 1 0 before.trace + 2 ∧
    traceCallCost 0 1 before.trace ≤ traceCallCost 0 1 out.trace ∧
    traceCallCost 0 1 out.trace ≤ traceCallCost 0 1 before.trace + 1 := by
  simpa only using wrapper_entry_call_bounds sk msg progress
    {before with backend := firmwareBackend b} out result h

end
end secure_wrapper_model
