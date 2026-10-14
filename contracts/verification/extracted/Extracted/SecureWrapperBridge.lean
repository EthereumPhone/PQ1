/- Instantiate the explicit wrapper dependencies with the already-extracted
   release signer and raw Rust verifier. This is model composition, not proof
   of physical backends or of the source-lifting/callback interpretation. -/
import Extracted.SecureWrapperSpec
import Extracted.SignReleaseBridge
import Extracted.WholeVerifierSpec
open Aeneas Aeneas.Std Result
namespace secure_wrapper_model
noncomputable section
open Extracted.Equiv

/-- Keep the environmental inputs explicit; replace only the signer/verifier
    oracles with the actual extracted functions and their existing models. -/
def firmwareBackend (b : Backend) : Backend :=
  { b with
    sign := fun sk seed root msg opt shuffle =>
      _root_.sphincs_c10.hypertree.release_sign_inner sk seed root msg opt () shuffle
    verify := _root_.sphincs_c10.hypertree.verify }

/-- Every successful wrapper return contains bytes from the release signer,
    independent of either shuffle, and passes the faithful raw Rust verifier.
    The raw verifier's zero-node continuation is retained; this theorem does
    not assert the converse refinement to the strict byte verifier. -/
theorem wrapper_firmware_release (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress
      ⟨firmwareBackend b,[],0,0,0⟩ = .ok (.Ok sig,out)) :
    ∃ opt, pureReleaseSign sk.sk_seed msg sk.pk_seed sk.pk_root (some opt) = .ok sig ∧
      rawVerifierResult sk.pk_seed sk.pk_root msg sig = true ∧
      ∀ shuffle, _root_.sphincs_c10.hypertree.release_sign_inner
        sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) () shuffle = .ok sig := by
  obtain ⟨opt,sha,shb,prior,actual,expected,_,_,_,ha,_,hv,_⟩ :=
    wrapper_entry_success_certificate sk msg progress _ out sig h
  change _root_.sphincs_c10.hypertree.release_sign_inner
    sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) () sha = .ok sig at ha
  change _root_.sphincs_c10.hypertree.verify sk.pk_seed sk.pk_root msg sig = .ok true at hv
  rw [firmware_sign_release_pure] at ha
  obtain ⟨v,hr,he⟩ := WP.spec_imp_exists
    (firmware_verify_raw_result sk.pk_seed sk.pk_root msg sig)
  rw [hv] at hr
  cases hr
  refine ⟨opt,ha,he.symm,?_⟩
  intro shuffle
  rw [firmware_sign_release_pure]
  exact ha

end
end secure_wrapper_model
