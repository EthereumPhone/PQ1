/- Actual public-key root against the existing shared functional tree value.
   This retains the supplied hash interpretation and callback-free extraction. -/
import Extracted.C10FunctionalBuilders
import Extracted.C10FunctionalSigner

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalWots Extracted.C10FunctionalTrees
open Extracted.C10FunctionalBuildValues
open Extracted.C10FunctionalSignerValues Extracted.C10FunctionalSignatureBytes
open Extracted.C10FunctionalBuilders
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.C10FunctionalKeygen

theorem extracted_public_root (secret : Std.Array Std.U8 32#usize)
    (seed : Std.Array Std.U8 16#usize) :
    sphincs_c10.hypertree.compute_pk_root secret seed ⦃ root =>
      byteInts root.val = merkle_root_value suppliedBackend
        (byteInts (pad16Pure seed).val) (byteInts secret.val) 1 0 ⦄ := by
  let* ⟨root, hr⟩ ← Equiv.xmss_compute_pk_root_spec secret seed
  rw [hr, merkle_node_value _ _ _ _ 9 0 (by decide) (by decide),
    merkle_root_value, root_eq_node, pad16p_eq]
  rfl

/-- Initialization uses the root actually computed by the extracted keygen.
    The following release call retains every bounded failure in its Result. -/
theorem initialized_release_bytes (secret message : Std.Array Std.U8 32#usize)
    (seed : Std.Array Std.U8 16#usize) (random : Option (Std.Array Std.U8 16#usize))
    (progress : sphincs_c10.hypertree.ProgressSink) (shuffle : sphincs_c10.shuffle.ShuffleSeed) :
    (do let root ← sphincs_c10.hypertree.compute_pk_root secret seed
        let sig ← sphincs_c10.hypertree.release_sign_inner secret seed root message random progress shuffle
        .ok (signatureBytes sig)) =
      (do let words ← signerResult suppliedBackend (byteInts (pad16Pure seed).val)
            (pad_node (merkle_root_value suppliedBackend (byteInts (pad16Pure seed).val)
              (byteInts secret.val) 1 0))
            (byteInts secret.val) (byteInts (optionalBytes random))
            (byteInts message.val)
          .ok (encodeWords words)) := by
  obtain ⟨root,hr,hvalue⟩ := WP.spec_imp_exists (extracted_public_root secret seed)
  rw [hr]
  simp only [bind_tc_ok]
  rw [C10FunctionalSigner.extracted_signer_bytes, pad_node_value root, hvalue]

end Extracted.C10FunctionalKeygen
