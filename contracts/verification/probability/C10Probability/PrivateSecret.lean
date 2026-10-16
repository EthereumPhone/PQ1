import C10Probability.PrivateTransfer
import C10Probability.SecretPrefix

/-! The concrete one-secret, 32-byte private-prefix interface. These are
manually transcribed byte formulas, not a translation of the complete C10
keygen/sign/adversary program. The shared and independent executions are the
full interpreters; no freshness or successful-signing premise is imposed. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def prefixedPrivateInput (secret : Digest) (tail : ByteKey) : ByteKey :=
  secretBytes secret ++ tail

theorem prefixedPrivateInput_decodes (secret : Digest) (tail : ByteKey) :
    decodeSecretPrefix (prefixedPrivateInput secret tail) = some secret :=
  decodeSecretPrefix_secret secret tail

theorem prefixedPrivateInput_injective (secret : Digest) :
    Function.Injective (prefixedPrivateInput secret) := by
  intro first second he
  exact List.append_cancel_left he

theorem prefixedPrivateInput_r (secret : Digest) (random message : ByteKey) (nonce : Counter) :
    rDerivationInput (secretBytes secret) random message nonce =
      prefixedPrivateInput secret (rGrindTag ++ random ++ message ++ List.ofFn (counterBytes nonce)) := by
  simp only [prefixedPrivateInput, rDerivationInput, counterKey, rInputStem, List.append_assoc]

theorem private_secret_event_bounds {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q) (event : Set R) :
    (privateShared digestDraw digestDraw prefixedPrivateInput client).toOuterMeasure event ≤
      (privateIndependent digestDraw client).toOuterMeasure event + (q : ℝ≥0∞) / 2 ^ 256 ∧
    (privateIndependent digestDraw client).toOuterMeasure event ≤
      (privateShared digestDraw digestDraw prefixedPrivateInput client).toOuterMeasure event +
        (q : ℝ≥0∞) / 2 ^ 256 := by
  simpa only [digestDraw, Digest, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    private_event_bounds digestDraw prefixedPrivateInput decodeSecretPrefix
      prefixedPrivateInput_decodes prefixedPrivateInput_injective client q budget event

theorem private_secret_event_error_real {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram (Sum ByteKey ByteKey) Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, PublicBudget program q) (event : Set R) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput client).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw client).toOuterMeasure event).toReal| ≤ (q : ℝ) / 2 ^ 256 := by
  simpa only [digestDraw, Digest, Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    private_event_error_real digestDraw prefixedPrivateInput decodeSecretPrefix
      prefixedPrivateInput_decodes prefixedPrivateInput_injective client q budget event

end
end C10Probability
