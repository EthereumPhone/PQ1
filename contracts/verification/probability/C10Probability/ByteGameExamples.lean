import C10Probability.ByteForgeBound
import C10Probability.ByteSessionExamples
import C10Probability.SignatureCodecExamples
import C10Probability.ForgeNumeric

/-! An inhabited cached byte-game witness and the existing kernel-checked
numerical bounds on arbitrary finite byte clients. The cached witness does not
claim that its populated table is an initialized random-oracle history. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def byteExampleSignature : ByteKey :=
  wireEncode (wireSignatureFromStructured sessionExampleSignature session_example_signature_shape)

theorem byte_example_decode : c10DecodeSignature byteExampleSignature = some sessionExampleSignature := by
  have roundtrip := c10_signature_decode_encode sessionExampleSignature session_example_signature_shape
  rw [c10_encode_signature_wellformed _ session_example_signature_shape, Option.bind_some] at roundtrip
  exact roundtrip

theorem byte_game_cached_initialized_accept (cfg : C10SessionConfig) (publicSeed : Digest) :
    c10ByteGame id cfg publicSeed (fun _ _ =>
      (.done (List.replicate 32 0, byteExampleSignature) : C10ByteClient C10ByteForgery 0))
      0 0 (fun _ => some (2 ^ 128)) = PMF.pure (true, fun _ => some (2 ^ 128)) := by
  have decoded : byteForgeryToStructured (List.replicate 32 0, byteExampleSignature) =
      (List.replicate 32 0, sessionExampleSignature) :=
    byte_forgery_decoded _ _ _ byte_example_decode
  have translated : byteAdversaryToStructured (fun _ _ =>
      (.done (List.replicate 32 0, byteExampleSignature) : C10ByteClient C10ByteForgery 0)) =
      (fun _ _ => (.done (List.replicate 32 0, sessionExampleSignature) : C10Client C10Forgery 0)) := by
    funext seed root
    exact congrArg C10Client.done decoded
  have execution := session_cached_initialized_accept cfg publicSeed
  rw [← translated] at execution
  exact (c10_byte_game_refinement id cfg publicSeed _ 0 0 _).symm.trans execution

theorem byte_game_bad_final_retains_keygen [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) (table : Memo K Digest) :
    c10ByteGame encode cfg publicSeed
      (fun _ _ => (.done (List.replicate 32 0, []) : C10ByteClient C10ByteForgery 0)) 0 0 table =
      (c10Keygen encode table publicSeed).map (fun key => (false, key.2)) := by
  rw [c10ByteGame, PMF.map]
  apply pmf_bind_support_congr
  intro key _
  rw [c10ByteDriver, c10ByteSession, PMF.pure_bind]
  apply c10_byte_final_bad_length
  change (0 : ℕ) ≠ 4008
  decide

theorem c10_byte_forge_example_small {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) :
    (c10ByteInitializedShared forgeExampleConfig sampler (2 ^ 20) 65536).toOuterMeasure {true} <
      (1 : ℝ≥0∞) / 2 ^ 50 := by
  exact (c10_byte_shared_forge_bound forgeExampleConfig sampler (2 ^ 20) 65536).trans_lt
    forge_example_charge_small

theorem c10_byte_forge_example_medium {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) :
    (c10ByteInitializedShared forgeExampleConfig sampler (2 ^ 24) 65536).toOuterMeasure {true} <
      (1 : ℝ≥0∞) / 2 ^ 34 := by
  exact (c10_byte_shared_forge_bound forgeExampleConfig sampler (2 ^ 24) 65536).trans_lt
    forge_example_charge_medium

end
end C10Probability
