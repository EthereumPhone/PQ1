import C10Probability.ObservedForestOpening

/-! Concrete boundary witnesses for node decoding, the bounded target universe,
full-digest projection, successful releases and finite final candidates. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def malformedNodeInput : ByteKey :=
  List.ofFn (randomizerBytesEquiv.symm (1 : Randomizer)) ++ List.replicate 16 255

theorem malformed_node_candidate_counted :
    decodeNodeSlot malformedNodeInput = some 1 ∧
    variableCandidate nodeQueryDecode fixedNodeCandidates (.inl malformedNodeInput) = true ∧
    malformedNodeInput ≠ nodeBlock 1 := by decide +kernel

theorem short_node_candidate_excluded :
    decodeNodeSlot (List.replicate 31 255) = none ∧
    decodeNodeSlot (List.replicate 32 255) = some allFFNode := by decide +kernel

theorem full_digest_node_projection_example :
    randomizerOfDigest (0 : Digest) = randomizerOfDigest (1 : Digest) ∧
    (0 : Digest) ≠ 1 ∧ randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel

theorem fors_coordinate_boundaries_example :
    forsTargetKey ((0 : Fin (2 ^ 18)), (0 : Fin 12), (0 : Fin 2048)) ≠
      forsTargetKey ((131072 : Fin (2 ^ 18)), (0 : Fin 12), (0 : Fin 2048)) ∧
    forsTargetKey ((0 : Fin (2 ^ 18)), (11 : Fin 12), (2047 : Fin 2048)) ≠
      Sum.inr (forsPrivateTail 0 12 2047) ∧
    forsTargetKey ((0 : Fin (2 ^ 18)), (0 : Fin 12), (0 : Fin 2048)) ≠
      Sum.inr (forsPrivateTail 0 0 2048) := by decide +kernel

theorem fors_unbounded_encoding_alias_example :
    forsPrivateTail 0 0 0 = forsPrivateTail (2 ^ 32) 0 0 := by decide +kernel

theorem fors_selected_release_opens (secret : Digest) (table : Memo WotsQuery Digest) :
    evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ReleaseOpening 0 ⟨[none], [], 0⟩ (some ([], 0))) table false =
        PMF.pure ⟨some ⟨0, [randomizerOfDigest secret], [], []⟩, table, true⟩ := by
  simp [c10ReleaseOpening, evalOpening, c10FinishOutput, deferredForestOutput, deferredNode]

theorem fors_known_release_unopened (secret : Digest) (table : Memo WotsQuery Digest) :
    evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ReleaseOpening 0 ⟨[some 7], [], 0⟩ (some ([], 0))) table false =
        PMF.pure ⟨some ⟨0, [7], [], []⟩, table, false⟩ := by
  simp [c10ReleaseOpening, evalOpening, c10FinishOutput, deferredForestOutput, deferredNode]

theorem fors_empty_cache_not_selected (target : ForsTarget) (out : C10ObservedGame)
    (cfg : C10SessionConfig) :
    (out, fun _ => none) ∉ observedSelectedOpening target cfg := by
  simp [observedSelectedOpening, selectedOpeningEvent]

theorem fors_returned_not_selected (target : ForsTarget) (out : C10ObservedGame)
    (cfg : C10SessionConfig) (table : Memo WotsQuery Digest)
    (returned : ForsReturned target (sessionConfigAt cfg out.key) out.driver.session.exposures table) :
    (out, table) ∉ observedSelectedOpening target cfg := by
  simp [observedSelectedOpening, selectedOpeningEvent, returned]

theorem fors_missing_final_candidates (out : C10ObservedGame)
    (empty : out.driver.session.session.value.2.secrets = []) :
    forgedForsCandidates out = {0} := by
  ext value
  simp [forgedForsCandidates, empty, eq_comm]

theorem fors_zero_signature_charge (cfg : C10SessionConfig) (qr : ℕ) :
    forsOpeningCharge cfg qr 0 = ((177524 + qr : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  unfold forsOpeningCharge
  simp only [Nat.zero_mul, Nat.add_zero]
  apply min_eq_right
  apply ENNReal.div_le_div_right
  exact_mod_cast (show 177524 + qr ≤ 177526 + qr by omega)

theorem fors_one_signature_charge (cfg : C10SessionConfig) :
    forsOpeningCharge cfg 0 1 = (585934 : ℝ≥0∞) / 2 ^ 128 := by
  norm_num only [forsOpeningCharge, Nat.one_mul, Nat.add_zero]
  apply min_eq_left
  apply ENNReal.div_le_div_right
  exact_mod_cast (show 585934 ≤ 177524 + (sessionSignCost cfg + 1) by
    unfold sessionSignCost
    omega)

end
end C10Probability
