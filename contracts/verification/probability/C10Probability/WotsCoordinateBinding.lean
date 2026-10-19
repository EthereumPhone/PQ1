import C10Probability.WotsCutInputs

/-! Concrete coordinate binding for the finite two-layer WOTS universe. Bounds
are supplied by the address types, so truncated byte fields are not treated as
injective over arbitrary naturals. -/
namespace C10Probability
noncomputable section

theorem be_bytes_eight_small_injective {a b : ℕ} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32)
    (equal : beBytes 8 a = beBytes 8 b) : a = b := by
  have digit (i : Fin 8) : a / 256 ^ (8 - 1 - i.val) % 256 =
      b / 256 ^ (8 - 1 - i.val) % 256 := by
    have field := congrArg (fun bytes : ByteKey => ((bytes[i.val]?).getD 0).val) equal
    dsimp only at field
    rw [List.getElem?_eq_getElem (by simpa only [be_bytes_length] using i.isLt),
      List.getElem?_eq_getElem (by simpa only [be_bytes_length] using i.isLt)] at field
    change ((beBytes 8 a).get ⟨i.val, by simpa only [be_bytes_length] using i.isLt⟩).val =
      ((beBytes 8 b).get ⟨i.val, by simpa only [be_bytes_length] using i.isLt⟩).val at field
    rw [be_bytes_get, be_bytes_get] at field
    exact field
  have h0 := digit ⟨4, by decide⟩
  have h1 := digit ⟨5, by decide⟩
  have h2 := digit ⟨6, by decide⟩
  have h3 := digit ⟨7, by decide⟩
  norm_num at h0 h1 h2 h3
  omega

theorem wots_address_fields (layer tree kp index pos layer' tree' kp' index' pos' : ℕ)
    (equal : c10Address layer tree 0 kp index pos 0 =
      c10Address layer' tree' 0 kp' index' pos' 0) :
    beBytes 4 layer = beBytes 4 layer' ∧ beBytes 8 tree = beBytes 8 tree' ∧
      beBytes 4 kp = beBytes 4 kp' ∧ beBytes 4 index = beBytes 4 index' := by
  have field (offset width : ℕ) := congrArg
    (fun bytes : ByteKey => (bytes.drop offset).take width) equal
  refine ⟨?_, ?_, ?_, ?_⟩
  · simpa [c10Address, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 0 4
  · simpa [c10Address, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 4 8
  · simpa [c10Address, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 16 4
  · simpa [c10Address, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 20 4

def wotsTargetInput (seed : ByteKey) (source : WotsTarget) (position : ℕ)
    (node : Randomizer) : WotsQuery :=
  .inl (wotsChainInput seed (wotsTargetLayer source) (wotsTargetTree source)
    (wotsTargetKp source) source.2.val position node)

theorem wots_target_input_binding (seed : ByteKey) (first second : WotsTarget)
    (pos pos' : ℕ) (node node' : Randomizer)
    (bound : pos < 2 ^ 32) (bound' : pos' < 2 ^ 32)
    (equal : wotsTargetInput seed first pos node = wotsTargetInput seed second pos' node') :
    first = second ∧ pos = pos' ∧ node = node' := by
  have parts := wots_chain_input_parts seed _ _ _ _ _ _ _ _ _ _ _ _ (Sum.inl.inj equal)
  have fields := wots_address_fields _ _ _ _ _ _ _ _ _ _ parts.1
  have hf := wots_target_bounds first
  have hs := wots_target_bounds second
  refine ⟨?_, wots_chain_input_position_eq seed _ _ _ _ _ _ _ _ _ _ _ _ bound bound'
    (Sum.inl.inj equal), parts.2⟩
  apply wots_target_fields_injective first second
  · exact be_bytes_four_injective (by omega) (by omega) fields.1
  · exact be_bytes_eight_small_injective (by omega) (by omega) fields.2.1
  · exact be_bytes_four_injective (by omega) (by omega) fields.2.2.1
  · exact Fin.ext (be_bytes_four_injective (by omega) (by omega) fields.2.2.2)

theorem wots_target_input_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget) (position : ℕ) (node : Randomizer)
    (bound : position < 2 ^ 32)
    (equal : wotsTargetInput seed source position node = wotsCutIncoming seed target previous) :
    source = target.1 ∧ position + 1 = target.2.val ∧ node = previous := by
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact (wots_target_not_public target.1 _ equal).elim
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    have binding := wots_target_input_binding seed source target.1 position
      (target.2.val - 1) node previous bound (by have := target.2.isLt; omega) equal
    exact ⟨binding.1, by omega, binding.2.2⟩

theorem wots_target_private_incoming (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (source : WotsTarget)
    (equal : wotsTargetKey source = wotsCutIncoming seed target previous) :
    source = target.1 ∧ target.2.val = 0 := by
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact ⟨wots_target_key_injective equal, zero⟩
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    cases equal

end
end C10Probability
