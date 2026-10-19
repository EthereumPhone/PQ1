import C10Probability.ForsTarget

/-! The actual two-layer WOTS address universe: every lower tree/leaf pair,
every upper leaf in tree zero, and all43chains. Protected cuts are0through6;
the public endpoint7 is excluded. Field equality uses explicit encoding bounds. -/
namespace C10Probability
noncomputable section

abbrev WotsLogicalAddress := Sum (Fin 512 × Fin 512) (Fin 512)
abbrev WotsTarget := WotsLogicalAddress × Fin 43
abbrev WotsCutTarget := WotsTarget × Fin 7

def wotsTargetLayer (target : WotsTarget) : ℕ :=
  match target.1 with | .inl _ => 0 | .inr _ => 1

def wotsTargetTree (target : WotsTarget) : ℕ :=
  match target.1 with | .inl lower => lower.1.val | .inr _ => 0

def wotsTargetKp (target : WotsTarget) : ℕ :=
  match target.1 with | .inl lower => lower.2.val | .inr upper => upper.val

def wotsTargetKey (target : WotsTarget) : WotsQuery :=
  .inr (wotsPrivateTail (wotsTargetLayer target) (wotsTargetTree target)
    (wotsTargetKp target) target.2.val)

theorem wots_target_bounds (target : WotsTarget) :
    wotsTargetLayer target < 2 ∧ wotsTargetTree target < 512 ∧
      wotsTargetKp target < 512 ∧ target.2.val < 43 := by
  rcases target with ⟨lower | upper, index⟩
  · exact ⟨by change 0 < 2; decide, lower.1.isLt, lower.2.isLt, index.isLt⟩
  · exact ⟨by change 1 < 2; decide, by change 0 < 512; decide, upper.isLt, index.isLt⟩

theorem wots_target_fields_injective (first second : WotsTarget)
    (layer : wotsTargetLayer first = wotsTargetLayer second)
    (tree : wotsTargetTree first = wotsTargetTree second)
    (kp : wotsTargetKp first = wotsTargetKp second)
    (index : first.2 = second.2) : first = second := by
  rcases first with ⟨a | a, i⟩ <;> rcases second with ⟨b | b, j⟩
  · exact Prod.ext (congrArg Sum.inl (Prod.ext (Fin.ext tree) (Fin.ext kp))) index
  · cases layer
  · cases layer
  · exact Prod.ext (congrArg Sum.inr (Fin.ext kp)) index

theorem be_bytes_thirty_two_injective {a b : ℕ} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32)
    (equal : beBytes 32 a = beBytes 32 b) : a = b := by
  have digit (i : Fin 32) : a / 256 ^ (32 - 1 - i.val) % 256 =
      b / 256 ^ (32 - 1 - i.val) % 256 := by
    have field := congrArg (fun bytes : ByteKey => ((bytes[i.val]?).getD 0).val) equal
    dsimp only at field
    rw [List.getElem?_eq_getElem (by simpa only [be_bytes_length] using i.isLt),
      List.getElem?_eq_getElem (by simpa only [be_bytes_length] using i.isLt)] at field
    change ((beBytes 32 a).get ⟨i.val, by simpa only [be_bytes_length] using i.isLt⟩).val =
      ((beBytes 32 b).get ⟨i.val, by simpa only [be_bytes_length] using i.isLt⟩).val at field
    rw [be_bytes_get, be_bytes_get] at field
    exact field
  have h0 := digit ⟨28, by decide⟩
  have h1 := digit ⟨29, by decide⟩
  have h2 := digit ⟨30, by decide⟩
  have h3 := digit ⟨31, by decide⟩
  norm_num at h0 h1 h2 h3
  omega

theorem wots_private_tail_fields (layer tree kp index layer' tree' kp' index' : ℕ)
    (equal : wotsPrivateTail layer tree kp index = wotsPrivateTail layer' tree' kp' index') :
    beBytes 4 layer = beBytes 4 layer' ∧ beBytes 32 tree = beBytes 32 tree' ∧
      beBytes 4 kp = beBytes 4 kp' ∧ beBytes 4 index = beBytes 4 index' := by
  have field (offset width : ℕ) := congrArg
    (fun bytes : ByteKey => (bytes.drop offset).take width) equal
  refine ⟨?_, ?_, ?_, ?_⟩
  · simpa [wotsPrivateTail, wotsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 4 4
  · simpa [wotsPrivateTail, wotsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 8 32
  · simpa [wotsPrivateTail, wotsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 40 4
  · simpa [wotsPrivateTail, wotsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 44 4

theorem wots_target_key_injective : Function.Injective wotsTargetKey := by
  intro first second equal
  have fields := wots_private_tail_fields _ _ _ _ _ _ _ _ (Sum.inr.inj equal)
  have hf := wots_target_bounds first
  have hs := wots_target_bounds second
  apply wots_target_fields_injective first second
  · exact be_bytes_four_injective (by omega) (by omega) fields.1
  · exact be_bytes_thirty_two_injective (by omega) (by omega) fields.2.1
  · exact be_bytes_four_injective (by omega) (by omega) fields.2.2.1
  · exact Fin.ext (be_bytes_four_injective (by omega) (by omega) fields.2.2.2)

theorem wots_target_card : Fintype.card WotsTarget = 11294208 := by
  simp [WotsTarget, WotsLogicalAddress]

theorem wots_cut_target_card : Fintype.card WotsCutTarget = 79059456 := by
  simp [WotsCutTarget]

theorem wots_target_not_public (target : WotsTarget) (key : ByteKey) :
    (.inl key : WotsQuery) ≠ wotsTargetKey target := by
  simp [wotsTargetKey]

theorem wots_target_not_fors (target : WotsTarget) (ht tree leaf : ℕ) :
    (.inr (forsPrivateTail ht tree leaf) : WotsQuery) ≠ wotsTargetKey target := by
  intro equal
  have widths := congrArg List.length (Sum.inr.inj equal)
  simp only [fors_private_tail_length, wots_private_tail_length] at widths
  omega

end
end C10Probability
