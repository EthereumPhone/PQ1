import C10Probability.NodeCommitment
import C10Probability.GrindInterface

/-! The ordinary FORS target universe retains every address, tree and leaf.
Byte equality is converted back to coordinate equality only under explicit
field bounds. The special thirteenth tree is outside this universe. -/
namespace C10Probability
noncomputable section

abbrev ForsTarget := Fin (2 ^ 18) × Fin 12 × Fin 2048

def forsTargetKey (target : ForsTarget) : WotsQuery :=
  .inr (forsPrivateTail target.1.val target.2.1.val target.2.2.val)

theorem be_bytes_four_injective {a b : ℕ} (ha : a < 2 ^ 32) (hb : b < 2 ^ 32)
    (equal : beBytes 4 a = beBytes 4 b) : a = b := by
  have digit (i : Fin 4) := congrArg
    (fun bytes : ByteKey => ((bytes[i.val]?).getD 0).val) equal
  have h0 := digit ⟨0, by decide⟩
  have h1 := digit ⟨1, by decide⟩
  have h2 := digit ⟨2, by decide⟩
  have h3 := digit ⟨3, by decide⟩
  norm_num [beBytes] at h0 h1 h2 h3
  omega

theorem fors_tail_fields (ht tree leaf ht' tree' leaf' : ℕ)
    (equal : forsPrivateTail ht tree leaf = forsPrivateTail ht' tree' leaf') :
    beBytes 4 ht = beBytes 4 ht' ∧ beBytes 4 tree = beBytes 4 tree' ∧
      beBytes 4 leaf = beBytes 4 leaf' := by
  have field (offset : ℕ) := congrArg (fun bytes : ByteKey => (bytes.drop offset).take 4) equal
  refine ⟨?_, ?_, ?_⟩
  · simpa [forsPrivateTail, forsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 4
  · simpa [forsPrivateTail, forsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 8
  · simpa [forsPrivateTail, forsTag, List.append_assoc, List.drop_append,
      List.take_append, be_bytes_length] using field 12

theorem fors_target_key_injective : Function.Injective forsTargetKey := by
  intro a b equal
  have fields := fors_tail_fields _ _ _ _ _ _ (Sum.inr.inj equal)
  have first := be_bytes_four_injective (a := a.1.val) (b := b.1.val)
    (by have := a.1.isLt; omega) (by have := b.1.isLt; omega) fields.1
  have second := be_bytes_four_injective (a := a.2.1.val) (b := b.2.1.val)
    (by have := a.2.1.isLt; omega) (by have := b.2.1.isLt; omega) fields.2.1
  have third := be_bytes_four_injective (a := a.2.2.val) (b := b.2.2.val)
    (by have := a.2.2.isLt; omega) (by have := b.2.2.isLt; omega) fields.2.2
  exact Prod.ext (Fin.ext first) (Prod.ext (Fin.ext second) (Fin.ext third))

theorem fors_target_card : Fintype.card ForsTarget = 6442450944 := by
  simp [ForsTarget]

theorem fors_target_not_public (target : ForsTarget) (key : ByteKey) :
    (.inl key : WotsQuery) ≠ forsTargetKey target := by
  simp [forsTargetKey]

theorem fors_target_not_wots (target : ForsTarget) (layer tree kp index : ℕ) :
    (.inr (wotsPrivateTail layer tree kp index) : WotsQuery) ≠ forsTargetKey target := by
  intro equal
  have lengths := congrArg List.length (Sum.inr.inj equal)
  simp only [wots_private_tail_length, fors_private_tail_length] at lengths
  omega

theorem fors_target_not_counter (target : ForsTarget) (stem : ByteKey) (nonce : Counter) :
    (.inr (counterKey stem nonce) : WotsQuery) ≠ forsTargetKey target := by
  intro equal
  have lengths := congrArg List.length (Sum.inr.inj equal)
  simp only [counterKey, List.length_append, List.length_ofFn,
    fors_private_tail_length] at lengths
  omega

theorem fors_target_not_last (target : ForsTarget) (ht leaf : ℕ) :
    (.inr (forsPrivateTail ht 12 leaf) : WotsQuery) ≠ forsTargetKey target := by
  intro equal
  have fields := fors_tail_fields _ _ _ _ _ _ (Sum.inr.inj equal)
  have trees := be_bytes_four_injective (by decide : 12 < 2 ^ 32)
    (by have := target.2.1.isLt; omega) fields.2.1
  have := target.2.1.isLt
  omega

end
end C10Probability
