import C10Probability.TargetSet

/-! The public node is exactly the first16 big-endian digest bytes. The zero
sentinel event is a stored node, not a zero full digest or a low-half test. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def nodeBytes (digest : Digest) : RandomizerBytes :=
  fun i => bytesDigestEquiv.symm digest ⟨i.val, by omega⟩

def nodeZero (digest : Digest) : Bool := decide (nodeBytes digest = fun _ => 0)

def PublicNodeZero (table : Memo ByteKey Digest) : Prop :=
  ∃ (key : ByteKey) (digest : Digest), table key = some digest ∧ nodeZero digest = true

theorem node_bytes_projection (digest : Digest) :
    nodeBytes digest = randomizerBytesEquiv.symm (randomizerOfDigest digest) := by
  funext i
  exact (randomizer_digest_byte digest i).symm

theorem zero_randomizer_bytes :
    randomizerBytesEquiv.symm (0 : Randomizer) = fun _ => 0 := by
  funext i
  apply Fin.ext
  simp [randomizer_byte_value]

theorem node_zero_iff (digest : Digest) :
    nodeZero digest = true ↔ randomizerOfDigest digest = 0 := by
  simp only [nodeZero, decide_eq_true_eq]
  change nodeBytes digest = (fun _ => 0) ↔ randomizerOfDigest digest = 0
  rw [node_bytes_projection, ← zero_randomizer_bytes]
  exact randomizerBytesEquiv.symm.injective.eq_iff

theorem node_zero_targets : nodeZero = inTargets randomizerOfDigest {0} := by
  funext digest
  apply Bool.eq_iff_iff.mpr
  simp only [node_zero_iff, inTargets, decide_eq_true_eq, Finset.mem_singleton]

theorem public_node_zero_iff (table : Memo ByteKey Digest) :
    PublicNodeZero table ↔ ¬ NoTarget nodeZero table := by
  classical
  simp [PublicNodeZero, NoTarget, Bool.not_eq_false]

theorem node_zero_mass : acceptMass digestDraw nodeZero = ((2 : ℝ≥0∞) ^ 128)⁻¹ := by
  rw [node_zero_targets, projected_target_mass digestDraw randomizerOfDigest randomizer_uniform]
  simp only [Finset.card_singleton, Nat.cast_one, Fintype.card_fin, Nat.cast_pow,
    Nat.cast_ofNat, one_div]

theorem digest_program_zero_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | PublicNodeZero out.2} ≤ (n : ℝ≥0∞) / (2 : ℝ≥0∞) ^ 128 := by
  simpa only [← public_node_zero_iff, node_zero_mass, div_eq_mul_inv] using
    randomizedProgram_target_bound digestDraw nodeZero client (fun _ => none)
      (noTarget_empty nodeZero)

theorem digest_program_zero_bound_real {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram ByteKey Digest R n)) :
    ((randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | PublicNodeZero out.2}).toReal ≤ (n : ℝ) / (2 : ℝ) ^ 128 := by
  simpa only [← public_node_zero_iff, node_zero_mass, ENNReal.toReal_inv,
    ENNReal.toReal_pow, ENNReal.toReal_ofNat, div_eq_mul_inv] using
      randomizedProgram_target_bound_real digestDraw nodeZero client (fun _ => none)
        (noTarget_empty nodeZero)

theorem node_zero_low_bit : nodeZero 1 = true := by
  rw [node_zero_iff]
  apply Fin.ext
  exact randomizer_low_bit_dropped

theorem node_zero_retained_bit : nodeZero ⟨2 ^ 128, by decide⟩ = false := by
  apply Bool.eq_false_iff.mpr
  simp only [ne_eq, node_zero_iff]
  intro h
  have hv := congrArg Fin.val h
  rw [randomizer_first_retained_bit] at hv
  contradiction

end
end C10Probability
