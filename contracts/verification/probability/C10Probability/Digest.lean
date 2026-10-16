import C10Probability.Uniform
import C10Probability.Projections
import Mathlib.Algebra.BigOperators.Fin

/-! Full 256-bit digest projections with explicit byte/integer formulas.
This does not identify a concrete hash call with a fresh uniform draw. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev Digest := Fin (2 ^ 256)
abbrev DigestBytes := Fin 32 → Fin 256

def digestDraw : PMF Digest := PMF.uniformOfFintype Digest

def reverseBytes : DigestBytes ≃ DigestBytes where
  toFun b i := b i.rev
  invFun b i := b i.rev
  left_inv b := by funext i; simp
  right_inv b := by funext i; simp

/-- The last byte is least significant, as in the deployed digest integer. -/
def bytesDigestEquiv : DigestBytes ≃ Digest :=
  reverseBytes.trans (finFunctionFinEquiv.trans (finCongr (by norm_num)))

theorem bytes_digest_value (b : DigestBytes) :
    (bytesDigestEquiv b).val = ∑ i : Fin 32, (b i.rev).val * 256 ^ i.val := by rfl

theorem digest_byte_value (d : Digest) (i : Fin 32) :
    (bytesDigestEquiv.symm d i).val = d.val / 256 ^ (31 - i.val) % 256 := by
  change d.val / 256 ^ i.rev.val % 256 = _
  simp only [Fin.val_rev]
  congr 3; omega

theorem digest_bytes_roundtrip (d : Digest) :
    bytesDigestEquiv (bytesDigestEquiv.symm d) = d := by
  exact bytesDigestEquiv.apply_symm_apply d

theorem bytes_digest_roundtrip (b : DigestBytes) :
    bytesDigestEquiv.symm (bytesDigestEquiv b) = b := by
  exact bytesDigestEquiv.symm_apply_apply b

theorem bytes_uniform_digest :
    (PMF.uniformOfFintype DigestBytes).map bytesDigestEquiv = digestDraw := by
  exact uniform_map_equiv bytesDigestEquiv

theorem last_byte_is_low :
    (bytesDigestEquiv (fun i => if i.val = 31 then 1 else 0)).val = 1 := by decide

theorem first_byte_is_high :
    (bytesDigestEquiv (fun i => if i.val = 0 then 1 else 0)).val = 2 ^ 248 := by decide

/-- The complete low 129-bit block; 127 bits remain outside this projection. -/
def wotsBlock (d : Digest) : Fin (8 ^ 43) :=
  radixField (2 ^ 127) (8 ^ 43) 1 ((finCongr (by norm_num)) d)

def wotsOfDigest (d : Digest) : WotsWord := finFunctionFinEquiv.symm (wotsBlock d)

theorem wots_block_value (d : Digest) : (wotsBlock d).val = d.val % 8 ^ 43 := by
  simp only [wotsBlock, radixField_value, finCongr_apply, Fin.val_cast, Nat.div_one]

theorem radix_digit_after_mod (base count i value : ℕ) (hi : i < count) :
    (value % base ^ count / base ^ i) % base = value / base ^ i % base := by
  have hp : base ^ count = base ^ i * base ^ (count - i) := by
    rw [← pow_add]; congr 1; omega
  have hd : base ∣ base ^ (count - i) := by
    simpa using (Nat.pow_dvd_pow base (show 1 ≤ count - i by omega))
  rw [hp, Nat.mod_mul_right_div_self, Nat.mod_mod_of_dvd _ hd]

/-- Same per-chain quotient/remainder expression as the deployed integer spec. -/
theorem wots_digest_digit (d : Digest) (i : Fin 43) :
    (wotsOfDigest d i).val = d.val / 2 ^ (3 * i.val) % 8 := by
  change ((wotsBlock d).val / 8 ^ i.val) % 8 = _
  rw [wots_block_value, radix_digit_after_mod 8 43 i.val d.val i.isLt]
  congr 2
  rw [show (8 : ℕ) = 2 ^ 3 by decide, ← pow_mul]

theorem digest_uniform_wots_block : digestDraw.map wotsBlock =
    PMF.uniformOfFintype (Fin (8 ^ 43)) := by
  have h := congrArg (PMF.map (radixField (2 ^ 127) (8 ^ 43) 1))
    (uniform_map_equiv (finCongr (show 2 ^ 256 = 2 ^ 127 * 8 ^ 43 * 1 by norm_num)))
  rw [uniform_radixField] at h
  simpa only [PMF.map_comp, Function.comp_def, wotsBlock, digestDraw] using h

theorem digest_uniform_wots : digestDraw.map wotsOfDigest = wotsDraw := by
  have h := congrArg (PMF.map (finFunctionFinEquiv (m := 8) (n := 43)).symm)
    digest_uniform_wots_block
  rw [uniform_map_equiv] at h
  simpa only [PMF.map_comp, Function.comp_def, wotsOfDigest, wotsDraw] using h

/-- The FORS acceptance field begins at bit132 and has width11. -/
def forsOfDigest (d : Digest) : ForsField :=
  radixField (2 ^ 113) 2048 (2 ^ 132) ((finCongr (by norm_num)) d)

theorem fors_digest_field (d : Digest) :
    (forsOfDigest d).val = d.val / 2 ^ 132 % 2048 := by rfl

theorem digest_uniform_fors : digestDraw.map forsOfDigest = forsDraw := by
  have h := congrArg (PMF.map (radixField (2 ^ 113) 2048 (2 ^ 132)))
    (uniform_map_equiv (finCongr (show 2 ^ 256 = 2 ^ 113 * 2048 * 2 ^ 132 by norm_num)))
  rw [uniform_radixField] at h
  simpa only [PMF.map_comp, Function.comp_def, forsOfDigest, digestDraw, forsDraw] using h

/-- Bit128 is consumed, despite the 128-bit node width. -/
theorem wots_129th_bit :
    (wotsOfDigest ⟨2 ^ 128, by decide⟩ 42).val = 4 := by decide

theorem wots_first_unused_bit :
    (wotsOfDigest ⟨2 ^ 129, by decide⟩ 42).val = 0 := by decide

theorem fors_first_bit :
    (forsOfDigest ⟨2 ^ 132, by decide⟩).val = 1 := by decide

theorem fors_last_bit :
    (forsOfDigest ⟨2 ^ 142, by decide⟩).val = 1024 := by decide

theorem fors_below_field :
    (forsOfDigest ⟨2 ^ 131, by decide⟩).val = 0 := by decide

theorem fors_above_field :
    (forsOfDigest ⟨2 ^ 143, by decide⟩).val = 0 := by decide

end
end C10Probability
