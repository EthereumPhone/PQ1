import Std

/-!
Value-level transcription of the pinned Eager buffer branches, followed by
history and integer-length composition. This file is NOT extracted Rust, and
does not prove the pointer, constructor, callback or cross-tool interpretation.
The theorem assumptions describe valid entry data, not desired step results.
-/
namespace StreamingHistory

structure Step (α : Type) where
  emitted : List α
  residual : List α
  newBlocks : Nat

def split (input : List α) : Step α :=
  let n := input.length / 64
  ⟨input.take (n * 64), input.drop (n * 64), n⟩

def step (buffered input : List α) : Step α :=
  let rem := 64 - buffered.length
  if input.length < rem then
    ⟨[], buffered ++ input, 0⟩
  else if buffered.isEmpty then
    split input
  else
    let tail := input.drop rem
    let s := split tail
    ⟨buffered ++ input.take rem ++ s.emitted, s.residual, 1 + s.newBlocks⟩

theorem split_conserves (input : List α) :
    (split input).emitted ++ (split input).residual = input := by
  exact List.take_append_drop _ input

theorem split_emitted_length (input : List α) :
    (split input).emitted.length = 64 * (split input).newBlocks := by
  have h := Nat.div_mul_le_self input.length 64
  simp only [split, List.length_take]
  rw [Nat.min_eq_left h, Nat.mul_comm]

theorem split_residual_length (input : List α) :
    (split input).residual.length = input.length % 64 := by
  simp only [split, List.length_drop]
  omega

theorem split_residual_bound (input : List α) :
    (split input).residual.length < 64 := by
  rw [split_residual_length]
  exact Nat.mod_lt _ (by decide)

theorem step_conserves (buffered input : List α) :
    (step buffered input).emitted ++ (step buffered input).residual =
      buffered ++ input := by
  by_cases h : input.length < 64 - buffered.length
  · simp [step, h]
  · by_cases e : buffered.isEmpty = true
    · have hb : buffered = [] := List.isEmpty_iff.mp e
      simp only [step, h, e, ↓reduceIte]
      simpa only [hb, List.nil_append] using split_conserves input
    · simp only [step, h, e, Bool.false_eq_true, ↓reduceIte, List.append_assoc]
      rw [split_conserves, List.take_append_drop]

theorem step_residual_bound (buffered input : List α)
    (valid : buffered.length < 64) :
    (step buffered input).residual.length < 64 := by
  by_cases h : input.length < 64 - buffered.length
  · simp only [step, h, ↓reduceIte, List.length_append]
    omega
  · by_cases e : buffered.isEmpty = true
    · simpa only [step, h, e, Bool.false_eq_true, ↓reduceIte] using split_residual_bound input
    · simpa only [step, h, e, Bool.false_eq_true, ↓reduceIte] using
        split_residual_bound (input.drop (64 - buffered.length))

theorem step_emitted_length (buffered input : List α)
    (valid : buffered.length < 64) :
    (step buffered input).emitted.length = 64 * (step buffered input).newBlocks := by
  by_cases h : input.length < 64 - buffered.length
  · simp [step, h]
  · by_cases e : buffered.isEmpty = true
    · simpa only [step, h, e, Bool.false_eq_true, ↓reduceIte] using split_emitted_length input
    · have hr : 64 - buffered.length ≤ input.length := by omega
      simp only [step, h, e, Bool.false_eq_true, ↓reduceIte, List.length_append, List.length_take,
        Nat.min_eq_left hr, split_emitted_length]
      omega

theorem step_length_conservation (buffered input : List α)
    (valid : buffered.length < 64) :
    64 * (step buffered input).newBlocks + (step buffered input).residual.length =
      buffered.length + input.length := by
  have h := congrArg List.length (step_conserves buffered input)
  simpa only [List.length_append, step_emitted_length buffered input valid] using h

theorem step_count_exact (buffered input : List α)
    (valid : buffered.length < 64) :
    (step buffered input).newBlocks = (buffered.length + input.length) / 64 := by
  have hc := step_length_conservation buffered input valid
  have hr := step_residual_bound buffered input valid
  omega

theorem step_residual_exact (buffered input : List α)
    (valid : buffered.length < 64) :
    (step buffered input).residual.length = (buffered.length + input.length) % 64 := by
  have hc := step_length_conservation buffered input valid
  have hr := step_residual_bound buffered input valid
  omega

structure State (α : Type) where
  emitted : List α
  buffered : List α
  blocks : Nat

def Valid (s : State α) : Prop :=
  s.emitted.length = 64 * s.blocks ∧ s.buffered.length < 64

def advance (s : State α) (input : List α) : State α :=
  let out := step s.buffered input
  ⟨s.emitted ++ out.emitted, out.residual, s.blocks + out.newBlocks⟩

def run (s : State α) : List (List α) → State α
  | [] => s
  | input :: rest => run (advance s input) rest

theorem advance_valid (s : State α) (input : List α) (valid : Valid s) :
    Valid (advance s input) := by
  obtain ⟨he, hb⟩ := valid
  constructor
  · simp only [advance, List.length_append, he, step_emitted_length _ _ hb]
    omega
  · exact step_residual_bound _ _ hb

theorem advance_conserves (s : State α) (input : List α) :
    (advance s input).emitted ++ (advance s input).buffered =
      (s.emitted ++ s.buffered) ++ input := by
  simp only [advance, List.append_assoc, step_conserves]

theorem run_valid (s : State α) (inputs : List (List α)) (valid : Valid s) :
    Valid (run s inputs) := by
  induction inputs generalizing s with
  | nil => exact valid
  | cons input rest ih => exact ih _ (advance_valid s input valid)

theorem run_conserves (s : State α) (inputs : List (List α)) :
    (run s inputs).emitted ++ (run s inputs).buffered =
      (s.emitted ++ s.buffered) ++ inputs.flatten := by
  induction inputs generalizing s with
  | nil => simp [run]
  | cons input rest ih =>
      simp only [run, ih, advance_conserves, List.flatten_cons, List.append_assoc]

theorem run_length_conservation (s : State α) (inputs : List (List α))
    (valid : Valid s) :
    64 * (run s inputs).blocks + (run s inputs).buffered.length =
      s.emitted.length + s.buffered.length + inputs.flatten.length := by
  have hc := congrArg List.length (run_conserves s inputs)
  have hv := (run_valid s inputs valid).1
  simpa only [List.length_append, hv] using hc

theorem run_count_exact (s : State α) (inputs : List (List α))
    (valid : Valid s) :
    (run s inputs).blocks =
      (s.emitted.length + s.buffered.length + inputs.flatten.length) / 64 := by
  have hc := run_length_conservation s inputs valid
  have hr := (run_valid s inputs valid).2
  omega

theorem run_residual_exact (s : State α) (inputs : List (List α))
    (valid : Valid s) :
    (run s inputs).buffered.length =
      (s.emitted.length + s.buffered.length + inputs.flatten.length) % 64 := by
  have hc := run_length_conservation s inputs valid
  have hr := (run_valid s inputs valid).2
  omega

theorem run_append (s : State α) (left right : List (List α)) :
    run s (left ++ right) = run (run s left) right := by
  induction left generalizing s with
  | nil => rfl
  | cons input rest ih => exact ih (advance s input)

def initial : State α := ⟨[], [], 0⟩

theorem initial_valid : Valid (initial : State α) := by
  simp [Valid, initial]

theorem initialized_history (inputs : List (List α)) :
    let out := run initial inputs
    out.emitted ++ out.buffered = inputs.flatten ∧
    out.blocks = inputs.flatten.length / 64 ∧
    out.buffered.length = inputs.flatten.length % 64 := by
  exact ⟨by simpa [initial] using run_conserves initial inputs,
         by simpa [initial] using run_count_exact initial inputs initial_valid,
         by simpa [initial] using run_residual_exact initial inputs initial_valid⟩

theorem run_prefix (s : State α) (inputs : List (List α)) :
    (run s inputs).emitted =
      ((s.emitted ++ s.buffered) ++ inputs.flatten).take (run s inputs).emitted.length := by
  rw [← run_conserves s inputs, List.take_left]

theorem run_suffix (s : State α) (inputs : List (List α)) :
    (run s inputs).buffered =
      ((s.emitted ++ s.buffered) ++ inputs.flatten).drop (run s inputs).emitted.length := by
  rw [← run_conserves s inputs, List.drop_left]

theorem run_canonical_prefix (s : State α) (inputs : List (List α))
    (valid : Valid s) :
    (run s inputs).emitted =
      ((s.emitted ++ s.buffered) ++ inputs.flatten).take
        (64 * ((s.emitted.length + s.buffered.length + inputs.flatten.length) / 64)) := by
  rw [run_prefix s inputs, (run_valid s inputs valid).1, run_count_exact s inputs valid]

theorem run_canonical_suffix (s : State α) (inputs : List (List α))
    (valid : Valid s) :
    (run s inputs).buffered =
      ((s.emitted ++ s.buffered) ++ inputs.flatten).drop
        (64 * ((s.emitted.length + s.buffered.length + inputs.flatten.length) / 64)) := by
  rw [run_suffix s inputs, (run_valid s inputs valid).1, run_count_exact s inputs valid]

theorem state_ext (s t : State α) (he : s.emitted = t.emitted)
    (hb : s.buffered = t.buffered) (hc : s.blocks = t.blocks) : s = t := by
  cases s
  cases t
  simp_all

/-- Any segmentation of the same bytes yields the same modeled state. -/
theorem run_segmentation (s : State α) (left right : List (List α))
    (valid : Valid s) (same : left.flatten = right.flatten) :
    run s left = run s right := by
  apply state_ext
  · rw [run_canonical_prefix s left valid, run_canonical_prefix s right valid, same]
  · rw [run_canonical_suffix s left valid, run_canonical_suffix s right valid, same]
  · rw [run_count_exact s left valid, run_count_exact s right valid, same]

/- Checked u64 operations make overflow refusal explicit. These are mathematical
   operator models, not extracted Rust methods or a replacement hash backend. -/
def checkedAdd (a b : UInt64) : Option UInt64 :=
  if a.toNat + b.toNat < 2^64 then some (a + b) else none

def checkedMul (a b : UInt64) : Option UInt64 :=
  if a.toNat * b.toNat < 2^64 then some (a * b) else none

def bitLength (blocks pos : UInt64) : Option UInt64 := do
  let complete ← checkedMul 64 blocks
  let total ← checkedAdd pos complete
  checkedMul 8 total

theorem checkedAdd_ofNat (a b : Nat) (bound : a + b < 2^64) :
    checkedAdd (UInt64.ofNat a) (UInt64.ofNat b) = some (UInt64.ofNat (a + b)) := by
  have ha : a < UInt64.size := by change a < 2^64; omega
  have hb : b < UInt64.size := by change b < 2^64; omega
  simp only [checkedAdd, UInt64.toNat_ofNat_of_lt' ha,
    UInt64.toNat_ofNat_of_lt' hb, ite_eq_left bound, UInt64.ofNat_add]

theorem checkedMul_ofNat (a b : Nat) (ha : a < 2^64) (hb : b < 2^64)
    (bound : a * b < 2^64) :
    checkedMul (UInt64.ofNat a) (UInt64.ofNat b) = some (UInt64.ofNat (a * b)) := by
  simp only [checkedMul, UInt64.toNat_ofNat_of_lt' ha,
    UInt64.toNat_ofNat_of_lt' hb, ite_eq_left bound, UInt64.ofNat_mul]

theorem bitLength_exact (blocks pos : Nat) (bound : 64 * blocks + pos < 2^61) :
    bitLength (UInt64.ofNat blocks) (UInt64.ofNat pos) =
      some (UInt64.ofNat (8 * (64 * blocks + pos))) := by
  have hb : blocks < 2^64 := by omega
  have hp : pos < 2^64 := by omega
  have hc : 64 * blocks < 2^64 := by omega
  have ht : pos + 64 * blocks < 2^64 := by omega
  have hl : 8 * (pos + 64 * blocks) < 2^64 := by omega
  unfold bitLength
  rw [show (64 : UInt64) = UInt64.ofNat 64 by decide,
      show (8 : UInt64) = UInt64.ofNat 8 by decide]
  rw [checkedMul_ofNat 64 blocks (by decide) hb hc]
  simp only [Option.bind_eq_bind, Option.bind_some]
  rw [checkedAdd_ofNat pos (64 * blocks) ht]
  simp only [Option.bind_some]
  rw [checkedMul_ofNat 8 (pos + 64 * blocks) (by decide) ht hl]
  rw [Nat.add_comm pos]

theorem bitLength_value_exact (blocks pos : Nat)
    (bound : 64 * blocks + pos < 2^61) :
    (bitLength (UInt64.ofNat blocks) (UInt64.ofNat pos)).map UInt64.toNat =
      some (8 * (64 * blocks + pos)) := by
  rw [bitLength_exact blocks pos bound]
  simp only [Option.map_some]
  rw [UInt64.toNat_ofNat_of_lt' (by change 8 * (64 * blocks + pos) < 2^64; omega)]

theorem advance_counter_checked (s : State α) (input : List α)
    (valid : Valid s) (bound : 64 * s.blocks + s.buffered.length + input.length < 2^61) :
    checkedAdd (UInt64.ofNat s.blocks) (UInt64.ofNat (step s.buffered input).newBlocks) =
      some (UInt64.ofNat (advance s input).blocks) := by
  have hc := step_length_conservation s.buffered input valid.2
  apply checkedAdd_ofNat
  omega

theorem partial_counter_checked (s : State α) (input : List α) (portion : Nat)
    (valid : Valid s) (bound : 64 * s.blocks + s.buffered.length + input.length < 2^61)
    (part : portion ≤ (step s.buffered input).newBlocks) :
    checkedAdd (UInt64.ofNat s.blocks) (UInt64.ofNat portion) =
      some (UInt64.ofNat (s.blocks + portion)) := by
  have hc := step_length_conservation s.buffered input valid.2
  apply checkedAdd_ofNat
  omega

theorem history_bitLength (s : State α) (inputs : List (List α))
    (valid : Valid s)
    (bound : s.emitted.length + s.buffered.length + inputs.flatten.length < 2^61) :
    (bitLength (UInt64.ofNat (run s inputs).blocks)
      (UInt64.ofNat (run s inputs).buffered.length)).map UInt64.toNat =
        some (8 * (s.emitted.length + s.buffered.length + inputs.flatten.length)) := by
  have hc := run_length_conservation s inputs valid
  have hb : 64 * (run s inputs).blocks + (run s inputs).buffered.length < 2^61 := by omega
  rw [bitLength_value_exact _ _ hb, hc]

theorem initialized_history_bitLength (inputs : List (List α))
    (bound : inputs.flatten.length < 2^61) :
    (bitLength (UInt64.ofNat (run initial inputs).blocks)
      (UInt64.ofNat (run initial inputs).buffered.length)).map UInt64.toNat =
        some (8 * inputs.flatten.length) := by
  simpa only [initial, List.length_nil, Nat.zero_add] using
    history_bitLength initial inputs initial_valid (by simpa [initial] using bound)

/-- Every update counter fits if the entire history fits the byte bound. -/
theorem history_update_checked (s : State α) (earlier suffix : List (List α))
    (input : List α) (valid : Valid s)
    (bound : s.emitted.length + s.buffered.length +
      (earlier ++ input :: suffix).flatten.length < 2^61) :
    checkedAdd (UInt64.ofNat (run s earlier).blocks)
      (UInt64.ofNat (step (run s earlier).buffered input).newBlocks) =
        some (UInt64.ofNat (advance (run s earlier) input).blocks) := by
  have hc := run_length_conservation s earlier valid
  simp only [List.flatten_append, List.flatten_cons, List.length_append] at bound
  apply advance_counter_checked _ _ (run_valid s earlier valid)
  omega

/-- Final-history bounds justify the length encoding of every earlier. -/
theorem history_prefix_bitLength (s : State α) (earlier suffix : List (List α))
    (valid : Valid s)
    (bound : s.emitted.length + s.buffered.length +
      (earlier ++ suffix).flatten.length < 2^61) :
    (bitLength (UInt64.ofNat (run s earlier).blocks)
      (UInt64.ofNat (run s earlier).buffered.length)).map UInt64.toNat =
        some (8 * (s.emitted.length + s.buffered.length + earlier.flatten.length)) := by
  simp only [List.flatten_append, List.length_append] at bound
  apply history_bitLength s earlier valid
  omega

theorem last_representable_length :
    (bitLength (UInt64.ofNat (2^55 - 1)) 63).map UInt64.toNat = some (2^64 - 8) := by
  decide

theorem first_overflowing_length :
    bitLength (UInt64.ofNat (2^55)) 0 = none := by
  decide

#print axioms split_conserves
#print axioms split_emitted_length
#print axioms split_residual_length
#print axioms split_residual_bound
#print axioms step_conserves
#print axioms step_residual_bound
#print axioms step_emitted_length
#print axioms step_length_conservation
#print axioms step_count_exact
#print axioms step_residual_exact
#print axioms advance_valid
#print axioms advance_conserves
#print axioms run_valid
#print axioms run_conserves
#print axioms run_length_conservation
#print axioms run_count_exact
#print axioms run_residual_exact
#print axioms run_append
#print axioms initial_valid
#print axioms initialized_history
#print axioms run_prefix
#print axioms run_suffix
#print axioms run_canonical_prefix
#print axioms run_canonical_suffix
#print axioms state_ext
#print axioms run_segmentation
#print axioms checkedAdd_ofNat
#print axioms checkedMul_ofNat
#print axioms bitLength_exact
#print axioms bitLength_value_exact
#print axioms advance_counter_checked
#print axioms partial_counter_checked
#print axioms history_bitLength
#print axioms initialized_history_bitLength
#print axioms history_update_checked
#print axioms history_prefix_bitLength
#print axioms last_representable_length
#print axioms first_overflowing_length

end StreamingHistory
