import C10Probability.GrindInterface

/-! Request contexts for the actual private R derivation. A fixed-width message
and counter make the optional-randomness/message boundary unambiguous. The
history predicate records origins; it does not assume independent replies. -/
namespace C10Probability
noncomputable section

abbrev RContext := ByteKey × ByteKey

def validRContext (context : RContext) : Prop :=
  context.2.length = 32 ∧ (context.1.length = 0 ∨ context.1.length = 16)

def rContextTail (context : RContext) (nonce : Counter) : ByteKey :=
  counterKey (rTailStem context.1 context.2) nonce

theorem r_context_tail_parts (context : RContext) (nonce : Counter) :
    rContextTail context nonce =
      [82, 95, 103, 114, 105, 110, 100] ++ context.1 ++ context.2 ++
        List.ofFn (counterBytes nonce) := by
  exact rfl

theorem r_context_tail_length (context : RContext) (nonce : Counter) :
    (rContextTail context nonce).length = 39 + context.1.length + context.2.length := by
  simp [rContextTail, counter_key_length, rTailStem, rGrindTag]
  omega

theorem r_context_tail_width (context : RContext) (nonce : Counter)
    (valid : validRContext context) :
    (rContextTail context nonce).length = 71 ∨
      (rContextTail context nonce).length = 87 := by
  rw [r_context_tail_length]
  rcases valid with ⟨message, random | random⟩ <;> simp [message, random]

theorem r_context_tail_injective (left right : RContext) (a b : Counter)
    (leftMessage : left.2.length = 32) (rightMessage : right.2.length = 32)
    (equal : rContextTail left a = rContextTail right b) :
    left = right ∧ a = b := by
  have lengths := congrArg List.length equal
  rw [r_context_tail_length, r_context_tail_length] at lengths
  have randomWidths : left.1.length = right.1.length := by omega
  have stemWidths : (rTailStem left.1 left.2).length =
      (rTailStem right.1 right.2).length := by
    simp [rTailStem, leftMessage, rightMessage, randomWidths]
  change rTailStem left.1 left.2 ++ List.ofFn (counterBytes a) =
    rTailStem right.1 right.2 ++ List.ofFn (counterBytes b) at equal
  have stems := List.append_inj_left equal stemWidths
  have counters := List.append_inj_right equal stemWidths
  have fields : left.1 ++ left.2 = right.1 ++ right.2 := by
    apply List.append_cancel_left (as := rGrindTag)
    simpa only [rTailStem, List.append_assoc] using stems
  exact ⟨Prod.ext (List.append_inj_left fields randomWidths)
    (List.append_inj_right fields randomWidths),
    counter_bytes_injective (List.ofFn_injective counters)⟩

theorem r_context_distinct_tails (left right : RContext) (a b : Counter)
    (leftValid : validRContext left) (rightValid : validRContext right)
    (distinct : left ≠ right) : rContextTail left a ≠ rContextTail right b := by
  intro equal
  exact distinct (r_context_tail_injective left right a b leftValid.1 rightValid.1 equal).1

theorem r_context_tail_counter_injective (context : RContext) :
    Function.Injective (rContextTail context) := by
  exact counter_key_injective (rTailStem context.1 context.2)

theorem r_context_schedule_origin (context : RContext) (start n : ℕ)
    (bound : start + n ≤ 2 ^ 32) (key : ByteKey)
    (member : key ∈ counterSchedule (rTailStem context.1 context.2) start n bound) :
    ∃ nonce : Counter, key = rContextTail context nonce ∧
      start ≤ nonce.val ∧ nonce.val < start + n := by
  obtain ⟨i, rfl⟩ := List.mem_ofFn.mp member
  refine ⟨⟨start + i.val, by omega⟩, rfl, ?_, ?_⟩
  · change start ≤ start + i.val
    omega
  · change start + i.val < start + n
    omega

def RContextHistory (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) : Prop :=
  ∀ context nonce value, validRContext context →
    table (.inr (rContextTail context nonce)) = some value → context ∈ contexts

theorem r_context_history_empty :
    RContextHistory ∅ (fun _ => none) := by
  intro context nonce value valid stored
  cases stored

theorem r_context_history_mono (before after : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (subset : before ⊆ after)
    (history : RContextHistory before table) : RContextHistory after table := by
  intro context nonce value valid stored
  exact subset (history context nonce value valid stored)

theorem r_context_unseen_fresh (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : RContextHistory contexts table)
    (context : RContext) (valid : validRContext context) (unseen : context ∉ contexts)
    (nonce : Counter) : table (.inr (rContextTail context nonce)) = none := by
  cases stored : table (.inr (rContextTail context nonce)) with
  | none => rfl
  | some value => exact False.elim (unseen (history context nonce value valid stored))

theorem r_context_unseen_schedule_fresh (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (history : RContextHistory contexts table)
    (context : RContext) (valid : validRContext context) (unseen : context ∉ contexts)
    (start n : ℕ) (bound : start + n ≤ 2 ^ 32) :
    ∀ key ∈ counterSchedule (rTailStem context.1 context.2) start n bound,
      table (.inr key) = none := by
  intro key member
  obtain ⟨nonce, rfl, _, _⟩ := r_context_schedule_origin context start n bound key member
  exact r_context_unseen_fresh contexts table history context valid unseen nonce

end
end C10Probability
