import C10Probability.WotsProbedBound

/-! An incoming public probe contains the preceding chain value. The actual
unreturned event therefore satisfies a finite recurrence over cuts0through6.
Every charge refers to the original probed game and its final cache. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def wotsPreviousCut (target : WotsCutTarget) : WotsCutTarget :=
  (target.1, ⟨target.2.val - 1, lt_of_le_of_lt (Nat.sub_le _ _) target.2.isLt⟩)

theorem wots_before_cut_previous (seed : ByteKey) (target : WotsCutTarget)
    (table : Memo WotsQuery Digest) (positive : 0 < target.2.val) :
    replayProgram table (wotsBeforeCutProgram seed target.1 target.2.val) =
      replayProgram table (wotsCutProgram seed (wotsPreviousCut target)) := by
  cases cut : target.2.val with
  | zero => omega
  | succ steps =>
    simp only [wotsCutProgram, wotsPreviousCut, cut, Nat.add_sub_cancel, wotsBeforeCutProgram]
    rw [cut, Nat.add_sub_cancel]

theorem wots_record_previous_exposes (target : WotsCutTarget) (record : C10SigningRecord)
    (exposed : WotsRecordExposes (wotsPreviousCut target) record) : WotsRecordExposes target record := by
  rcases exposed with lower | upper
  · exact Or.inl ⟨lower.1, le_trans lower.2 (Nat.sub_le _ _)⟩
  · exact Or.inr ⟨upper.1, le_trans upper.2 (Nat.sub_le _ _)⟩

theorem wots_returned_previous_mono (target : WotsCutTarget) (cfg : C10SessionConfig)
    (entries : List C10Exposure) (table : Memo WotsQuery Digest)
    (returned : WotsReturned (wotsPreviousCut target) cfg entries table) :
    WotsReturned target cfg entries table := by
  obtain ⟨entry, member, record, valid, exposed⟩ := returned
  exact ⟨entry, member, record, valid, wots_record_previous_exposes target record exposed⟩

theorem wots_probed_opening_split (seed : ByteKey) (target : WotsCutTarget) (cfg : C10SessionConfig)
    (qr : ℕ) (out : C10ProbedGame × Memo WotsQuery Digest)
    (length : (c10ProbeQueries out.1).length ≤ qr + 361)
    (member : out ∈ wotsProbedOpeningEvent seed target cfg qr) :
    out ∈ wotsProbedUnrevealedEvent seed target cfg qr ∨
      (0 < target.2.val ∧ out ∈ wotsProbedOpeningEvent seed (wotsPreviousCut target) cfg qr) := by
  obtain ⟨unreturned, value, recorded, candidate⟩ := member
  by_cases hit : WotsProbeHit seed target out.1 out.2
  · obtain ⟨positive, previous, previousReplay, queried⟩ := hit
    refine Or.inr ⟨positive, ?_, previous, ?_, ?_⟩
    · intro parentReturned
      exact unreturned (wots_returned_previous_mono target (sessionConfigAt cfg out.1.1.key)
        out.1.1.driver.session.exposures out.2 parentReturned)
    · rw [wots_before_cut_previous seed target out.2 positive] at previousReplay
      exact previousReplay
    · apply wots_probe_value_candidate (qr + 361) (wotsPreviousCut target).1.2 out.1 length
        (wotsCutIncoming seed target previous) previous queried
      rw [wots_cut_incoming_positive seed target previous positive]
      exact wots_chain_input_decodes seed _ _ _ _ _ previous
  · refine Or.inl ⟨?_, value, recorded, candidate⟩
    intro excluded
    exact excluded.elim unreturned hit

theorem wots_probed_opening_zero_bound (target : WotsCutTarget) (zero : target.2.val = 0)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
      (wotsProbedOpeningEvent (wotsGameSeed publicSeed) target cfg qr) ≤ wotsCutCharge qr qs := by
  refine le_trans ?_ (wots_probed_unrevealed_bound target cfg publicSeed adversary qr qs)
  apply PMF.toOuterMeasure_mono
  intro out member
  rcases wots_probed_opening_split (wotsGameSeed publicSeed) target cfg qr out
    (c10_probed_game_query_bound cfg publicSeed adversary qr qs (fun _ => none) out member.2) member.1 with
    unexposed | earlier
  · exact unexposed
  · have := earlier.1
    omega

theorem wots_probed_opening_step_bound (target : WotsCutTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
      (wotsProbedOpeningEvent (wotsGameSeed publicSeed) target cfg qr) ≤ wotsCutCharge qr qs +
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
      (wotsProbedOpeningEvent (wotsGameSeed publicSeed) (wotsPreviousCut target) cfg qr) := by
  let game := evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)
  calc
    _ ≤ game.toOuterMeasure (wotsProbedUnrevealedEvent (wotsGameSeed publicSeed) target cfg qr ∪
        wotsProbedOpeningEvent (wotsGameSeed publicSeed) (wotsPreviousCut target) cfg qr) := by
      apply PMF.toOuterMeasure_mono
      intro out member
      rcases wots_probed_opening_split (wotsGameSeed publicSeed) target cfg qr out
        (c10_probed_game_query_bound cfg publicSeed adversary qr qs (fun _ => none) out member.2) member.1 with
        unexposed | earlier
      · exact Or.inl unexposed
      · exact Or.inr earlier.2
    _ ≤ game.toOuterMeasure (wotsProbedUnrevealedEvent (wotsGameSeed publicSeed) target cfg qr) +
        game.toOuterMeasure (wotsProbedOpeningEvent (wotsGameSeed publicSeed) (wotsPreviousCut target) cfg qr) :=
      MeasureTheory.measure_union_le _ _
    _ ≤ _ := add_le_add (wots_probed_unrevealed_bound target cfg publicSeed adversary qr qs) le_rfl

theorem wots_probed_opening_bound (target : WotsCutTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
      (wotsProbedOpeningEvent (wotsGameSeed publicSeed) target cfg qr) ≤
        ((target.2.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs := by
  have allCuts : ∀ j, ∀ cut : Fin 7, cut.val = j →
      (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
        (wotsProbedOpeningEvent (wotsGameSeed publicSeed) (target.1, cut) cfg qr) ≤
          ((cut.val + 1 : ℕ) : ℝ≥0∞) * wotsCutCharge qr qs := by
    intro j
    induction j with
    | zero =>
      intro cut cutEq
      simpa only [cutEq, Nat.zero_add, Nat.cast_one, one_mul] using
        wots_probed_opening_zero_bound (target.1, cut) cutEq cfg publicSeed adversary qr qs
    | succ j ih =>
      intro cut cutEq
      have previous := ih (wotsPreviousCut (target.1, cut)).2
        (by simp only [wotsPreviousCut, cutEq, Nat.add_sub_cancel])
      have step := wots_probed_opening_step_bound (target.1, cut) cfg publicSeed adversary qr qs
      refine step.trans ?_
      have sum := add_le_add_left previous (wotsCutCharge qr qs)
      simpa only [wotsPreviousCut, cutEq, Nat.add_sub_cancel, Nat.cast_add, Nat.cast_one,
        add_mul, one_mul, add_assoc, add_comm, add_left_comm] using sum
  exact allCuts target.2.val target.2 rfl

end
end C10Probability
