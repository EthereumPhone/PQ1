import C10Probability.RContextReplay
import C10Probability.RPublicHistory

/-! A new request context derives fresh private inputs from history origins;
an accepted old context replays. Only the former pays the independent-label
exhaustion plus public-history/birthday charge. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def rExhaustionCharge (history trials : ℕ) : ℝ≥0∞ :=
  rejectMass digestDraw (forsAccept ∘ forsOfDigest) ^ trials +
    (collisionPairs history trials : ℝ≥0∞) / 2 ^ 128

theorem r_exhaustion_charge_mono (before after trials : ℕ) (bound : before ≤ after) :
    rExhaustionCharge before trials ≤ rExhaustionCharge after trials := by
  unfold rExhaustionCharge
  apply add_le_add le_rfl
  apply ENNReal.div_le_div_right
  exact_mod_cast Nat.add_le_add_right (Nat.mul_le_mul_left trials bound) (trials.choose 2)

theorem r_private_fresh_result (table : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (fresh : ∀ key ∈ counterSchedule (rTailStem context.1 context.2) 0 n bound,
      table (.inr key) = none) :
    (privateRandomizerSearch table context.1 context.2 seed root n bound).map
      (fun out => forgetLabel out.1) =
      (randomMemoGrind (randomizerDraw.map (Sum.inl ∘ hmsgRandomizerInput seed root context.2))
        digestDraw (forsAccept ∘ forsOfDigest) table 0 n).map Prod.fst := by
  let hidden : Sum ByteKey ByteKey → Bool := fun key =>
    match key with | .inl _ => false | .inr _ => true
  have distinct := List.Nodup.map (Sum.inr_injective : Function.Injective
      (Sum.inr : ByteKey → Sum ByteKey ByteKey))
    (counter_schedule_nodup (rTailStem context.1 context.2) 0 n bound)
  have absent : ∀ key ∈ (counterSchedule (rTailStem context.1 context.2) 0 n bound).map Sum.inr,
      table key = none := by
    intro key member
    obtain ⟨original, present, rfl⟩ := List.mem_map.mp member
    exact fresh original present
  have privateKeys : ∀ key ∈
      (counterSchedule (rTailStem context.1 context.2) 0 n bound).map Sum.inr,
      hidden key = true := by
    intro key member
    obtain ⟨original, _, rfl⟩ := List.mem_map.mp member
    rfl
  simpa only [privateRandomizerSearch, randomizerDraw, List.length_map,
    counter_schedule_length] using derivedMemoGrind_result digestDraw randomizerOfDigest
      (Sum.inl ∘ hmsgRandomizerInput seed root context.2) (forsAccept ∘ forsOfDigest)
      hidden (fun _ => rfl) table 0 _ distinct absent privateKeys

theorem r_private_fresh_none (table : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (fresh : ∀ key ∈ counterSchedule (rTailStem context.1 context.2) 0 n bound,
      table (.inr key) = none) :
    ((privateRandomizerSearch table context.1 context.2 seed root n bound).map Prod.fst) none =
      ((randomMemoGrind (randomizerDraw.map (Sum.inl ∘ hmsgRandomizerInput seed root context.2))
        digestDraw (forsAccept ∘ forsOfDigest) table 0 n).map Prod.fst) none := by
  have equality := congrArg (fun p => p none)
    (r_private_fresh_result table context seed root n bound fresh)
  rw [← forgetLabel_none_mass
    ((privateRandomizerSearch table context.1 context.2 seed root n bound).map Prod.fst)]
  simpa only [PMF.map_comp, Function.comp_def] using equality

theorem r_private_fresh_exhaustion (table : Memo (Sum ByteKey ByteKey) Digest)
    (context : RContext) (seed root : ByteKey) (n : ℕ) (bound : 0 + n ≤ 2 ^ 32)
    (fresh : ∀ key ∈ counterSchedule (rTailStem context.1 context.2) 0 n bound,
      table (.inr key) = none) :
    ((privateRandomizerSearch table context.1 context.2 seed root n bound).map Prod.fst) none ≤
      rExhaustionCharge
        (embeddedHistory table (Sum.inl ∘ hmsgRandomizerInput seed root context.2)).card n := by
  rw [r_private_fresh_none table context seed root n bound fresh]
  have injective : Function.Injective (Sum.inl ∘ hmsgRandomizerInput seed root context.2 :
      Randomizer → Sum ByteKey ByteKey) := by
    intro left right equal
    exact hmsg_randomizer_injective seed root context.2 (Sum.inl.inj equal)
  have result := (randomMemo_event_bounds digestDraw (forsAccept ∘ forsOfDigest) table
    (Sum.inl ∘ hmsgRandomizerInput seed root context.2) injective
    (embeddedHistory table (Sum.inl ∘ hmsgRandomizerInput seed root context.2))
    (embeddedHistory_covers table (Sum.inl ∘ hmsgRandomizerInput seed root context.2))
    0 n {none}).1
  simpa only [randomizer_uniform, PMF.toOuterMeasure_apply_singleton, grind_none,
    Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat, rExhaustionCharge] using result

theorem r_context_exhaustion_bound (contexts : Finset RContext)
    (table : Memo (Sum ByteKey ByteKey) Digest) (context : RContext)
    (valid : validRContext context) (seed root : ByteKey)
    (n : ℕ) (bound : 0 + n ≤ 2 ^ 32) (historyBudget : ℕ)
    (origins : RContextHistory contexts table)
    (accepted : AcceptedRContexts contexts table seed root n bound)
    (publicHistory : BoundedRPublicHistory historyBudget table) :
    ((privateRandomizerSearch table context.1 context.2 seed root n bound).map Prod.fst) none ≤
      rExhaustionCharge historyBudget n := by
  classical
  by_cases old : context ∈ contexts
  · rw [accepted_r_context_has_no_exhaustion contexts table seed root n bound accepted context old]
    exact zero_le _
  · exact (r_private_fresh_exhaustion table context seed root n bound
      (r_context_unseen_schedule_fresh contexts table origins context valid old 0 n bound)).trans
      (r_exhaustion_charge_mono _ historyBudget n
        (bounded_r_public_history_hmsg_card historyBudget table publicHistory seed root context.2))

end
end C10Probability
