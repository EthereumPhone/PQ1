import C10Probability.RandomGrind

/-! Event bounds for the online memoized loop. Equality away from schedule
collisions is discharged by the fresh-schedule theorem, not assumed as a
probability bound. Independent source keys and initial-history coverage remain
explicit inputs to this comparison experiment. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {α β K L : Type*}

theorem event_mass_le_one (p : PMF α) (event : Set α) : p.toOuterMeasure event ≤ 1 := by
  rw [PMF.toOuterMeasure_apply, ← p.tsum_coe]
  apply ENNReal.tsum_le_tsum
  intro x
  exact Set.indicator_apply_le (fun _ => le_rfl)

theorem event_mass_ne_top (p : PMF α) (event : Set α) : p.toOuterMeasure event ≠ ⊤ := by
  exact ne_top_of_le_ne_top ENNReal.one_ne_top (event_mass_le_one p event)

/-- Generic mixture comparison, using equality on every supported good index.
The bad-event charge is the actual index-distribution probability. -/
theorem mixture_event_le (q : PMF β) (f g : β → PMF α) (bad : β → Bool)
    (heq : ∀ b ∈ q.support, bad b = false → f b = g b) (event : Set α) :
    (q.bind f).toOuterMeasure event ≤
      (q.bind g).toOuterMeasure event + (q.map bad) true := by
  rw [PMF.toOuterMeasure_bind_apply, PMF.toOuterMeasure_bind_apply,
    PMF.map_apply, ← ENNReal.tsum_add]
  apply ENNReal.tsum_le_tsum
  intro b
  by_cases hs : b ∈ q.support
  · cases hb : bad b
    · simp [heq b hs hb]
    · simp only [↓reduceIte]
      calc
        _ ≤ q b * 1 := mul_le_mul_right (event_mass_le_one (f b) event) (q b)
        _ ≤ _ := by simp only [mul_one]; exact le_add_left le_rfl
  · have hz : q b = 0 := (q.apply_eq_zero_iff b).mpr hs
    simp [hz]

theorem mixture_event_bounds (q : PMF β) (f g : β → PMF α) (bad : β → Bool)
    (heq : ∀ b ∈ q.support, bad b = false → f b = g b) (event : Set α) :
    (q.bind f).toOuterMeasure event ≤ (q.bind g).toOuterMeasure event + (q.map bad) true ∧
    (q.bind g).toOuterMeasure event ≤ (q.bind f).toOuterMeasure event + (q.map bad) true := by
  exact ⟨mixture_event_le q f g bad heq event,
    mixture_event_le q g f bad (fun b hb hg => (heq b hb hg).symm) event⟩

/-- The exact preimage of the cache is finite because the source alphabet is
finite. It supplies a concrete history-coverage witness for any starting table. -/
def embeddedHistory [Fintype K] (table : Memo L α) (embed : K → L) : Finset K :=
  Finset.univ.filter fun key => (table (embed key)).isSome

theorem embeddedHistory_covers [Fintype K] (table : Memo L α) (embed : K → L) :
    ∀ key, key ∉ embeddedHistory table embed → table (embed key) = none := by
  intro key hk
  simpa [embeddedHistory] using hk

theorem embeddedHistory_empty [Fintype K] (embed : K → L) :
    embeddedHistory (fun _ => (none : Option α)) embed = ∅ := by
  simp [embeddedHistory]


variable [Fintype K] [Nonempty K] [DecidableEq K] [DecidableEq L]

theorem embedded_schedule_fresh (p : PMF α) (accept : α → Bool)
    (table : Memo L α) (embed : K → L) (hinj : Function.Injective embed)
    (seen : Finset K) (cover : ∀ key, key ∉ seen → table (embed key) = none)
    (start n : ℕ) (keys : List K)
    (hs : keys ∈ (drawList (PMF.uniformOfFintype K) n).support)
    (hg : collisionScan seen keys = false) :
    (memoGrind p accept table start (keys.map embed)).map Prod.fst =
      grind p accept start n := by
  obtain ⟨hd, hf⟩ := (collisionScan_false seen keys).mp hg
  have h := memoGrind_fresh p accept table start (keys.map embed) (List.Nodup.map hinj hd)
    (by
      intro key hk
      obtain ⟨source, hsource, rfl⟩ := List.mem_map.mp hk
      exact cover source (hf source hsource))
  simpa only [List.length_map, drawList_length _ n keys hs] using h

/-- Uniform source keys may be encoded injectively into a larger shared key
space. `seen` must cover every initially cached key in that encoded domain. -/
theorem randomMemo_event_bounds (p : PMF α) (accept : α → Bool)
    (table : Memo L α) (embed : K → L) (hinj : Function.Injective embed)
    (seen : Finset K) (cover : ∀ key, key ∉ seen → table (embed key) = none)
    (start n : ℕ) (event : Set (Option (ℕ × α))) :
    ((randomMemoGrind ((PMF.uniformOfFintype K).map embed) p accept table start n).map
      Prod.fst).toOuterMeasure event ≤ (grind p accept start n).toOuterMeasure event +
        (collisionPairs seen.card n : ℝ≥0∞) / Fintype.card K ∧
    (grind p accept start n).toOuterMeasure event ≤
      ((randomMemoGrind ((PMF.uniformOfFintype K).map embed) p accept table start n).map
        Prod.fst).toOuterMeasure event +
          (collisionPairs seen.card n : ℝ≥0∞) / Fintype.card K := by
  have hm := mixture_event_bounds (drawList (PMF.uniformOfFintype K) n)
    (fun keys => (memoGrind p accept table start (keys.map embed)).map Prod.fst)
    (fun _ => grind p accept start n) (collisionScan seen)
    (embedded_schedule_fresh p accept table embed hinj seen cover start n) event
  rw [PMF.bind_const, drawList_collision] at hm
  rw [randomMemoGrind_embedded, PMF.map_bind]
  exact ⟨hm.1.trans (add_le_add le_rfl (key_collision_bound seen n)),
    hm.2.trans (add_le_add le_rfl (key_collision_bound seen n))⟩

theorem randomMemo_event_error_real (p : PMF α) (accept : α → Bool)
    (table : Memo L α) (embed : K → L) (hinj : Function.Injective embed)
    (seen : Finset K) (cover : ∀ key, key ∉ seen → table (embed key) = none)
    (start n : ℕ) (event : Set (Option (ℕ × α))) :
    |(((randomMemoGrind ((PMF.uniformOfFintype K).map embed) p accept table start n).map
      Prod.fst).toOuterMeasure event).toReal -
      ((grind p accept start n).toOuterMeasure event).toReal| ≤
        (collisionPairs seen.card n : ℝ) / Fintype.card K := by
  obtain ⟨hl, hr⟩ := randomMemo_event_bounds p accept table embed hinj seen cover start n event
  have hd : (collisionPairs seen.card n : ℝ≥0∞) / Fintype.card K ≠ ⊤ :=
    ENNReal.div_ne_top (by simp) (by simp)
  have hrealL := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hl
  have hrealR := ENNReal.toReal_mono
    (ENNReal.add_ne_top.mpr ⟨event_mass_ne_top _ _, hd⟩) hr
  rw [ENNReal.toReal_add (event_mass_ne_top _ _) hd] at hrealL hrealR
  simp only [ENNReal.toReal_div, ENNReal.toReal_natCast] at hrealL hrealR
  exact abs_sub_le_iff.mpr ⟨by linarith, by linarith⟩


end
end C10Probability
