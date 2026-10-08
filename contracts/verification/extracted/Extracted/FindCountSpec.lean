/- Functional correctness of the actual bounded WOTS count search.
   SHA uses the existing supplied backend; lean_extract erases progress
   callbacks. No probability of success, independence, or callback behavior
   is assumed or established here. -/
import Extracted.FindCount.Funs
import Extracted.PkFromSigSpec
import Extracted.WotsSpecBridge

open Aeneas Aeneas.Std Result ControlFlow
set_option maxRecDepth 4096
set_option maxHeartbeats 8000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

noncomputable def grindSum (d : Std.Array Std.U8 32#usize) : Nat :=
  ((List.range 43).map (wotsDigit d)).sum

noncomputable def grindAccept (seed adrs message : Std.Array Std.U8 32#usize)
    (count : Std.U32) : Prop :=
  grindSum (wots_digest_pure seed adrs message count) = 205

theorem grind_sum_loop_eq (iter : core.ops.range.Range Std.Usize)
    (digits : Std.Array Std.U8 43#usize) (sum : Std.Usize) :
    wots.find_count_loop0_loop0 iter digits sum =
      wots.pk_from_sig_loop0 iter digits sum := rfl

set_option maxHeartbeats 8000000 in
theorem grind_body_spec (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (count : Std.U32)
    (hcount : count.val < 10000000) :
    wots.find_count_loop0.body seed message progress pct adrs count
      ⦃ r =>
        (∃ digits, r = done (count, wots_digest_pure seed adrs message count, digits) ∧
          grindAccept seed adrs message count ∧
          ∀ j, j < 43 → (digits.val[j]!).val =
            wotsDigit (wots_digest_pure seed adrs message count) j) ∨
        (∃ next, r = cont next ∧ next.val = count.val + 1 ∧
          ¬ grindAccept seed adrs message count) ⦄ := by
  unfold wots.find_count_loop0.body
  simp only [params.L, params.TARGET_SUM]
  step
  let* ⟨d, hd⟩ ← hash.wots_digest_spec seed adrs message count
  let* ⟨digits, hdigits⟩ ← extract_digits_spec d
  rw [grind_sum_loop_eq]
  let* ⟨sum, hsum⟩ ← pk_loop0_value digits
    { start := 0#usize, «end» := 43#usize } 0#usize d hdigits rfl (by decide) (by simp)
  have heq : sum = 205#usize ↔ grindAccept seed adrs message count := by
    constructor
    · intro h
      have hv : sum.val = 205 := congrArg UScalar.val h
      rw [hsum, hd] at hv
      exact hv
    · intro h
      apply UScalar.eq_of_val_eq
      change sum.val = 205
      rw [hsum, hd]
      exact h
  split
  · rename_i h
    simp only [WP.spec_ok]
    exact Or.inl ⟨digits, by rw [hd], heq.mp h, by simpa [hd, wotsDigit] using hdigits⟩
  · rename_i h
    have hreject := mt heq.mpr h
    simp only [wots.GRIND_REPORT_EVERY]
    step* <;> first | scalar_tac | skip
    all_goals
      simp only [hypertree.report, ite_self, bind_tc_ok]
      step* <;> first | scalar_tac | skip

set_option maxHeartbeats 8000000 in
theorem grind_loop_first (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (start target : Std.U32)
    (hle : start.val ≤ target.val) (hbound : target.val < 10000000)
    (haccept : grindAccept seed adrs message target)
    (hfirst : ∀ c : Std.U32, start.val ≤ c.val → c.val < target.val →
      ¬ grindAccept seed adrs message c) :
    wots.find_count_loop0 seed message progress pct adrs start
      ⦃ r => r.1 = target ∧ r.2.1 = wots_digest_pure seed adrs message target ∧
        ∀ j, j < 43 → (r.2.2.val[j]!).val =
          wotsDigit (wots_digest_pure seed adrs message target) j ⦄ := by
  unfold wots.find_count_loop0
  apply loop.spec_decr_nat
    (measure := fun c : Std.U32 => target.val - c.val)
    (inv := fun c : Std.U32 => start.val ≤ c.val ∧ c.val ≤ target.val)
  · intro c hc
    let* ⟨r, hr⟩ ← grind_body_spec seed adrs message progress pct c (by omega)
    rcases hr with ⟨digits, rfl, ha, hd⟩ | ⟨next, rfl, hn, hno⟩
    · have hct : c = target := by
        apply UScalar.eq_of_val_eq
        by_contra h
        exact hfirst c hc.1 (by omega) ha
      subst c
      exact ⟨rfl, rfl, hd⟩
    · have hne : c.val ≠ target.val := by
        intro h
        have he : c = target := UScalar.eq_of_val_eq h
        exact hno (he ▸ haccept)
      exact ⟨by omega, by omega, by omega⟩
  · exact ⟨by omega, hle⟩

theorem grind_loop_exhausted (seed adrs message : Std.Array Std.U8 32#usize)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (start : Std.U32)
    (hbound : start.val ≤ 10000000)
    (hreject : ∀ c : Std.U32, start.val ≤ c.val → c.val < 10000000 →
      ¬ grindAccept seed adrs message c) :
    wots.find_count_loop0 seed message progress pct adrs start = .fail .assertionFailure := by
  generalize hmeasure : 10000000 - start.val = n
  induction n using Nat.strong_induction_on generalizing start with
  | h n ih =>
    unfold wots.find_count_loop0
    rw [loop.eq_1]
    by_cases hb : start.val < 10000000
    · obtain ⟨r, hr, hp⟩ := WP.spec_imp_exists
        (grind_body_spec seed adrs message progress pct start hb)
      rw [hr]
      rcases hp with ⟨digits, rfl, ha, _⟩ | ⟨next, rfl, hn, _⟩
      · exact False.elim (hreject start (by omega) hb ha)
      · exact ih (10000000 - next.val) (by omega) next (by omega)
          (fun c hc hcmax => hreject c (by omega) hcmax) rfl
    · have hfalse : ¬ start < 10000000#u32 := by scalar_tac
      simp only [wots.find_count_loop0.body, massert, hfalse, if_false, bind_tc_fail]

set_option maxHeartbeats 300000 in
/-- The actual source returns the first accepted count, its complete digest,
    and all 43 digits. The premise identifies an accepted trial, not a result
    of the search. The unconditional theorem below also covers exhaustion. -/
theorem find_count_first_success (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) (target : Std.U32)
    (hbound : target.val < 10000000)
    (haccept : grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message target)
    (hfirst : ∀ c : Std.U32, c.val < target.val →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) :
    wots.find_count seed layer tree kp message progress pct
      ⦃ r => r.1 = target ∧
        r.2.1 = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message target ∧
        ∀ j, j < 43 → (r.2.2.val[j]!).val =
          wotsDigit r.2.1 j ⦄ := by
  obtain ⟨a, ha, hv⟩ := WP.spec_imp_exists
    (make_adrs_spec layer tree 0#u32 kp 0#u32 0#u32 0#u32)
  unfold wots.find_count
  simp only [params.ADRS_WOTS, ha, bind_tc_ok]
  rw [← adrsArr_eq_of_map_val a layer tree 0 kp.val 0 0 0 hv]
  obtain ⟨r, hr, hc, hd, hi⟩ := WP.spec_imp_exists
    (grind_loop_first seed (adrsArr layer tree 0 kp.val 0 0 0) message progress pct
      0#u32 target (Nat.zero_le _) hbound haccept (fun c _ hc => hfirst c hc))
  rw [hr]
  exact ⟨hc, hd, fun j hj => by rw [hd]; exact hi j hj⟩

/-- Rust's terminal panic is reconstructed by Charon as an assertion; its
    extracted result is a failure, never divergence or a successful tuple. -/
theorem find_count_exhausted (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8)
    (hreject : ∀ c : Std.U32, c.val < 10000000 →
      ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) :
    wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure := by
  obtain ⟨a, ha, hv⟩ := WP.spec_imp_exists
    (make_adrs_spec layer tree 0#u32 kp 0#u32 0#u32 0#u32)
  unfold wots.find_count
  simp only [params.ADRS_WOTS, ha, bind_tc_ok]
  rw [← adrsArr_eq_of_map_val a layer tree 0 kp.val 0 0 0 hv]
  exact grind_loop_exhausted seed _ message progress pct 0#u32 (by decide)
    (fun c _ hc => hreject c hc)

/-- No success assumption: every input either returns its first accepted
    trial, or fails exactly because the bounded interval contains none.
    This is functional totality, not a probability bound or a callback proof. -/
theorem find_count_total (seed message : Std.Array Std.U8 32#usize)
    (layer : Std.U32) (tree : Std.U64) (kp : Std.U32)
    (progress : hypertree.ProgressSink) (pct : Std.U8) :
    (∃ c d digits,
      wots.find_count seed layer tree kp message progress pct = .ok (c, d, digits) ∧
      c.val < 10000000 ∧
      grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      (∀ earlier : Std.U32, earlier.val < c.val →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message earlier) ∧
      d = wots_digest_pure seed (adrsArr layer tree 0 kp.val 0 0 0) message c ∧
      ∀ j, j < 43 → (digits.val[j]!).val = wotsDigit d j) ∨
    (wots.find_count seed layer tree kp message progress pct = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c) := by
  classical
  by_cases h : ∃ n : Nat, ∃ c : Std.U32, c.val = n ∧ c.val < 10000000 ∧
      grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c
  · obtain ⟨c, hc, hb, ha⟩ := Nat.find_spec h
    have hf : ∀ earlier : Std.U32, earlier.val < c.val →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message earlier := by
      intro earlier he hea
      exact Nat.find_min h (by omega) ⟨earlier, rfl, by omega, hea⟩
    obtain ⟨⟨c', d, digits⟩, hr, hc', hd, hi⟩ := WP.spec_imp_exists
      (find_count_first_success seed message layer tree kp progress pct c hb ha hf)
    dsimp only at hc'
    subst c'
    exact Or.inl ⟨c, d, digits, hr, hb, ha, hf, hd, hi⟩
  · have hn : ∀ c : Std.U32, c.val < 10000000 →
        ¬ grindAccept seed (adrsArr layer tree 0 kp.val 0 0 0) message c := by
      intro c hc ha
      exact h ⟨c.val, c, rfl, hc, ha⟩
    exact Or.inr ⟨find_count_exhausted seed message layer tree kp progress pct hn, hn⟩

end Extracted.Equiv
