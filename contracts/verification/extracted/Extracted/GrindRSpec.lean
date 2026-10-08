/- Actual FORS randomizer search: functional behavior under the existing SHA
   backend. No entropy, independence, hardness or success premise is assumed. -/
import Extracted.GrindR.Funs
import Extracted.HashSpecs.WotsDigest
import Extracted.HashSpecs.ChainHash
import Extracted.HashSpecs.HMsg
import Extracted.ForsExtract

open Aeneas Aeneas.Std Result ControlFlow
open Extracted.SetSlice
set_option maxRecDepth 4096
set_option maxHeartbeats 8000000
attribute [local irreducible] SphincsCVerify.Spec.Sha256Impl.sha256Bytes

namespace Extracted.Equiv
open sphincs_c10

noncomputable def forsRandomizer (sk message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    Std.Array Std.U8 16#usize :=
  truncate16 (sha256_pure (sk.val ++
    [82#u8, 95#u8, 103#u8, 114#u8, 105#u8, 110#u8, 100#u8] ++
    (match opt with | none => [] | some rand => rand.val) ++ message.val ++
    List.replicate 28 0#u8 ++ u32beBytes nonce.val))

noncomputable def forsGrindDigest (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) :
    Std.Array Std.U8 32#usize :=
  sha256_pure (seed.val ++ root.val ++ (pad16Pure (forsRandomizer sk message opt nonce)).val ++
    message.val ++ List.replicate 32 255#u8)

noncomputable def forsGrindAccept (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32) : Prop :=
  (digestWord (forsGrindDigest sk seed root message opt nonce) >>> 132) % 2^11 = 0

theorem fors_grind_body_spec (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (nonce : Std.U32)
    (hbound : nonce.val < 10000000) :
    fors.grind_r_loop.body sk message opt seed root 132#usize nonce
      ⦃ r =>
        (r = done (forsRandomizer sk message opt nonce,
          forsGrindDigest sk seed root message opt nonce) ∧
          forsGrindAccept sk seed root message opt nonce) ∨
        (∃ next, r = cont next ∧ next.val = nonce.val + 1 ∧
          ¬ forsGrindAccept sk seed root message opt nonce) ⦄ := by
  cases hopt : opt <;> unfold fors.grind_r_loop.body
  all_goals
    step
    step
    step
    step
    step
    have hbuf : (index_mut_back s2).val = List.replicate 28 0#u8 ++ u32beBytes nonce.val := by
      simp only [s_post3, s2_post, s1_post, Array.val_to_slice, a_post,
        Array.repeat_val, u32_toBEBytes_map_mk]
      exact rightAlign_word 28 _ (by simp [u32beBytes]) (by decide)
    simp only [lift, Array.to_slice, Array.make, hash.sha256_parts,
      bind_tc_ok, List.map_cons, List.map_nil, List.flatten_cons, List.flatten_nil,
      List.append_nil, hbuf]
    all_goals
      let* ⟨rv, hrv⟩ ← hash.truncate_spec _
      let* ⟨rb, hrb⟩ ← pad16_pure_spec rv
      rw [hash.h_msg_spec]
      simp only [bind_tc_ok, params.A]
      let* ⟨i, hi⟩ ← read_bits_le_spec _ 132#usize 11#usize (by decide) (by decide) (by decide)
      have hrv' : rv = forsRandomizer sk message opt nonce := by
        simp only [forsRandomizer, hopt, hrv, List.append_assoc, List.nil_append]
      have hd : sha256_pure (seed.val ++ root.val ++ rb.val ++ message.val ++
          List.replicate 32 255#u8) = forsGrindDigest sk seed root message opt nonce := by
        rw [hrb, hrv']
        rfl
      rw [hd] at hi
      have heq : i = 0#u64 ↔ forsGrindAccept sk seed root message opt nonce := by
        constructor
        · intro h
          have hv : i.val = 0 := congrArg UScalar.val h
          simpa only [hi] using hv
        · intro h
          apply UScalar.eq_of_val_eq
          change i.val = 0
          rw [hi]
          exact h
      simp only [← hopt]
      rw [hrv', hd]
      split
      · rename_i h
        exact Or.inl ⟨rfl, heq.mp h⟩
      · rename_i h
        have hno := mt heq.mpr h
        step* <;> first | scalar_tac | skip

theorem fors_grind_loop_first (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (start target : Std.U32)
    (hle : start.val ≤ target.val) (hb : target.val < 10000000)
    (ha : forsGrindAccept sk seed root message opt target)
    (hf : ∀ c : Std.U32, start.val ≤ c.val → c.val < target.val →
      ¬ forsGrindAccept sk seed root message opt c) :
    fors.grind_r_loop sk message opt seed root 132#usize start
      ⦃ r => r = (forsRandomizer sk message opt target,
        forsGrindDigest sk seed root message opt target) ⦄ := by
  unfold fors.grind_r_loop
  apply loop.spec_decr_nat
    (measure := fun c : Std.U32 => target.val - c.val)
    (inv := fun c : Std.U32 => start.val ≤ c.val ∧ c.val ≤ target.val)
  · intro c hc
    let* ⟨r, hr⟩ ← fors_grind_body_spec sk seed root message opt c (by omega)
    rcases hr with ⟨rfl, hac⟩ | ⟨next, rfl, hn, hno⟩
    · have hct : c = target := by
        apply UScalar.eq_of_val_eq
        by_contra h
        exact hf c hc.1 (by omega) hac
      subst c
      rfl
    · have hne : c.val ≠ target.val := by
        intro h
        have he : c = target := UScalar.eq_of_val_eq h
        exact hno (he ▸ ha)
      exact ⟨by omega, by omega, by omega⟩
  · exact ⟨by omega, hle⟩

theorem fors_grind_loop_exhausted (sk seed root message : Std.Array Std.U8 32#usize)
    (opt : Option (Std.Array Std.U8 16#usize)) (start : Std.U32)
    (hb : start.val ≤ 10000000)
    (hr : ∀ c : Std.U32, start.val ≤ c.val → c.val < 10000000 →
      ¬ forsGrindAccept sk seed root message opt c) :
    fors.grind_r_loop sk message opt seed root 132#usize start = .fail .assertionFailure := by
  generalize hmeasure : 10000000 - start.val = n
  induction n using Nat.strong_induction_on generalizing start with
  | h n ih =>
    unfold fors.grind_r_loop
    rw [loop.eq_1]
    by_cases hb' : start.val < 10000000
    · obtain ⟨r, he, hp⟩ := WP.spec_imp_exists
        (fors_grind_body_spec sk seed root message opt start hb')
      rw [he]
      rcases hp with ⟨rfl, ha⟩ | ⟨next, rfl, hn, _⟩
      · exact False.elim (hr start (by omega) hb' ha)
      · exact ih (10000000 - next.val) (by omega) next (by omega)
          (fun c hc hmax => hr c (by omega) hmax) rfl
    · have hfalse : ¬ start < 10000000#u32 := by scalar_tac
      simp only [fors.grind_r_loop.body, massert, hfalse, if_false, bind_tc_fail]

theorem fors_grind_start (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    fors.grind_r sk seed root message opt =
      fors.grind_r_loop sk message opt (pad16Pure seed) (pad16Pure root) 132#usize 0#u32 := by
  obtain ⟨s, hs, hsv⟩ := WP.spec_imp_exists (pad16_pure_spec seed)
  obtain ⟨r, hr, hrv⟩ := WP.spec_imp_exists (pad16_pure_spec root)
  subst s
  subst r
  unfold fors.grind_r
  simp only [hs, hr, bind_tc_ok, params.K, params.A]
  obtain ⟨i, hi, hiv, _⟩ := WP.spec_imp_exists
    (Std.Usize.sub_spec (x := 13#usize) (y := 1#usize) (by scalar_tac))
  have hie : i = 12#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  subst i
  obtain ⟨j, hj, hjv⟩ := WP.spec_imp_exists
    (Std.Usize.mul_spec (x := 12#usize) (y := 11#usize) (by scalar_tac))
  have hje : j = 132#usize := by apply UScalar.eq_of_val_eq; scalar_tac
  subst j
  rw [hi, bind_tc_ok, hj]
  rfl

/-- The actual source returns the R and full digest of the earliest accepted
    nonce. Optional randomness is an input, not an entropy assumption. -/
theorem grind_r_first_success (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (target : Std.U32) (hb : target.val < 10000000)
    (ha : forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt target)
    (hf : ∀ c : Std.U32, c.val < target.val →
      ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c) :
    fors.grind_r sk seed root message opt = .ok
      (forsRandomizer sk message opt target,
        forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt target) := by
  rw [fors_grind_start]
  obtain ⟨r, hr, hv⟩ := WP.spec_imp_exists
    (fors_grind_loop_first sk (pad16Pure seed) (pad16Pure root) message opt 0#u32 target
      (by simp) hb ha (fun c _ hc => hf c hc))
  rw [hr, hv]

/-- Every rejected trial leads to the next nonce; the bound leads to failure.
    Charon maps the terminal Rust panic to assertionFailure. -/
theorem grind_r_exhausted (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize))
    (hr : ∀ c : Std.U32, c.val < 10000000 →
      ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c) :
    fors.grind_r sk seed root message opt = .fail .assertionFailure := by
  rw [fors_grind_start]
  exact fors_grind_loop_exhausted sk (pad16Pure seed) (pad16Pure root) message opt 0#u32
    (by decide) (fun c _ hc => hr c hc)

/-- Unconditional bounded-search behavior: exact first accepted R/digest or
    failure because no nonce in the complete interval satisfies forced-zero. -/
theorem grind_r_total (sk message : Std.Array Std.U8 32#usize)
    (seed root : Std.Array Std.U8 16#usize) (opt : Option (Std.Array Std.U8 16#usize)) :
    (∃ c : Std.U32, c.val < 10000000 ∧
      forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c ∧
      (∀ earlier : Std.U32, earlier.val < c.val →
        ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt earlier) ∧
      fors.grind_r sk seed root message opt = .ok
        (forsRandomizer sk message opt c,
          forsGrindDigest sk (pad16Pure seed) (pad16Pure root) message opt c)) ∨
    (fors.grind_r sk seed root message opt = .fail .assertionFailure ∧
      ∀ c : Std.U32, c.val < 10000000 →
        ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c) := by
  classical
  by_cases h : ∃ n : Nat, ∃ c : Std.U32, c.val = n ∧ c.val < 10000000 ∧
      forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c
  · obtain ⟨c, hc, hb, ha⟩ := Nat.find_spec h
    have hf : ∀ earlier : Std.U32, earlier.val < c.val →
        ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt earlier := by
      intro earlier he hea
      exact Nat.find_min h (by omega) ⟨earlier, rfl, by omega, hea⟩
    exact Or.inl ⟨c, hb, ha, hf, grind_r_first_success sk message seed root opt c hb ha hf⟩
  · have hn : ∀ c : Std.U32, c.val < 10000000 →
        ¬ forsGrindAccept sk (pad16Pure seed) (pad16Pure root) message opt c := by
      intro c hc ha
      exact h ⟨c.val, c, rfl, hc, ha⟩
    exact Or.inr ⟨grind_r_exhausted sk message seed root opt hn, hn⟩

end Extracted.Equiv
