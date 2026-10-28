import Extracted.Sha256Portable.Schedule

open SphincsCVerify.Spec.Sha256Impl

namespace Sha256Portable

set_option maxHeartbeats 2000000
set_option maxRecDepth 4096

/-- A word-indexed form of the standard schedule recurrence. It is related
    below to the existing array-based specification, rather than replacing it. -/
def scheduledWord (block : Array Word) (t : Nat) : Word :=
  if t < 16 then block.getD t 0
  else nextWord (scheduledWord block (t - 16)) (scheduledWord block (t - 15))
    (scheduledWord block (t - 7)) (scheduledWord block (t - 2))
termination_by t
decreasing_by all_goals omega

theorem scheduledWord_initial (block : Array Word) (t : Nat) (ht : t < 16) :
    scheduledWord block t = block.getD t 0 := by
  rw [scheduledWord, if_pos ht]

theorem scheduledWord_next (block : Array Word) (t : Nat) (ht : 16 ≤ t) :
    scheduledWord block t =
      nextWord (scheduledWord block (t - 16)) (scheduledWord block (t - 15))
        (scheduledWord block (t - 7)) (scheduledWord block (t - 2)) := by
  rw [scheduledWord, if_neg (by omega)]

theorem messageSchedule_expand_eq (block words : Array Word) (t : Nat)
    (hs : words.size = t) (ht : 16 ≤ t) (hm : t ≤ 64)
    (hp : ∀ j, j < t → words.getD j 0 = scheduledWord block j) :
    messageSchedule.expand words t =
      Array.ofFn (fun j : Fin 64 => scheduledWord block j.val) := by
  rw [messageSchedule.expand]
  split
  · have he : t = 64 := by omega
    apply Array.ext
    · simp [hs, he]
    · intro j hj hj'
      rw [Array.getElem_eq_getD 0]
      simpa only [Array.getElem_ofFn] using hp j (by omega)
  · have h2 : t - 2 < t := by omega
    have h7 : t - 7 < t := by omega
    have h15 : t - 15 < t := by omega
    have h16 : t - 16 < t := by omega
    have hw : smallSigma1 (words.getD (t - 2) 0) + words.getD (t - 7) 0 +
        smallSigma0 (words.getD (t - 15) 0) + words.getD (t - 16) 0 =
        scheduledWord block t := by
      rw [hp _ h2, hp _ h7, hp _ h15, hp _ h16, scheduledWord_next block t ht]
      rfl
    rw [hw]
    apply messageSchedule_expand_eq block _ (t + 1)
    · simp [hs]
    · omega
    · omega
    · intro j hj
      by_cases hlt : j < t
      · simpa [Array.getD, Array.getElem_push_lt, hs, hlt, Nat.le_of_lt hlt] using hp j hlt
      · have he : j = t := by omega
        subst j
        simp [Array.getD, Array.getElem_push, hs]
termination_by 64 - t
decreasing_by omega

theorem messageSchedule_eq (block : Array Word) (hb : block.size = 16) :
    messageSchedule block = Array.ofFn (fun j : Fin 64 => scheduledWord block j.val) := by
  unfold messageSchedule
  apply messageSchedule_expand_eq block block 16 hb (by decide) (by decide)
  intro j hj
  exact (scheduledWord_initial block j hj).symm

theorem messageSchedule_word (block : Array Word) (hb : block.size = 16)
    (j : Nat) (hj : j < 64) :
    (messageSchedule block).getD j 0 = scheduledWord block j := by
  rw [messageSchedule_eq block hb]
  simp [Array.getD, hj]

/-- Prefix state after exactly `t` standard compression rounds. -/
def rounds (block : Array Word) (initial : Working) : Nat → Working
  | 0 => initial
  | t + 1 => round (rounds block initial t) (K.getD t 0) (scheduledWord block t)

theorem runRounds_go_eq (block : Array Word) (hb : block.size = 16)
    (initial : Working) (t : Nat) (ht : t ≤ 64) :
    runRounds.go (messageSchedule block) t (rounds block initial t) =
      rounds block initial 64 := by
  rw [runRounds.go]
  split
  · have he : t = 64 := by omega
    subst t
    rfl
  · rw [messageSchedule_word block hb t (by omega)]
    change runRounds.go (messageSchedule block) (t + 1) (rounds block initial (t + 1)) = _
    exact runRounds_go_eq block hb initial (t + 1) (by omega)
termination_by 64 - t
decreasing_by omega

theorem runRounds_eq (block : Array Word) (hb : block.size = 16) (initial : Working) :
    runRounds (messageSchedule block) initial = rounds block initial 64 :=
  runRounds_go_eq block hb initial 0 (by decide)

def round4 (s : Working) (k0 w0 k1 w1 k2 w2 k3 w3 : Word) : Working :=
  round (round (round (round s k0 w0) k1 w1) k2 w2) k3 w3

theorem rounds_four (block : Array Word) (initial : Working) (t : Nat) :
    round4 (rounds block initial t)
      (K.getD t 0) (scheduledWord block t)
      (K.getD (t + 1) 0) (scheduledWord block (t + 1))
      (K.getD (t + 2) 0) (scheduledWord block (t + 2))
      (K.getD (t + 3) 0) (scheduledWord block (t + 3)) =
      rounds block initial (t + 4) := by rfl

end Sha256Portable
