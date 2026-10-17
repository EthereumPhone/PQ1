import C10Probability.C10Finish
import C10Probability.RandomizerUnder

/-! Complete bounded structured C10 signing: R/H_msg grinding, forest, then
both layers. Every continuation consumes the cache returned by its predecessor.
The R trial counter is internal; the returned signature retains its R value. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def c10SignAfterProgram (encode : WotsQuery → K) (seed shuffle : ByteKey)
    (n : ℕ) (hn : n ≤ 2 ^ 32) (found : Option (ℕ × Randomizer × Digest)) :
    QueryProgram K Digest (Option C10Signature) (2 * n + 435044) :=
  match found with
  | none => .done none
  | some (_, randomizer, digest) => c10FinishProgram encode seed randomizer digest shuffle n hn

def c10SignAfter [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32)
    (found : Option (ℕ × Randomizer × Digest)) : PMF (Option C10Signature × Memo K Digest) :=
  match found with
  | none => PMF.pure (none, table)
  | some (_, randomizer, digest) => c10Finish encode table seed randomizer digest shuffle n hn

theorem c10_sign_after_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32)
    (found : Option (ℕ × Randomizer × Digest)) :
    evalProgram digestDraw (c10SignAfterProgram encode seed shuffle n hn found) table =
      c10SignAfter encode table seed shuffle n hn found := by
  cases found with
  | none => rfl
  | some value => exact c10_finish_eval encode table seed value.2.1 value.2.2 shuffle n hn

theorem c10_sign_after_map (encode : K → L) (labels : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32)
    (found : Option (ℕ × Randomizer × Digest)) :
    mapProgram encode (c10SignAfterProgram labels seed shuffle n hn found) =
      c10SignAfterProgram (encode ∘ labels) seed shuffle n hn found := by
  cases found with
  | none => rfl
  | some value => exact c10_finish_map _ _ _ _ _ _ _ _

def c10SignProgram (encode : WotsQuery → K) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    QueryProgram K Digest (Option C10Signature) (2 * m + 2 * n + 435044) :=
  castProgram (by omega)
    (bindProgram (randomizerUnderProgram encode random message seed root m hm)
      (c10SignAfterProgram encode seed shuffle n hn))

attribute [irreducible] c10SignProgram

def c10Sign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    PMF (Option C10Signature × Memo K Digest) :=
  (randomizerUnder encode table random message seed root m hm).bind
    (fun found => c10SignAfter encode found.2 seed shuffle n hn found.1)

theorem c10_sign_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    evalProgram digestDraw (c10SignProgram encode random message seed root shuffle m n hm hn) table =
      c10Sign encode table random message seed root shuffle m n hm hn := by
  simp only [c10SignProgram, evalProgram_cast, evalProgram_bind, randomizer_under_eval,
    c10_sign_after_eval, c10Sign]

theorem c10_sign_map (encode : K → L) (labels : WotsQuery → K)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    mapProgram encode (c10SignProgram labels random message seed root shuffle m n hm hn) =
      c10SignProgram (encode ∘ labels) random message seed root shuffle m n hm hn := by
  simp only [c10SignProgram, mapProgram_cast, mapProgram_bind, randomizer_under_map,
    c10_sign_after_map]

theorem c10_sign_public (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    PublicBudget (c10SignProgram id random message seed root shuffle m n hm hn)
      (m + 2 * n + 364290) := by
  rw [c10SignProgram, publicBudget_cast,
    show m + 2 * n + 364290 = m + (2 * n + 364290) by omega]
  apply publicBudget_bind _ _ m (2 * n + 364290) (randomizer_under_public _ _ _ _ _ _)
  intro found
  cases found with
  | none => trivial
  | some value => exact c10_finish_public _ _ _ _ _ _

theorem c10_sign_selected (secret : Digest) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (hs : seed.length = 32)
    (hr : root.length = 32) (hmsg : message.length = 32) :
    SelectedBudget nodeQuery (c10SignProgram (privateKey prefixedPrivateInput secret)
      random message seed root shuffle m n hm hn) (m + 435042) := by
  rw [c10SignProgram, selectedBudget_cast]
  apply selectedBudget_bind _ _ _ m 435042
    (randomizer_under_selected secret random message seed root m hm hs hr hmsg)
  intro found
  cases found with
  | none => trivial
  | some value => exact c10_finish_selected _ _ _ _ _ _ _ hs

theorem c10_sign_zero_r_budget [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (random message seed root shuffle : ByteKey)
    (n : ℕ) (hm : 0 ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    c10Sign encode table random message seed root shuffle 0 n hm hn = PMF.pure (none, table) := by
  simp only [c10Sign, randomizer_under_zero, PMF.pure_bind, c10SignAfter]

end
end C10Probability
