import C10Probability.C10Sign

/-! A returned R-exhaustion observation on the actual complete signer. The
client still receives the original signature reply. Later WOTS exhaustion has
flag false; neither observation changes any query or cache update. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

abbrev C10RSignReply := Option C10Signature × Bool

def c10RSignProgram (encode : WotsQuery → K) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    QueryProgram K Digest C10RSignReply (2 * m + 2 * n + 435044) :=
  castProgram (by omega)
    (bindProgram (randomizerUnderProgram encode random message seed root m hm)
      (fun found => mapReturnProgram (fun reply => (reply, found.isNone))
        (c10SignAfterProgram encode seed shuffle n hn found)))

def c10RSign [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    PMF (C10RSignReply × Memo K Digest) :=
  (randomizerUnder encode table random message seed root m hm).bind (fun found =>
    (c10SignAfter encode found.2 seed shuffle n hn found.1).map
      (fun reply => ((reply.1, found.1.isNone), reply.2)))

theorem c10_r_sign_eval [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    evalProgram digestDraw
      (c10RSignProgram encode random message seed root shuffle m n hm hn) table =
      c10RSign encode table random message seed root shuffle m n hm hn := by
  simp only [c10RSignProgram, evalProgram_cast, evalProgram_bind, randomizer_under_eval,
    evalProgram_mapReturn, c10_sign_after_eval, c10RSign]

theorem c10_r_sign_erases [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    (c10RSign encode table random message seed root shuffle m n hm hn).map
      (fun out => (out.1.1, out.2)) =
      c10Sign encode table random message seed root shuffle m n hm hn := by
  simp only [c10RSign, PMF.map_bind, PMF.map_comp, Function.comp_def, c10Sign]
  simp only [Prod.mk.eta]
  congr 1
  funext found
  exact PMF.map_id _

theorem c10_r_sign_map (encode : K → L) (labels : WotsQuery → K)
    (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    mapProgram encode (c10RSignProgram labels random message seed root shuffle m n hm hn) =
      c10RSignProgram (encode ∘ labels) random message seed root shuffle m n hm hn := by
  simp only [c10RSignProgram, mapProgram_cast, mapProgram_bind, randomizer_under_map,
    mapProgram_mapReturn, c10_sign_after_map]

theorem c10_r_sign_public (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    PublicBudget (c10RSignProgram id random message seed root shuffle m n hm hn)
      (m + 2 * n + 364290) := by
  rw [c10RSignProgram, publicBudget_cast,
    show m + 2 * n + 364290 = m + (2 * n + 364290) by omega]
  apply publicBudget_bind _ _ m (2 * n + 364290) (randomizer_under_public _ _ _ _ _ _)
  intro found
  rw [publicBudget_mapReturn]
  cases found with
  | none => trivial
  | some value => exact c10_finish_public _ _ _ _ _ _

theorem c10_r_sign_zero [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (random message seed root shuffle : ByteKey)
    (n : ℕ) (hm : 0 ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) :
    c10RSign encode table random message seed root shuffle 0 n hm hn =
      PMF.pure ((none, true), table) := by
  simp only [c10RSign, randomizer_under_zero, PMF.pure_bind, c10SignAfter,
    PMF.pure_map, Option.isNone_none]

end
end C10Probability
