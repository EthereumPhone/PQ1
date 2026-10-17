import C10Probability.LayerCharges

/-! The ordered hypertree signing loop. Each layer consumes the preceding
reconstructed node, shifts its tree coordinate before signing, and appends the
actual signature. Either layer may exhaust; the full cache survives failure. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

abbrev HypertreeSigned := Option (List LayerSignature × Randomizer)

def hypertreeSignProgram (encode : WotsQuery → K) (seed shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : (steps layer index : ℕ) → Randomizer →
    List LayerSignature → QueryProgram K Digest HypertreeSigned (steps * (n + 177511))
  | 0, _, _, current, signatures => .done (some (signatures, current))
  | steps + 1, layer, index, current, signatures =>
      castProgram (Nat.succ_mul steps (n + 177511)).symm
        (bindProgram (layerSignProgram encode seed layer (hypertreeParent index)
          (hypertreeLeaf index) current shuffle n hb) (fun signed =>
            match signed with
            | none => .done none
            | some (sig, root) => hypertreeSignProgram encode seed shuffle n hb steps
                (layer + 1) (hypertreeParent index) root (signatures ++ [sig])))

attribute [irreducible] hypertreeSignProgram

def hypertreeSign [DecidableEq K] (encode : WotsQuery → K) (seed shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) : (steps layer index : ℕ) → Randomizer →
    List LayerSignature → Memo K Digest → PMF (HypertreeSigned × Memo K Digest)
  | 0, _, _, current, signatures, table => PMF.pure (some (signatures, current), table)
  | steps + 1, layer, index, current, signatures, table =>
      (layerSign encode table seed layer (hypertreeParent index)
        (hypertreeLeaf index) current shuffle n hb).bind (fun signed =>
          match signed.1 with
          | none => PMF.pure (none, signed.2)
          | some (sig, root) => hypertreeSign encode seed shuffle n hb steps
              (layer + 1) (hypertreeParent index) root (signatures ++ [sig]) signed.2)

theorem hypertree_sign_eval [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) (steps layer index : ℕ)
    (current : Randomizer) (signatures : List LayerSignature) (table : Memo K Digest) :
    evalProgram digestDraw
      (hypertreeSignProgram encode seed shuffle n hb steps layer index current signatures) table =
      hypertreeSign encode seed shuffle n hb steps layer index current signatures table := by
  induction steps generalizing layer index current signatures table with
  | zero => simp only [hypertreeSignProgram, hypertreeSign, evalProgram]
  | succ steps ih =>
    simp only [hypertreeSignProgram, evalProgram_cast, evalProgram_bind, layer_sign_eval,
      hypertreeSign]
    congr 1
    funext signed
    cases signed.1 with
    | none => rfl
    | some value => exact ih _ _ _ _ _

theorem hypertree_sign_map (encode : K → L) (labels : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) (steps layer index : ℕ)
    (current : Randomizer) (signatures : List LayerSignature) :
    mapProgram encode
      (hypertreeSignProgram labels seed shuffle n hb steps layer index current signatures) =
      hypertreeSignProgram (encode ∘ labels) seed shuffle n hb steps layer index current signatures := by
  induction steps generalizing layer index current signatures with
  | zero => simp only [hypertreeSignProgram, mapProgram]
  | succ steps ih =>
    simp only [hypertreeSignProgram, mapProgram_cast, mapProgram_bind, layer_sign_map]
    congr 2
    funext signed
    cases signed with
    | none => rfl
    | some value => exact ih _ _ _ _

theorem hypertree_sign_public (seed shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (steps layer index : ℕ) (current : Randomizer) (signatures : List LayerSignature) :
    PublicBudget (hypertreeSignProgram id seed shuffle n hb steps layer index current signatures)
      (steps * (n + 155452)) := by
  induction steps generalizing layer index current signatures with
  | zero => simp only [hypertreeSignProgram, PublicBudget]
  | succ steps ih =>
    rw [hypertreeSignProgram, publicBudget_cast, Nat.succ_mul,
      Nat.add_comm (steps * (n + 155452))]
    apply publicBudget_bind _ _ (n + 155452) (steps * (n + 155452))
      (layer_sign_public _ _ _ _ _ _ _ _)
    intro signed
    cases signed with
    | none => trivial
    | some value => exact ih _ _ _ _

theorem hypertree_sign_selected (secret : Digest) (seed shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (steps layer index : ℕ) (current : Randomizer)
    (signatures : List LayerSignature) (hs : seed.length = 32) :
    SelectedBudget nodeQuery
      (hypertreeSignProgram (privateKey prefixedPrivateInput secret)
        seed shuffle n hb steps layer index current signatures) (steps * 177510) := by
  induction steps generalizing layer index current signatures with
  | zero => simp only [hypertreeSignProgram, SelectedBudget]
  | succ steps ih =>
    rw [hypertreeSignProgram, selectedBudget_cast, Nat.succ_mul, Nat.add_comm (steps * 177510)]
    apply selectedBudget_bind _ _ _ 177510 (steps * 177510)
      (layer_sign_selected _ _ _ _ _ _ _ _ _ hs)
    intro signed
    cases signed with
    | none => trivial
    | some value => exact ih _ _ _ _

end
end C10Probability
