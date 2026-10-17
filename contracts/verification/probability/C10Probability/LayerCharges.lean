import C10Probability.LayerSign

/-! Costs of the actual layer, including the subtree construction and all
reconstruction calls. Selected calls exclude WOTS count inputs; the raw zero
charge still counts them. Prefix comparison has its own empty-table and
independent-hidden-secret experiment. No fresh-call premise is inferred. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem layer_sign_after_selected (secret : Digest) (seed : ByteKey)
    (layer tree leaf : ℕ) (message : Randomizer) (auth : List Randomizer)
    (signed : WotsSignature) (hs : seed.length = 32) :
    SelectedBudget nodeQuery
      (layerSignAfterProgram (privateKey prefixedPrivateInput secret)
        seed layer tree leaf message auth signed) 106 := by
  cases signed with
  | none => trivial
  | some value =>
    rcases value with ⟨sigma, count⟩
    rw [layerSignAfterProgram, selectedBudget_mapReturn]
    exact layer_recover_selected seed layer tree leaf message ⟨sigma, count, auth⟩ hs

theorem layer_sign_selected (secret : Digest) (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (hs : seed.length = 32) :
    SelectedBudget nodeQuery
      (layerSignProgram (privateKey prefixedPrivateInput secret)
        seed layer tree leaf message shuffle n hb) 177510 := by
  rw [layerSignProgram, selectedBudget_cast]
  apply selectedBudget_bind _ _ _ 177151 359 (selectedBudget_total _ _)
  intro built
  apply selectedBudget_bind _ _ _ 1 358 (selectedBudget_total _ _)
  intro subseed
  exact selectedBudget_bind _ _ _ 252 106
    (wots_sign_selected secret seed layer tree leaf (nodeValueBytes message) subseed n hb
      hs (node_value_bytes_length message))
    (fun signed => layer_sign_after_selected secret seed layer tree leaf message built.1 signed hs)

theorem layer_sign_physical_eval (secret : Digest) (table : Memo ByteKey Digest)
    (seed : ByteKey) (layer tree leaf : ℕ) (message : Randomizer)
    (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32) :
    evalProgram digestDraw
      (mapProgram (privateKey prefixedPrivateInput secret)
        (layerSignProgram id seed layer tree leaf message shuffle n hb)) table =
      layerSign (privateKey prefixedPrivateInput secret) table
        seed layer tree leaf message shuffle n hb := by
  rw [layer_sign_map]
  exact layer_sign_eval _ _ _ _ _ _ _ _ _ _

theorem layer_sign_prefix_error (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (event : Set LayerSigned) :
    |((privateShared digestDraw digestDraw prefixedPrivateInput
        (PMF.pure (layerSignProgram id seed layer tree leaf message shuffle n hb))).toOuterMeasure event).toReal -
      ((privateIndependent digestDraw
        (PMF.pure (layerSignProgram id seed layer tree leaf message shuffle n hb))).toOuterMeasure event).toReal| ≤
      ((n + 155452 : ℕ) : ℝ) / 2 ^ 256 := by
  apply private_secret_event_error_real _ (n + 155452)
  intro program hp
  have he : program = layerSignProgram id seed layer tree leaf message shuffle n hb := by simpa using hp
  rw [he]
  exact layer_sign_public _ _ _ _ _ _ _ _

theorem layer_sign_domain_bad_bound (secret : Digest) (seed : ByteKey)
    (layer tree leaf : ℕ) (message : Randomizer) (shuffle : ByteKey)
    (n : ℕ) (hb : n ≤ 2 ^ 32) (hs : seed.length = 32) :
    (layerSign (privateKey prefixedPrivateInput secret) (fun _ => none)
      seed layer tree leaf message shuffle n hb).toOuterMeasure {out | DomainNodeBad out.2} ≤
        ((Nat.choose 177510 2 + (n + 177511) : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  have h := digest_program_domain_node_bad_bound
    (PMF.pure (layerSignProgram (privateKey prefixedPrivateInput secret)
      seed layer tree leaf message shuffle n hb)) 177510 (by
        intro program hp
        have he : program = layerSignProgram (privateKey prefixedPrivateInput secret)
            seed layer tree leaf message shuffle n hb := by simpa using hp
        rw [he]
        exact layer_sign_selected secret seed layer tree leaf message shuffle n hb hs)
  simpa only [randomizedProgram_pure, layer_sign_eval] using h

end
end C10Probability
