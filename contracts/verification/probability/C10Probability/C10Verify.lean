import C10Probability.C10Finish
import C10Probability.HypertreeRecover
import C10Probability.ForestRecover

/-! RawSigner.verify as a structured byte client: recompute H_msg, enforce the
last-FORS-index-zero condition, recover forest and both layers, then compare
the entire padded node. Parsing a4008-byte signature is a separate boundary. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def c10VerifyAfterProgram (encode : ByteKey → K) (seed root : ByteKey)
    (sig : C10Signature) (digest : Digest) : QueryProgram K Digest Bool 360 :=
  if forsAccept (forsOfDigest digest) then
    bindProgram (forestRecoverProgram encode seed (hypertreeIndex digest) digest sig.secrets sig.auths)
      (fun pk => mapReturnProgram (fun current => decide (nodeBlock current = root))
        (hypertreeRecoverProgram encode seed sig.layers 2 0 (hypertreeIndex digest) pk))
  else .done false

attribute [irreducible] c10VerifyAfterProgram

def c10VerifyAfter [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed root : ByteKey) (sig : C10Signature) (digest : Digest) : PMF (Bool × Memo K Digest) :=
  if forsAccept (forsOfDigest digest) then
    (forestRecover encode table seed (hypertreeIndex digest) digest sig.secrets sig.auths).bind
      (fun pk => (hypertreeRecover encode seed sig.layers 2 0 (hypertreeIndex digest) pk.1 pk.2).map
        (fun current => (decide (nodeBlock current.1 = root), current.2)))
  else PMF.pure (false, table)

theorem c10_verify_after_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed root : ByteKey) (sig : C10Signature) (digest : Digest) :
    evalProgram digestDraw (c10VerifyAfterProgram encode seed root sig digest) table =
      c10VerifyAfter encode table seed root sig digest := by
  cases ha : forsAccept (forsOfDigest digest) <;>
    simp only [c10VerifyAfterProgram, c10VerifyAfter, ha, Bool.false_eq_true, ↓reduceIte,
      evalProgram_bind, evalProgram_mapReturn, forest_recover_eval, hypertree_recover_eval,
      evalProgram]

theorem c10_verify_after_map (encode : K → L) (labels : ByteKey → K)
    (seed root : ByteKey) (sig : C10Signature) (digest : Digest) :
    mapProgram encode (c10VerifyAfterProgram labels seed root sig digest) =
      c10VerifyAfterProgram (encode ∘ labels) seed root sig digest := by
  cases ha : forsAccept (forsOfDigest digest) <;>
    simp only [c10VerifyAfterProgram, ha, Bool.false_eq_true, ↓reduceIte, mapProgram_bind,
      forest_recover_map, mapProgram_mapReturn, hypertree_recover_map, mapProgram]

def c10VerifyProgram (encode : ByteKey → K) (seed root message : ByteKey)
    (sig : C10Signature) : QueryProgram K Digest Bool 361 :=
  .query (encode (hmsgRandomizerInput seed root message sig.randomizer))
    (c10VerifyAfterProgram encode seed root sig)

def c10Verify [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) : PMF (Bool × Memo K Digest) :=
  (memoQuery digestDraw table (encode (hmsgRandomizerInput seed root message sig.randomizer))).bind
    (fun digest => c10VerifyAfter encode digest.2 seed root sig digest.1)

theorem c10_verify_eval [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) :
    evalProgram digestDraw (c10VerifyProgram encode seed root message sig) table =
      c10Verify encode table seed root message sig := by
  simp only [c10VerifyProgram, evalProgram, c10_verify_after_eval, c10Verify]

theorem c10_verify_map (encode : K → L) (labels : ByteKey → K)
    (seed root message : ByteKey) (sig : C10Signature) :
    mapProgram encode (c10VerifyProgram labels seed root message sig) =
      c10VerifyProgram (encode ∘ labels) seed root message sig := by
  simp only [c10VerifyProgram, mapProgram, c10_verify_after_map, Function.comp_def]

theorem c10_verify_after_selected (seed root : ByteKey) (sig : C10Signature)
    (digest : Digest) (hs : seed.length = 32) :
    SelectedBudget nodeQuery (c10VerifyAfterProgram id seed root sig digest) 358 := by
  cases ha : forsAccept (forsOfDigest digest)
  · rw [c10VerifyAfterProgram, ha, if_neg Bool.false_ne_true]
    trivial
  · rw [c10VerifyAfterProgram, ha, if_pos rfl]
    apply selectedBudget_bind _ _ _ 146 (2 * 106) (selectedBudget_total _ _)
    intro pk
    rw [selectedBudget_mapReturn]
    exact hypertree_recover_selected _ _ _ _ _ _ hs

theorem c10_verify_selected (seed root message : ByteKey) (sig : C10Signature)
    (hs : seed.length = 32) (hr : root.length = 32) (hm : message.length = 32) :
    SelectedBudget nodeQuery (c10VerifyProgram id seed root message sig) 358 := by
  simp only [c10VerifyProgram, id_eq, SelectedBudget, node_query_no_hmsg _ _ _ _ hs hr hm,
    Bool.false_eq_true, ↓reduceIte]
  exact fun digest => c10_verify_after_selected seed root sig digest hs

theorem c10_verify_after_rejected [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed root : ByteKey) (sig : C10Signature) (digest : Digest)
    (reject : forsAccept (forsOfDigest digest) = false) :
    c10VerifyAfter encode table seed root sig digest = PMF.pure (false, table) := by
  simp only [c10VerifyAfter, reject, Bool.false_eq_true, ↓reduceIte]

end
end C10Probability
