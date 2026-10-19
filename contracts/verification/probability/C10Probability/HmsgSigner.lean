import C10Probability.HmsgForest
import C10Probability.C10Sign
import C10Probability.C10Keygen

/-! Accepted H_msg calls in the actual structured signer. An R grinder can
make many rejected attempts but stops at its first accepted reply. -/
namespace C10Probability
noncomputable section

theorem layer_sign_hmsg_excluded (seed : ByteKey) (layer tree leaf : ℕ)
    (message : Randomizer) (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (width : seed.length = 32) (shuffleWidth : shuffle.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (layerSignProgram id seed layer tree leaf message shuffle n hb) := by
  rw [layerSignProgram, queryExclusion_cast]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
  · rw [merkleBuildProgram, queryExclusion_mapReturn]
    exact subtree_hmsg_excluded seed layer tree _ _ width
  · intro built _
    apply queryExclusion_bind hmsgQuery (fun subseed => subseed.length = 32) _ _ _
      (shuffle_derive_hmsg_excluded shuffle (layerShuffleLabel layer) shuffleWidth
        (by rw [layer_shuffle_label_length]; decide))
    intro subseed subseedWidth
    apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
      (wots_sign_hmsg_excluded seed layer tree leaf (nodeValueBytes message) subseed n hb
        width (node_value_bytes_length message) subseedWidth)
    intro signed _
    cases signed with
    | none => trivial
    | some signed =>
      rw [layerSignAfterProgram, queryExclusion_mapReturn]
      exact layer_recover_hmsg_excluded seed layer tree leaf message _ width

theorem hypertree_sign_hmsg_excluded (seed shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (steps layer index : ℕ) (current : Randomizer) (signatures : List LayerSignature)
    (width : seed.length = 32) (shuffleWidth : shuffle.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (hypertreeSignProgram id seed shuffle n hb steps layer index current signatures) := by
  induction steps generalizing layer index current signatures with
  | zero => rw [hypertreeSignProgram]; trivial
  | succ steps ih =>
    rw [hypertreeSignProgram, queryExclusion_cast]
    apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
      (layer_sign_hmsg_excluded _ _ _ _ _ _ _ _ width shuffleWidth)
    intro signed _
    cases signed with
    | none => trivial
    | some signed => exact ih _ _ _ _

theorem c10_finish_hmsg_excluded (seed : ByteKey) (randomizer : Randomizer) (digest : Digest)
    (shuffle : ByteKey) (n : ℕ) (hb : n ≤ 2 ^ 32)
    (width : seed.length = 32) (shuffleWidth : shuffle.length = 32) :
    QueryExclusion hmsgQuery (fun _ => True)
      (c10FinishProgram id seed randomizer digest shuffle n hb) := by
  rw [c10FinishProgram, queryExclusion_cast]
  apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
    (forest_sign_hmsg_excluded _ _ _ _ width shuffleWidth)
  intro forest _
  rw [queryExclusion_mapReturn]
  exact hypertree_sign_hmsg_excluded _ _ _ _ _ _ _ _ _ width shuffleWidth

theorem derivedProgram_reply_budget {K P L α : Type*} (charge : K → α → Bool)
    (firstKey : P → K) (derive : α → L) (encode : L → K) (accept : α → Bool)
    (firstFree : ∀ key reply, charge (firstKey key) reply = false)
    (onlyAccepted : ∀ label reply, charge (encode label) reply = true → accept reply = true)
    (start : ℕ) (keys : List P) :
    ReplyBudget charge (derivedProgram firstKey derive encode accept start keys) 1 := by
  induction keys generalizing start with
  | nil => trivial
  | cons key rest ih =>
    rw [derivedProgram, replyBudget_cast]
    intro first
    simp only [firstFree, Bool.false_eq_true, ↓reduceIte]
    intro second
    cases accepted : accept second
    · have uncharged : charge (encode (derive first)) second = false := by
        cases hc : charge (encode (derive first)) second
        · rfl
        · have := onlyAccepted (derive first) second hc
          simp [accepted] at this
      simpa only [uncharged, accepted, Bool.false_eq_true, ↓reduceIte] using ih (start + 1)
    · cases charge (encode (derive first)) second <;>
        simp only [accepted, Bool.false_eq_true, ↓reduceIte, ReplyBudget, and_true]
      decide

theorem randomizer_under_hmsg_budget (random message seed root : ByteKey)
    (m : ℕ) (hm : m ≤ 2 ^ 32) :
    ReplyBudget (hmsgReplyCharge hmsgQuery)
      (randomizerUnderProgram id random message seed root m hm) 1 := by
  rw [randomizerUnderProgram, mapProgram_id, privateRandomizerProgram, replyBudget_cast]
  apply derivedProgram_reply_budget
  · intro key reply
    rfl
  · intro label reply charged
    have both : hmsgQuery (Sum.inl (hmsgRandomizerInput seed root message label)) = true ∧
        forsAccept (forsOfDigest reply) = true := by
      simpa only [hmsgReplyCharge, Function.comp_apply, Bool.and_eq_true] using charged
    exact both.2

theorem c10_sign_hmsg_budget (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32)
    (width : seed.length = 32) (shuffleWidth : shuffle.length = 32) :
    ReplyBudget (hmsgReplyCharge hmsgQuery)
      (c10SignProgram id random message seed root shuffle m n hm hn) 1 := by
  rw [c10SignProgram, replyBudget_cast]
  apply replyBudget_bind _ _ _ 1 0 (randomizer_under_hmsg_budget _ _ _ _ _ _)
  intro found
  cases found with
  | none => trivial
  | some found =>
    exact queryExclusion_budget hmsgQuery _ _
      (c10_finish_hmsg_excluded seed found.2.1 found.2.2 shuffle n hn width shuffleWidth)

theorem c10_verify_hmsg_budget (seed root message : ByteKey) (sig : C10Signature)
    (width : seed.length = 32) :
    ReplyBudget (hmsgReplyCharge hmsgQuery) (c10VerifyProgram Sum.inl seed root message sig) 1 := by
  apply replyBudget_query _ _ _ 0
  intro digest
  apply queryExclusion_budget hmsgQuery (fun _ => True)
  cases accepted : forsAccept (forsOfDigest digest)
  · rw [c10VerifyAfterProgram, accepted, if_neg Bool.false_ne_true]
    trivial
  · rw [c10VerifyAfterProgram, accepted, if_pos rfl]
    apply queryExclusion_bind hmsgQuery (fun _ => True) _ _ _
      (forest_recover_hmsg_excluded _ _ _ _ _ width)
    intro pk _
    rw [queryExclusion_mapReturn]
    exact hypertree_recover_hmsg_excluded _ _ _ _ _ _ width

theorem c10_keygen_hmsg_budget (publicSeed : Digest) :
    ReplyBudget (hmsgReplyCharge hmsgQuery) (c10KeygenProgram id publicSeed) 0 := by
  apply queryExclusion_budget hmsgQuery (fun _ => True)
  simp only [c10KeygenProgram, subtreeRootProgram, queryExclusion_mapReturn]
  exact subtree_hmsg_excluded _ _ _ _ _ (node_block_length _)

end
end C10Probability
