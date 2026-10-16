import C10Probability.ChainProgram
import C10Probability.AddressBytes
import C10Probability.NodeZero

/-! Ordinary C10 WOTS chain addresses and the actual shared-cache node loop.
This is the chain component, not a full WOTS signing or recovery program. -/
namespace C10Probability
noncomputable section

def wotsChainInput (seed : ByteKey) (layer tree kp index position : ℕ)
    (current : Randomizer) : ByteKey :=
  seed ++ c10Address layer tree 0 kp index position 0 ++
    List.ofFn (randomizerBytesEquiv.symm current) ++ List.replicate 16 0

theorem wots_chain_input_length (seed : ByteKey) (layer tree kp index position : ℕ)
    (current : Randomizer) (hs : seed.length = 32) :
    (wotsChainInput seed layer tree kp index position current).length = 96 := by
  simp [wotsChainInput, c10_address_length, hs]

theorem wots_chain_input_selected (seed : ByteKey) (layer tree kp index position : ℕ)
    (current : Randomizer) (hs : seed.length = 32) :
    nodeQuery (wotsChainInput seed layer tree kp index position current) = true := by
  exact node_query_node_widths _ (Or.inl
    (wots_chain_input_length seed layer tree kp index position current hs))

theorem wots_chain_reply_bytes (digest : Digest) :
    List.ofFn (randomizerBytesEquiv.symm (randomizerOfDigest digest)) =
      List.ofFn (nodeBytes digest) := by
  rw [node_bytes_projection]

def wotsChainProgram (seed : ByteKey) (layer tree kp index start stop : ℕ)
    (current : Randomizer) : QueryProgram ByteKey Digest Randomizer (stop - start) :=
  chainProgram (wotsChainInput seed layer tree kp index) randomizerOfDigest
    start (stop - start) current

def wotsChainSearch (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) :
    PMF (Randomizer × Memo ByteKey Digest) :=
  chainLoop digestDraw (wotsChainInput seed layer tree kp index) randomizerOfDigest
    start (stop - start) current table

theorem wots_chain_program_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) :
    evalProgram digestDraw (wotsChainProgram seed layer tree kp index start stop current) table =
      wotsChainSearch table seed layer tree kp index start stop current := by
  exact evalProgram_chain _ _ _ _ _ _ _

theorem wots_chain_selected_budget (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) :
    SelectedBudget nodeQuery (wotsChainProgram seed layer tree kp index start stop current)
      (stop - start) := by
  exact selectedBudget_total _ _

theorem wots_chain_seven_budget (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) (hst : stop ≤ 7) :
    SelectedBudget nodeQuery (wotsChainProgram seed layer tree kp index start stop current) 7 := by
  exact selectedBudget_mono _ _ (by omega) (wots_chain_selected_budget seed layer tree kp index start stop current)

theorem wots_chain_selected_trace (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) (hs : seed.length = 32)
    (out : TraceOutput ByteKey Digest Randomizer)
    (ho : out ∈ (traceProgram digestDraw
      (wotsChainProgram seed layer tree kp index start stop current) table).support) :
    (out.queries.filter nodeQuery).length = stop - start := by
  exact traceProgram_chain_selected _ _ _ _
    (fun pos value => wots_chain_input_selected seed layer tree kp index pos value hs)
    _ _ _ _ _ ho

theorem wots_chain_no_steps (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp index start stop : ℕ) (current : Randomizer) (hs : stop ≤ start) :
    wotsChainSearch table seed layer tree kp index start stop current = PMF.pure (current, table) := by
  simp [wotsChainSearch, Nat.sub_eq_zero_of_le hs, chainLoop]

theorem wots_chain_split (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp index start mid stop : ℕ) (current : Randomizer)
    (hm : start ≤ mid) (hs : mid ≤ stop) :
    wotsChainSearch table seed layer tree kp index start stop current =
      (wotsChainSearch table seed layer tree kp index start mid current).bind (fun out =>
        wotsChainSearch out.2 seed layer tree kp index mid stop out.1) := by
  unfold wotsChainSearch
  rw [show stop - start = (mid - start) + (stop - mid) by omega, chainLoop_split]
  rw [show start + (mid - start) = mid by omega]

theorem wots_sign_digit_budget (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (index : Fin 43) (current : Randomizer) :
    SelectedBudget nodeQuery
      (wotsChainProgram seed layer tree kp index.val 0 (word index).val current) 7 := by
  exact wots_chain_seven_budget seed layer tree kp index.val 0 (word index).val current
    (by have h := (word index).isLt; omega)

theorem wots_recover_digit_budget (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (index : Fin 43) (current : Randomizer) :
    SelectedBudget nodeQuery
      (wotsChainProgram seed layer tree kp index.val (word index).val 7 current) 7 := by
  exact wots_chain_seven_budget seed layer tree kp index.val (word index).val 7 current (by omega)

theorem wots_sign_recover_chain (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (index : Fin 43) (current : Randomizer) :
    wotsChainSearch table seed layer tree kp index.val 0 7 current =
      (wotsChainSearch table seed layer tree kp index.val 0 (word index).val current).bind
        (fun out => wotsChainSearch out.2 seed layer tree kp index.val (word index).val 7 out.1) := by
  exact wots_chain_split table seed layer tree kp index.val 0 (word index).val 7 current
    (by omega) (by have h := (word index).isLt; omega)

end
end C10Probability
