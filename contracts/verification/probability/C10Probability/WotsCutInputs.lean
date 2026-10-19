import C10Probability.WotsTarget
import C10Probability.WotsInputBinding

/-! A selected intermediate node is the reply at its incoming chain key;
its outgoing commitment uses the next position. The position fields separate
those keys even when the two node values coincide. A raw incoming-key query
therefore supplies the preceding node as an ordinary input candidate. -/
namespace C10Probability
noncomputable section

theorem wots_chain_input_parts (seed : ByteKey)
    (layer tree kp index position layer' tree' kp' index' position' : ℕ)
    (node node' : Randomizer)
    (equal : wotsChainInput seed layer tree kp index position node =
      wotsChainInput seed layer' tree' kp' index' position' node') :
    c10Address layer tree 0 kp index position 0 =
        c10Address layer' tree' 0 kp' index' position' 0 ∧ node = node' := by
  simp only [wotsChainInput, List.append_assoc] at equal
  have joined := List.append_cancel_left equal
  have width : (c10Address layer tree 0 kp index position 0).length =
      (c10Address layer' tree' 0 kp' index' position' 0).length := by
    rw [c10_address_length, c10_address_length]
  exact ⟨List.append_inj_left joined width,
    node_block_injective (List.append_inj_right joined width)⟩

theorem c10_address_position (layer tree kind kp index position hashAddress : ℕ) :
    ((c10Address layer tree kind kp index position hashAddress).drop 24).take 4 =
      beBytes 4 position := by
  simp [c10Address, List.append_assoc, List.drop_append, be_bytes_length,
    List.drop_eq_nil_of_le]

theorem wots_chain_input_position_eq (seed : ByteKey)
    (layer tree kp index position layer' tree' kp' index' position' : ℕ)
    (node node' : Randomizer) (bound : position < 2 ^ 32) (bound' : position' < 2 ^ 32)
    (equal : wotsChainInput seed layer tree kp index position node =
      wotsChainInput seed layer' tree' kp' index' position' node') : position = position' := by
  have parts := wots_chain_input_parts seed _ _ _ _ _ _ _ _ _ _ _ _ equal
  have field := congrArg (fun bytes : ByteKey => (bytes.drop 24).take 4) parts.1
  apply be_bytes_four_injective bound bound'
  simpa only [c10_address_position] using field

theorem wots_chain_input_as_commit (seed : ByteKey) (layer tree kp index position : ℕ)
    (node : Randomizer) :
    (.inl (wotsChainInput seed layer tree kp index position node) : WotsQuery) =
      nodeCommitEncode node (seed ++ c10Address layer tree 0 kp index position 0) := by
  simp only [wotsChainInput, nodeCommitEncode, nodeBlock, List.append_assoc]

theorem wots_chain_input_decodes (seed : ByteKey) (layer tree kp index position : ℕ)
    (node : Randomizer) :
    nodeQueryDecode (.inl (wotsChainInput seed layer tree kp index position node)) = some node := by
  rw [wots_chain_input_as_commit, node_commit_decodes]

def wotsCutCommit (seed : ByteKey) (target : WotsCutTarget) (node : Randomizer)
    (_ : Unit) : WotsQuery :=
  .inl (wotsChainInput seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
    (wotsTargetKp target.1) target.1.2.val target.2.val node)

def wotsCutIncoming (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer) : WotsQuery :=
  if target.2.val = 0 then wotsTargetKey target.1 else
    .inl (wotsChainInput seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
      (wotsTargetKp target.1) target.1.2.val (target.2.val - 1) previous)

theorem wots_cut_commit_decodes (seed : ByteKey) (target : WotsCutTarget)
    (node : Randomizer) (label : Unit) :
    nodeQueryDecode (wotsCutCommit seed target node label) = some node := by
  exact wots_chain_input_decodes seed _ _ _ _ _ node

theorem wots_cut_commit_labels_injective (seed : ByteKey) (target : WotsCutTarget)
    (node : Randomizer) : Function.Injective (wotsCutCommit seed target node) := by
  intro first second _
  exact Subsingleton.elim first second

theorem wots_cut_incoming_zero (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (zero : target.2.val = 0) :
    wotsCutIncoming seed target previous = wotsTargetKey target.1 := by
  simp only [wotsCutIncoming, zero, ↓reduceIte]

theorem wots_cut_incoming_positive (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (positive : 0 < target.2.val) :
    wotsCutIncoming seed target previous = .inl
      (wotsChainInput seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
        (wotsTargetKp target.1) target.1.2.val (target.2.val - 1) previous) := by
  simp only [wotsCutIncoming, Nat.ne_of_gt positive, ↓reduceIte]

theorem wots_cut_commit_ne_incoming (seed : ByteKey) (target : WotsCutTarget)
    (node previous : Randomizer) (label : Unit) :
    wotsCutCommit seed target node label ≠ wotsCutIncoming seed target previous := by
  intro equal
  by_cases zero : target.2.val = 0
  · rw [wots_cut_incoming_zero seed target previous zero] at equal
    exact wots_target_not_public target.1 _ equal
  · rw [wots_cut_incoming_positive seed target previous (by omega)] at equal
    have position := wots_chain_input_position_eq seed _ _ _ _ _ _ _ _ _ _ node previous
      (by have := target.2.isLt; omega) (by have := target.2.isLt; omega) (Sum.inl.inj equal)
    omega

theorem wots_cut_incoming_candidate (seed : ByteKey) (target : WotsCutTarget)
    (previous : Randomizer) (positive : 0 < target.2.val) (key : ByteKey)
    (equal : (.inl key : WotsQuery) = wotsCutIncoming seed target previous) :
    nodeQueryDecode (.inl key) = some previous := by
  rw [equal, wots_cut_incoming_positive seed target previous positive]
  exact wots_chain_input_decodes seed _ _ _ _ _ previous

end
end C10Probability
