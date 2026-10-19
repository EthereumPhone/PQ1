import C10Probability.CandidateBudget
import C10Probability.ForsInputs

/-! The selected hidden value is the high128-bit node of a full digest.
Every sufficiently long raw public input contributes the first16 bytes of its
last32-byte block, even if the rest of that block has malformed padding. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def nodeOfBlock (bytes : ByteKey) : Randomizer :=
  randomizerBytesEquiv fun i => (bytes[i.val]?).getD 0

def decodeNodeSlot (key : ByteKey) : Option Randomizer :=
  if 32 ≤ key.length then some (nodeOfBlock (key.drop (key.length - 32))) else none

theorem decode_node_slot_short (key : ByteKey) (short : key.length < 32) :
    decodeNodeSlot key = none := by
  simp only [decodeNodeSlot, Nat.not_le_of_lt short, ↓reduceIte]

theorem decode_node_slot_append (stem block : ByteKey) (width : block.length = 32) :
    decodeNodeSlot (stem ++ block) = some (nodeOfBlock block) := by
  simp [decodeNodeSlot, List.length_append, width]

theorem node_of_block_node (value : Randomizer) : nodeOfBlock (nodeBlock value) = value := by
  apply randomizerBytesEquiv.symm.injective
  simp only [nodeOfBlock, Equiv.symm_apply_apply]
  funext i
  rw [nodeBlock, List.getElem?_eq_getElem (by simp; omega)]
  simp only [Option.getD_some]
  rw [List.getElem_append_left (by simpa only [List.length_ofFn] using i.isLt)]
  simp only [List.getElem_ofFn]

theorem node_of_block_replicate (byte : Fin 256) :
    nodeOfBlock (List.replicate 32 byte) = randomizerBytesEquiv (fun _ => byte) := by
  apply congrArg randomizerBytesEquiv
  funext i
  simp only [List.getElem?_replicate_of_lt (show i.val < 32 by omega), Option.getD_some]

theorem randomizer_zero_bytes (i : Fin 16) : randomizerBytesEquiv.symm 0 i = 0 := by
  apply Fin.ext
  rw [randomizer_byte_value]
  simp

theorem node_of_block_counter (nonce : Counter) :
    nodeOfBlock (List.ofFn (counterBytes nonce)) = 0 := by
  apply randomizerBytesEquiv.symm.injective
  simp only [nodeOfBlock, Equiv.symm_apply_apply]
  funext i
  rw [List.getElem?_eq_getElem (by simp; omega), List.getElem_ofFn]
  simp only [Option.getD_some, randomizer_zero_bytes]
  exact counter_leading_zero nonce ⟨i.val, by omega⟩ (by change i.val < 28; omega)

theorem decode_node_slot_counter (stem : ByteKey) (nonce : Counter) :
    decodeNodeSlot (counterKey stem nonce) = some 0 := by
  rw [counterKey, decode_node_slot_append _ _ (by simp), node_of_block_counter]

def allFFNode : Randomizer := randomizerBytesEquiv (fun _ => 255)

theorem all_ff_node_value : allFFNode.val = 2 ^ 128 - 1 := by decide +kernel

theorem decode_node_slot_hmsg (seed root message : ByteKey) (randomizer : Randomizer) :
    decodeNodeSlot (hmsgRandomizerInput seed root message randomizer) = some allFFNode := by
  simp only [hmsgRandomizerInput, ← List.append_assoc]
  rw [decode_node_slot_append _ _ (by simp), node_of_block_replicate]
  rfl

def fixedNodeCandidates : Finset Randomizer := {0, allFFNode}

theorem fixed_node_candidates_card : fixedNodeCandidates.card = 2 := by decide +kernel

def nodeQueryDecode : WotsQuery → Option Randomizer
  | .inl key => decodeNodeSlot key
  | .inr _ => none

def nodeCommitEncode (secret : Randomizer) (label : ByteKey) : WotsQuery :=
  .inl (label ++ nodeBlock secret)

theorem node_commit_decodes (secret : Randomizer) (label : ByteKey) :
    nodeQueryDecode (nodeCommitEncode secret label) = some secret := by
  simp only [nodeQueryDecode, nodeCommitEncode,
    decode_node_slot_append label _ (node_block_length secret), node_of_block_node]

theorem node_commit_labels_injective (secret : Randomizer) :
    Function.Injective (nodeCommitEncode secret) := by
  intro first second equal
  exact List.append_cancel_right (Sum.inl.inj equal)

theorem node_private_candidate_excluded (tail : ByteKey) :
    variableCandidate nodeQueryDecode fixedNodeCandidates (.inr tail) = false := by rfl

theorem node_counter_candidate_fixed (stem : ByteKey) (nonce : Counter) :
    variableCandidate nodeQueryDecode fixedNodeCandidates (.inl (counterKey stem nonce)) = false := by
  simp [variableCandidate, nodeQueryDecode, decode_node_slot_counter, fixedNodeCandidates]

theorem node_hmsg_candidate_fixed (seed root message : ByteKey) (randomizer : Randomizer) :
    variableCandidate nodeQueryDecode fixedNodeCandidates
      (.inl (hmsgRandomizerInput seed root message randomizer)) = false := by
  simp [variableCandidate, nodeQueryDecode, decode_node_slot_hmsg, fixedNodeCandidates]

theorem node_opening_candidate_bound {R : Type*} {n : ℕ}
    (client : PMF (OpeningProgram WotsQuery ByteKey Digest Digest R n)) (q m : ℕ)
    (budget : ∀ program ∈ client.support,
      SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
        (redactOpening program) q)
    (candidates : R → Finset Randomizer) (count : ∀ value, (candidates value).card ≤ m) :
    (openingGame digestDraw digestDraw nodeCommitEncode randomizerOfDigest client).toOuterMeasure
      (candidateEvent (openingCandidates candidates)) ≤
        ((q + 2 + m : ℕ) : ℝ≥0∞) / 2 ^ 128 := by
  simpa only [fixed_node_candidates_card, Randomizer, Fintype.card_fin,
    Nat.cast_pow, Nat.cast_ofNat] using
    opening_variable_candidate_bound digestDraw digestDraw nodeCommitEncode nodeQueryDecode
      randomizerOfDigest randomizer_uniform node_commit_decodes node_commit_labels_injective
      client fixedNodeCandidates q m budget candidates count

end
end C10Probability
