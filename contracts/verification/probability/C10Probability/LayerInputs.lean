import C10Probability.WotsSigning
import C10Probability.ShuffleDerive

/-! Manual hypertree coordinates and the complete seven-byte WOTS labels.
Natural count arguments retain the full 32-byte encoding. Rust's u32 counter
domain is a separate, explicit property of supplied or returned signatures. -/
namespace C10Probability
noncomputable section

def layerShuffleLabel (layer : ℕ) : ByteKey :=
  if layer = 0 then [119,111,116,115,45,48,0] else [119,111,116,115,45,49,0]

theorem layer_shuffle_label_length (layer : ℕ) : (layerShuffleLabel layer).length = 7 := by
  unfold layerShuffleLabel
  split <;> rfl

theorem layer_shuffle_input_length (seed : ByteKey) (layer : ℕ) (hs : seed.length = 32) :
    (shuffleDeriveInput seed (layerShuffleLabel layer)).length = 61 := by
  rw [shuffle_derive_input_length seed _ hs, layer_shuffle_label_length]

def hypertreeIndex (digest : Digest) : ℕ := digest.val / 2 ^ 143 % 2 ^ 18

def hypertreeLeaf (index : ℕ) : ℕ := index % 512

def hypertreeParent (index : ℕ) : ℕ := index / 512

theorem hypertree_index_bound (digest : Digest) : hypertreeIndex digest < 2 ^ 18 :=
  Nat.mod_lt _ (by decide)

theorem hypertree_leaf_bound (index : ℕ) : hypertreeLeaf index < 512 :=
  Nat.mod_lt _ (by decide)

theorem hypertree_coordinate_split (index : ℕ) :
    hypertreeLeaf index + 512 * hypertreeParent index = index := by
  exact Nat.mod_add_div index 512

theorem hypertree_first_parent_bound (digest : Digest) :
    hypertreeParent (hypertreeIndex digest) < 512 := by
  have hb := hypertree_index_bound digest
  unfold hypertreeParent
  omega

theorem hypertree_second_parent_zero (digest : Digest) :
    hypertreeParent (hypertreeParent (hypertreeIndex digest)) = 0 := by
  exact Nat.div_eq_of_lt (hypertree_first_parent_bound digest)

def wotsRecoverCountInput (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (count : ℕ) : ByteKey :=
  wotsCountStem seed layer tree kp message ++ beBytes 32 count

theorem wots_recover_counter_input (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (count : Counter) :
    wotsRecoverCountInput seed layer tree kp message count.val =
      counterKey (wotsCountStem seed layer tree kp message) count := by
  rw [wotsRecoverCountInput, be_bytes_counter]
  rfl

theorem wots_recover_count_length (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (count : ℕ) (hs : seed.length = 32) (hm : message.length = 16) :
    (wotsRecoverCountInput seed layer tree kp message count).length = 128 := by
  simp [wotsRecoverCountInput, wotsCountStem, c10_address_length, be_bytes_length, hs, hm]

theorem wots_recover_count_excluded (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (count : ℕ) (hs : seed.length = 32) (hm : message.length = 16) :
    nodeQuery (wotsRecoverCountInput seed layer tree kp message count) = false := by
  have ht : ((wotsRecoverCountInput seed layer tree kp message count).drop 44).take 4 =
      List.replicate 4 0 := by
    have he : wotsRecoverCountInput seed layer tree kp message count =
        seed ++ c10Address layer tree 0 kp 0 0 0 ++
          (message ++ List.replicate 16 0 ++ beBytes 32 count) := by
      simp only [wotsRecoverCountInput, wotsCountStem, List.append_assoc]
    rw [he, node_input_tag _ _ _ hs (c10_address_length _ _ _ _ _ _ _),
      c10_address_count_kind]
  rw [nodeQuery, wots_recover_count_length _ _ _ _ _ _ hs hm, ht]
  decide

structure LayerSignature where
  sigma : WotsSigma
  count : ℕ
  auth : List Randomizer

def emptyLayerSignature : LayerSignature := ⟨fun _ => 0, 0, []⟩

def LayerSignatureWellFormed (sig : LayerSignature) : Prop :=
  sig.count < 2 ^ 32 ∧ sig.auth.length = 9

def nodeValueBytes (value : Randomizer) : ByteKey :=
  List.ofFn (randomizerBytesEquiv.symm value)

theorem node_value_bytes_length (value : Randomizer) : (nodeValueBytes value).length = 16 := by
  simp [nodeValueBytes]

theorem node_value_block (value : Randomizer) :
    nodeBlock value = nodeValueBytes value ++ List.replicate 16 0 := by rfl

end
end C10Probability
