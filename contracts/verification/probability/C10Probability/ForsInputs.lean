import C10Probability.MerkleInputs

/-! Manual FORS byte inputs. The private label contains the tag once and all
three coordinates; physical interpretation supplies the secret prefix. Public
leaf/pair inputs retain kind3 and compression retains kind4 and all13 roots. -/
namespace C10Probability
noncomputable section

def forsTag : ByteKey := [102, 111, 114, 115]

def forsPrivateTail (ht tree leaf : ℕ) : ByteKey :=
  forsTag ++ beBytes 4 ht ++ beBytes 4 tree ++ beBytes 4 leaf

theorem fors_private_tail_length (ht tree leaf : ℕ) :
    (forsPrivateTail ht tree leaf).length = 16 := by
  simp [forsPrivateTail, forsTag, be_bytes_length]

theorem fors_private_input_length (secret : Digest) (ht tree leaf : ℕ) :
    (prefixedPrivateInput secret (forsPrivateTail ht tree leaf)).length = 48 := by
  simp [prefixedPrivateInput, secretBytes, fors_private_tail_length]

theorem fors_private_input_selected (secret : Digest) (ht tree leaf : ℕ) :
    nodeQuery (prefixedPrivateInput secret (forsPrivateTail ht tree leaf)) = true := by
  apply node_query_other_width <;> simp [fors_private_input_length]

def forsLeafInput (seed : ByteKey) (ht tree leaf : ℕ) (secret : Randomizer) : ByteKey :=
  seed ++ c10Address 0 ht 3 tree 0 0 leaf ++ nodeBlock secret

def forsPairInput (seed : ByteKey) (ht tree height parent : ℕ)
    (left right : Randomizer) : ByteKey :=
  seed ++ c10Address 0 ht 3 tree 0 (height + 1) parent ++ nodeBlock left ++ nodeBlock right

def forsTreePairInput (seed : ByteKey) (ht tree leaf height : ℕ)
    (left right : Randomizer) : ByteKey :=
  forsPairInput seed ht tree height (leaf / 2 ^ (height + 1)) left right

def forsPkInput (seed : ByteKey) (ht : ℕ) (roots : List Randomizer) : ByteKey :=
  seed ++ c10Address 0 ht 4 0 0 0 0 ++ roots.flatMap nodeBlock

def forestIndex (digest : Digest) (tree : ℕ) : ℕ := digest.val / 2 ^ (11 * tree) % 2048

theorem forest_index_bound (digest : Digest) (tree : ℕ) : forestIndex digest tree < 2048 := by
  exact Nat.mod_lt _ (by decide)

theorem fors_leaf_input_length (seed : ByteKey) (ht tree leaf : ℕ) (secret : Randomizer)
    (hs : seed.length = 32) : (forsLeafInput seed ht tree leaf secret).length = 96 := by
  simp [forsLeafInput, hs, c10_address_length, node_block_length]

theorem fors_pair_input_length (seed : ByteKey) (ht tree height parent : ℕ)
    (left right : Randomizer) (hs : seed.length = 32) :
    (forsPairInput seed ht tree height parent left right).length = 128 := by
  simp [forsPairInput, hs, c10_address_length, node_block_length]

theorem fors_pk_input_length (seed : ByteKey) (ht : ℕ) (roots : List Randomizer)
    (hs : seed.length = 32) (hr : roots.length = 13) :
    (forsPkInput seed ht roots).length = 480 := by
  simp only [forsPkInput, List.length_append, c10_address_length,
    node_blocks_length, hs, hr]

theorem fors_leaf_input_selected (seed : ByteKey) (ht tree leaf : ℕ) (secret : Randomizer)
    (hs : seed.length = 32) : nodeQuery (forsLeafInput seed ht tree leaf secret) = true := by
  apply node_query_other_width <;> simp [fors_leaf_input_length _ _ _ _ _ hs]

theorem fors_pair_input_selected (seed : ByteKey) (ht tree height parent : ℕ)
    (left right : Randomizer) (hs : seed.length = 32) :
    nodeQuery (forsPairInput seed ht tree height parent left right) = true := by
  unfold forsPairInput nodeBlock
  simp only [← List.append_assoc]
  apply node_query_pair _ _ _ _ hs (c10_address_length _ _ _ _ _ _ _)
    (by simp) (by simp)
  rw [c10_address_kind]
  decide +kernel

theorem fors_pk_input_selected (seed : ByteKey) (ht : ℕ) (roots : List Randomizer)
    (hs : seed.length = 32) (hr : roots.length = 13) :
    nodeQuery (forsPkInput seed ht roots) = true := by
  apply node_query_other_width <;> simp [fors_pk_input_length _ _ _ hs hr]

end
end C10Probability
