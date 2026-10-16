import C10Probability.WotsChain

/-! Ordered WOTS public-key compression in the same full-digest memo oracle.
The input is manually transcribed from RawWots.recover and hash::th_multi. -/
namespace C10Probability
noncomputable section

def nodeBlock (value : Randomizer) : ByteKey :=
  List.ofFn (randomizerBytesEquiv.symm value) ++ List.replicate 16 0

theorem node_block_length (value : Randomizer) : (nodeBlock value).length = 32 := by
  simp [nodeBlock]

theorem node_block_digest (digest : Digest) :
    nodeBlock (randomizerOfDigest digest) =
      List.ofFn (nodeBytes digest) ++ List.replicate 16 0 := by
  rw [nodeBlock, wots_chain_reply_bytes]

theorem node_blocks_length (values : List Randomizer) :
    (values.flatMap nodeBlock).length = 32 * values.length := by
  induction values with
  | nil => simp
  | cons value rest ih =>
    simp only [List.flatMap_cons, List.length_append, node_block_length, ih,
      List.length_cons, Nat.mul_add, Nat.mul_one]
    omega

def wotsPkInput (seed : ByteKey) (layer tree kp : ℕ) (values : List Randomizer) : ByteKey :=
  seed ++ c10Address layer tree 1 kp 0 0 0 ++ values.flatMap nodeBlock

theorem wots_pk_input_length (seed : ByteKey) (layer tree kp : ℕ)
    (values : List Randomizer) (hs : seed.length = 32) (hv : values.length = 43) :
    (wotsPkInput seed layer tree kp values).length = 1440 := by
  simp only [wotsPkInput, List.length_append, c10_address_length,
    node_blocks_length, hs, hv]

theorem wots_pk_input_selected (seed : ByteKey) (layer tree kp : ℕ)
    (values : List Randomizer) (hs : seed.length = 32) (hv : values.length = 43) :
    nodeQuery (wotsPkInput seed layer tree kp values) = true := by
  exact node_query_node_widths _ (Or.inr (Or.inr
    (wots_pk_input_length seed layer tree kp values hs hv)))

def wotsCompressProgram (seed : ByteKey) (layer tree kp : ℕ)
    (values : List Randomizer) : QueryProgram ByteKey Digest Randomizer 1 :=
  .query (wotsPkInput seed layer tree kp values)
    (fun digest => .done (randomizerOfDigest digest))

def wotsCompress (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (values : List Randomizer) : PMF (Randomizer × Memo ByteKey Digest) :=
  (memoQuery digestDraw table (wotsPkInput seed layer tree kp values)).map
    (fun reply => (randomizerOfDigest reply.1, reply.2))

theorem wots_compress_eval (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (values : List Randomizer) :
    evalProgram digestDraw (wotsCompressProgram seed layer tree kp values) table =
      wotsCompress table seed layer tree kp values := by
  rfl

theorem wots_compress_cached (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (values : List Randomizer) (digest : Digest)
    (cached : table (wotsPkInput seed layer tree kp values) = some digest) :
    wotsCompress table seed layer tree kp values = PMF.pure (randomizerOfDigest digest, table) := by
  rw [wotsCompress, memoQuery_cached _ _ _ _ cached, PMF.pure_map]

theorem wots_compress_budget (seed : ByteKey) (layer tree kp : ℕ)
    (values : List Randomizer) :
    SelectedBudget nodeQuery (wotsCompressProgram seed layer tree kp values) 1 := by
  exact selectedBudget_total _ _

end
end C10Probability
