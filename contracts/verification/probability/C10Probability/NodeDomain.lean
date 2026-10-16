import C10Probability.SharedRandomizer

/-! Manual byte-domain transcription of EasyCrypt `NodeQueryDomain.node_query`.
Exclude every160-byte key and zero-kind128-byte keys, retaining every other raw
key, including malformed inputs. This selector is not a parser or allowlist. -/
namespace C10Probability
noncomputable section

def nodeQuery (key : ByteKey) : Bool :=
  decide (key.length ≠ 160 ∧
    (key.length ≠ 128 ∨ (key.drop 44).take 4 ≠ List.replicate 4 0))

theorem node_query_other_width (key : ByteKey) (hh : key.length ≠ 160)
    (hc : key.length ≠ 128) : nodeQuery key = true := by
  simp [nodeQuery, hh, hc]

theorem node_query_no_160 (key : ByteKey) (hw : key.length = 160) :
    nodeQuery key = false := by simp [nodeQuery, hw]

theorem node_query_no_hmsg (seed root message : ByteKey) (r : Randomizer)
    (hs : seed.length = 32) (hr : root.length = 32) (hm : message.length = 32) :
    nodeQuery (hmsgRandomizerInput seed root message r) = false :=
  node_query_no_160 _ (hmsg_randomizer_length seed root message r hs hr hm)

theorem node_input_tag (seed address payload : ByteKey)
    (hs : seed.length = 32) (ha : address.length = 32) :
    ((seed ++ address ++ payload).drop 44).take 4 = (address.drop 12).take 4 := by
  rw [List.append_assoc, List.drop_append]
  simp only [List.drop_eq_nil_of_le (show seed.length ≤ 44 by omega), hs,
    List.nil_append]
  norm_num
  rw [List.drop_append_of_le_length (show 12 ≤ address.length by omega),
    List.take_append_of_le_length (show 4 ≤ (address.drop 12).length by simp [ha])]

theorem node_query_no_count (seed address message : ByteKey) (nonce : Counter)
    (hs : seed.length = 32) (ha : address.length = 32) (hm : message.length = 16)
    (hk : (address.drop 12).take 4 = List.replicate 4 0) :
    nodeQuery (counterKey (seed ++ address ++ message ++ List.replicate 16 0) nonce) =
      false := by
  have hw : (counterKey (seed ++ address ++ message ++ List.replicate 16 0) nonce).length =
      128 := by simp [counter_key_length, hs, ha, hm]
  have ht : ((counterKey (seed ++ address ++ message ++ List.replicate 16 0) nonce).drop 44).take 4 =
      List.replicate 4 0 := by
    have he : counterKey (seed ++ address ++ message ++ List.replicate 16 0) nonce =
        seed ++ address ++ (message ++ List.replicate 16 0 ++ List.ofFn (counterBytes nonce)) := by
      simp only [counterKey, List.append_assoc]
    rw [he, node_input_tag seed address _ hs ha, hk]
  rw [nodeQuery, hw, ht]
  decide

theorem node_query_chain (seed address value : ByteKey)
    (hs : seed.length = 32) (ha : address.length = 32) (hv : value.length = 16) :
    nodeQuery (seed ++ address ++ value ++ List.replicate 16 0) = true := by
  apply node_query_other_width <;> simp [hs, ha, hv]

theorem node_query_pair (seed address lhs rhs : ByteKey)
    (hs : seed.length = 32) (ha : address.length = 32)
    (hl : lhs.length = 16) (hr : rhs.length = 16)
    (hk : (address.drop 12).take 4 ≠ List.replicate 4 0) :
    nodeQuery (seed ++ address ++ lhs ++ List.replicate 16 0 ++ rhs ++ List.replicate 16 0) =
      true := by
  have hw : (seed ++ address ++ lhs ++ List.replicate 16 0 ++ rhs ++ List.replicate 16 0).length =
      128 := by simp [hs, ha, hl, hr]
  have ht : ((seed ++ address ++ lhs ++ List.replicate 16 0 ++ rhs ++ List.replicate 16 0).drop 44).take 4 =
      (address.drop 12).take 4 := by
    have he : seed ++ address ++ lhs ++ List.replicate 16 0 ++ rhs ++ List.replicate 16 0 =
        seed ++ address ++ (lhs ++ List.replicate 16 0 ++ rhs ++ List.replicate 16 0) := by
      simp only [List.append_assoc]
    rw [he, node_input_tag seed address _ hs ha]
  rw [nodeQuery, hw, ht]
  simp only [ne_eq, hk, not_false_eq_true, or_true, and_true, decide_eq_true_eq]
  decide

theorem node_query_node_widths (key : ByteKey)
    (hw : key.length = 96 ∨ key.length = 480 ∨ key.length = 1440) : nodeQuery key = true := by
  apply node_query_other_width <;> omega

theorem node_query_r_input (secret random message : ByteKey) (nonce : Counter)
    (hs : secret.length = 32) (hm : message.length = 32)
    (hr : random.length = 0 ∨ random.length = 16) :
    nodeQuery (rDerivationInput secret random message nonce) = true := by
  have hw := r_input_length secret random message nonce hs hm
  apply node_query_other_width <;> omega

end
end C10Probability
