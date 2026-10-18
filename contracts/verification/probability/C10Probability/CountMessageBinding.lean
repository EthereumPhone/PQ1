import C10Probability.CountReplay
import C10Probability.AcceptedObserver
import C10Probability.NodeInputBinding

/-! Equality of accepted words alone does not bind their messages. At a fixed
logical address, actual count lookups either bind the 16-byte node message or
exhibit two distinct public inputs with the same accepted word. Counts retain
their full 32-byte encoding; no count bound or hash injectivity is assumed. -/
namespace C10Probability
noncomputable section

def AcceptedWotsCollision (cache : Memo ByteKey Digest) : Prop :=
  ∃ key other value reply, cache key = some value ∧ cache other = some reply ∧
    wotsAccept (wotsOfDigest value) = true ∧
    wotsOfDigest value = wotsOfDigest reply ∧ key ≠ other

theorem accepted_wots_collision_iff (cache : Memo ByteKey Digest) :
    AcceptedWotsCollision cache ↔ ¬ AcceptedCollisionFree wotsOfDigest wotsAccept cache := by
  classical
  simp only [AcceptedWotsCollision, AcceptedCollisionFree, not_forall, exists_prop]

theorem node_value_bytes_injective : Function.Injective nodeValueBytes := by
  intro first second equal
  exact randomizerBytesEquiv.symm.injective (List.ofFn_injective equal)

theorem wots_count_input_message_eq (seed : ByteKey) (layer tree kp : ℕ)
    (first second : ByteKey) (count other : ℕ) (width : first.length = second.length)
    (equal : wotsRecoverCountInput seed layer tree kp first count =
      wotsRecoverCountInput seed layer tree kp second other) : first = second := by
  simp only [wotsRecoverCountInput, wotsCountStem, List.append_assoc] at equal
  exact List.append_inj_left
    (List.append_cancel_left (List.append_cancel_left equal)) width

theorem wots_count_input_node_eq (seed : ByteKey) (layer tree kp : ℕ)
    (first second : Randomizer) (count other : ℕ)
    (equal : wotsRecoverCountInput seed layer tree kp (nodeValueBytes first) count =
      wotsRecoverCountInput seed layer tree kp (nodeValueBytes second) other) : first = second := by
  exact node_value_bytes_injective (wots_count_input_message_eq seed layer tree kp _ _ count other
    (by rw [node_value_bytes_length, node_value_bytes_length]) equal)

theorem accepted_count_message_cases (cache : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (first second : Randomizer) (count other : ℕ)
    (value reply : Digest)
    (left : cache (wotsRecoverCountInput seed layer tree kp (nodeValueBytes first) count) = some value)
    (right : cache (wotsRecoverCountInput seed layer tree kp (nodeValueBytes second) other) = some reply)
    (accepted : wotsAccept (wotsOfDigest value) = true)
    (same : wotsOfDigest value = wotsOfDigest reply) :
    first = second ∨ AcceptedWotsCollision cache := by
  classical
  by_cases equal : wotsRecoverCountInput seed layer tree kp (nodeValueBytes first) count =
      wotsRecoverCountInput seed layer tree kp (nodeValueBytes second) other
  · exact Or.inl (wots_count_input_node_eq seed layer tree kp first second count other equal)
  · exact Or.inr ⟨_, _, value, reply, left, right, accepted, same, equal⟩

end
end C10Probability
