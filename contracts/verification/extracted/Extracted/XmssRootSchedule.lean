/- Finite C10 tree geometry. The schedule certificate contains only natural
   indices and heights; it is checked by the Lean kernel, without native code
   axioms. Hash values and seeds do not occur in this certificate. -/
import Aeneas

namespace Extracted.Equiv

def xmssRootSlots (j : Nat) : List (Nat × Nat) :=
  (((List.range 10).reverse.filter fun h => j / 2^h % 2 == 1).map
    fun h => (h, j / 2^h - 1))

def xmssRootScheduleAt (j h : Nat) : Prop :=
  (j + 1) % 2^h = 0 →
  let slots := xmssRootSlots j
  let sp := slots.length - h
  h ≤ slots.length ∧
  (if sp > 0 ∧ slots[sp-1]!.1 = h then
    h < 9 ∧ slots[sp-1]!.2 = 2 * (j / 2^(h+1)) ∧
      j / 2^h = 2 * (j / 2^(h+1)) + 1 ∧
      (j+1) % 2^(h+1) = 0
   else
    sp < 10 ∧ xmssRootSlots (j+1) = slots.take sp ++ [(h, j / 2^h)])

instance (j h : Nat) : Decidable (xmssRootScheduleAt j h) := by
  unfold xmssRootScheduleAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem xmss_root_schedule :
    ∀ (j : Fin 512) (h : Fin 10), xmssRootScheduleAt j.val h.val := by
  decide +kernel

@[simp] theorem xmssRootSlots_zero : xmssRootSlots 0 = [] := by decide
@[simp] theorem xmssRootSlots_final : xmssRootSlots 512 = [(9, 0)] := by decide

end Extracted.Equiv
