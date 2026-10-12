/- Finite C10 tree geometry. The schedule certificate contains only natural
   indices and heights; it is checked by the Lean kernel, without native code
   axioms. Hash values and seeds do not occur in this certificate. -/
import Aeneas

namespace Extracted.Equiv

def forsRootSlots (j : Nat) : List (Nat × Nat) :=
  (((List.range 12).reverse.filter fun h => j / 2^h % 2 == 1).map
    fun h => (h, j / 2^h - 1))

def forsRootScheduleAt (j h : Nat) : Prop :=
  (j + 1) % 2^h = 0 →
  let slots := forsRootSlots j
  let sp := slots.length - h
  h ≤ slots.length ∧
  (if sp > 0 ∧ slots[sp-1]!.1 = h then
    h < 11 ∧ slots[sp-1]!.2 = 2 * (j / 2^(h+1)) ∧
      j / 2^h = 2 * (j / 2^(h+1)) + 1 ∧
      (j+1) % 2^(h+1) = 0
   else
    sp < 12 ∧ forsRootSlots (j+1) = slots.take sp ++ [(h, j / 2^h)])

instance (j h : Nat) : Decidable (forsRootScheduleAt j h) := by
  unfold forsRootScheduleAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem fors_root_schedule :
    ∀ (j : Fin 2048) (h : Fin 12), forsRootScheduleAt j.val h.val := by
  decide +kernel

@[simp] theorem forsRootSlots_zero : forsRootSlots 0 = [] := by decide
@[simp] theorem forsRootSlots_final : forsRootSlots 2048 = [(11, 0)] := by decide

end Extracted.Equiv
