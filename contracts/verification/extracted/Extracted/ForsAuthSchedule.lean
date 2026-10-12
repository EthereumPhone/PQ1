/- Finite geometry of authentication-path capture, independent of hash values. -/
import Extracted.ForsRootSchedule

namespace Extracted.Equiv

def forsAuthSibling (leaf h : Nat) : Nat := (leaf / 2^h) ^^^ 1

def forsAuthEnd (leaf h : Nat) : Nat := (leaf / 2^(h+1)+1)*2^(h+1)-1

def forsAuthLeafAt (leaf h : Nat) : Prop :=
  let s := forsAuthSibling leaf h
  let e := forsAuthEnd leaf h
  s < 2048 ∧ s*2^h < 2048 ∧ e < 2048 ∧
  (e+1) % 2^(h+1) = 0 ∧ e+1 = (e/2^(h+1)+1)*2^(h+1) ∧
  s = (if (leaf/2^h)%2 = 0 then leaf/2^h+1 else leaf/2^h-1) ∧
  (if s%2 = 0 then s = 2*(e/2^(h+1)) else s = 2*(e/2^(h+1))+1) ∧
  (s+1)*2^h ≤ 2048

instance (leaf h : Nat) : Decidable (forsAuthLeafAt leaf h) := by
  unfold forsAuthLeafAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem fors_auth_leaf_schedule :
    ∀ (leaf : Fin 2048) (h : Fin 11), forsAuthLeafAt leaf.val h.val := by
  decide +kernel

def forsAuthCarryAt (j h : Nat) : Prop :=
  (j+1) % 2^h = 0 →
  let slots := forsRootSlots j
  let sp := slots.length-h
  if sp > 0 ∧ slots[sp-1]!.1 = h then
    j+1 = (j/2^(h+1)+1)*2^(h+1)
  else
    (j+1) % 2^(h+1) ≠ 0

instance (j h : Nat) : Decidable (forsAuthCarryAt j h) := by
  unfold forsAuthCarryAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem fors_auth_carry_schedule :
    ∀ (j : Fin 2048) (h : Fin 12), forsAuthCarryAt j.val h.val := by
  decide +kernel

end Extracted.Equiv
