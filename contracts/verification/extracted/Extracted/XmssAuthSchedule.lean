/- Finite geometry of authentication-path capture, independent of hash values. -/
import Extracted.XmssRootSchedule

namespace Extracted.Equiv

def xmssAuthSibling (leaf h : Nat) : Nat := (leaf / 2^h) ^^^ 1

def xmssAuthEnd (leaf h : Nat) : Nat := (leaf / 2^(h+1)+1)*2^(h+1)-1

def xmssAuthLeafAt (leaf h : Nat) : Prop :=
  let s := xmssAuthSibling leaf h
  let e := xmssAuthEnd leaf h
  s < 512 ∧ s*2^h < 512 ∧ e < 512 ∧
  (e+1) % 2^(h+1) = 0 ∧ e+1 = (e/2^(h+1)+1)*2^(h+1) ∧
  s = (if (leaf/2^h)%2 = 0 then leaf/2^h+1 else leaf/2^h-1) ∧
  (if s%2 = 0 then s = 2*(e/2^(h+1)) else s = 2*(e/2^(h+1))+1) ∧
  (s+1)*2^h ≤ 512

instance (leaf h : Nat) : Decidable (xmssAuthLeafAt leaf h) := by
  unfold xmssAuthLeafAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem xmss_auth_leaf_schedule :
    ∀ (leaf : Fin 512) (h : Fin 9), xmssAuthLeafAt leaf.val h.val := by
  decide +kernel

def xmssAuthCarryAt (j h : Nat) : Prop :=
  (j+1) % 2^h = 0 →
  let slots := xmssRootSlots j
  let sp := slots.length-h
  if sp > 0 ∧ slots[sp-1]!.1 = h then
    j+1 = (j/2^(h+1)+1)*2^(h+1)
  else
    (j+1) % 2^(h+1) ≠ 0

instance (j h : Nat) : Decidable (xmssAuthCarryAt j h) := by
  unfold xmssAuthCarryAt
  infer_instance

set_option maxRecDepth 100000 in
set_option maxHeartbeats 16000000 in
theorem xmss_auth_carry_schedule :
    ∀ (j : Fin 512) (h : Fin 10), xmssAuthCarryAt j.val h.val := by
  decide +kernel

end Extracted.Equiv
