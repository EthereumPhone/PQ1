/-
ByteVec extra lemmas — what the rest of the project relies on.

Each lemma here is closed (no `sorry`); they are pure structural
reasoning about `ByteVec`'s `Array UInt8`-backed representation.
-/

import SphincsCVerify.Spec.Bytes

namespace SphincsCVerify.Spec.ByteVec

/-! ## Cast lemmas -/

theorem cast_size {m n : Nat} (h : m = n) (v : ByteVec m) :
    (cast h v).data = v.data := rfl

theorem cast_self (v : ByteVec n) : cast rfl v = v := rfl

/-! ## Append size -/

theorem append_size {m n : Nat} (xs : ByteVec m) (ys : ByteVec n) :
    (append xs ys).data.size = m + n := (append xs ys).size_eq

/-! ## zero / ones -/

theorem zero_size (n : Nat) : (zero n).data.size = n := (zero n).size_eq
theorem ones_size (n : Nat) : (ones n).data.size = n := (ones n).size_eq

end SphincsCVerify.Spec.ByteVec
