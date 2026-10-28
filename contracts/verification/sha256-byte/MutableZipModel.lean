module
public import Aeneas.Std
public import Aeneas.Tactic
@[expose] public section

/- Exploratory, source-scoped library model, not an adopted Aeneas backend.
   The selected Rust IterMut/ChunksExact pair implements TrustedRandomAccess.
   Its ZipImpl uses its own index/len, leaving both underlying cursors intact.
   The profile must reject any other concrete Zip instantiation. -/
namespace PQ1Research.MutableZip
open Aeneas Aeneas.Std Result

structure MutableIterator (Self Item : Type) where
  next : Self → Result (Option Item × Self × (Self → Option Item → Self))

def iterMutWitness (T : Type) :
    MutableIterator (core.slice.iter.IterMut T) T :=
  ⟨core.slice.iter.IteratorIterMut.next⟩

structure ZipState (A B : Type) where
  fst : A
  snd : B
  index : Nat
  len : Nat

abbrev State (T U : Type) :=
  ZipState (core.slice.iter.IterMut T) (core.slice.iter.ChunksExact U)

def valid {T U : Type} (z : State T U) : Prop :=
  z.fst.i ≤ z.fst.slice.length ∧
  z.len = min (z.fst.slice.length - z.fst.i) z.snd.chunks.length ∧
  z.index ≤ z.len

def putBack {T U : Type} (position : Nat) (z : State T U)
    (item : Option (T × Slice U)) : State T U :=
  match item with
  | none => z
  | some (word, _) =>
      { z with fst := { z.fst with slice := z.fst.slice.setAtNat position word } }

def make {T U : Type}
    (_IA : MutableIterator (core.slice.iter.IterMut T) T)
    (IB : core.iter.traits.collect.IntoIterator
      (core.slice.iter.ChunksExact U) (Slice U) (core.slice.iter.ChunksExact U))
    (a : core.slice.iter.IterMut T) (b : core.slice.iter.ChunksExact U) :
    Result (State T U × (State T U → core.slice.iter.IterMut T)) := do
  let b' ← IB.into_iter b
  ok (⟨a, b', 0, min (a.slice.length - a.i) b'.chunks.length⟩, fun z => z.fst)

def next {T U : Type}
    (_IA : MutableIterator (core.slice.iter.IterMut T) T)
    (_IB : core.iter.traits.iterator.Iterator (core.slice.iter.ChunksExact U) (Slice U))
    (z : State T U) :
    Result (Option (T × Slice U) × State T U ×
      (State T U → Option (T × Slice U) → State T U)) :=
  if z.index < z.len then
    if ha : z.fst.i + z.index < z.fst.slice.length then
      if hb : z.index < z.snd.chunks.length then
        ok (some (z.fst.slice[z.fst.i + z.index], z.snd.chunks[z.index]),
          { z with index := z.index + 1 }, putBack (z.fst.i + z.index))
      else fail .panic
    else fail .panic
  else ok (none, z, fun state _ => state)

theorem putBack_none {T U : Type} (p : Nat) (z : State T U) :
    putBack p z none = z := rfl

theorem putBack_frame {T U : Type} (p : Nat) (z : State T U)
    (v : Option (T × Slice U)) :
    (putBack p z v).snd = z.snd ∧
    (putBack p z v).index = z.index ∧
    (putBack p z v).len = z.len ∧
    (putBack p z v).fst.i = z.fst.i := by
  cases v <;> simp [putBack]

theorem putBack_length {T U : Type} (p : Nat) (z : State T U)
    (v : Option (T × Slice U)) :
    (putBack p z v).fst.slice.length = z.fst.slice.length := by
  cases v <;> simp [putBack]

theorem putBack_value {T U : Type} [Inhabited T]
    (p : Nat) (z : State T U) (word : T) (chunk : Slice U)
    (h : p < z.fst.slice.length) :
    (putBack p z (some (word, chunk))).fst.slice.val[p]! = word := by
  simpa [putBack] using Slice.getElem!_Nat_setAtNat_eq z.fst.slice p word h

theorem putBack_other {T U : Type} [Inhabited T]
    (p q : Nat) (z : State T U) (word : T) (chunk : Slice U)
    (h : p ≠ q) :
    (putBack p z (some (word, chunk))).fst.slice.val[q]! = z.fst.slice.val[q]! := by
  simpa [putBack] using Slice.getElem!_Nat_setAtNat_ne z.fst.slice p q word h

theorem putBack_valid {T U : Type} (p : Nat) (z : State T U)
    (v : Option (T × Slice U)) (h : valid z) : valid (putBack p z v) := by
  cases v <;> simpa [putBack, valid] using h

theorem next_exhausted {T U : Type}
    (IA : MutableIterator (core.slice.iter.IterMut T) T)
    (IB : core.iter.traits.iterator.Iterator (core.slice.iter.ChunksExact U) (Slice U))
    (z : State T U) (h : z.len ≤ z.index) :
    next IA IB z = ok (none, z, fun state _ => state) := by
  simp [next, Nat.not_lt.mpr h]

theorem next_in_bounds {T U : Type} (z : State T U)
    (h : valid z) (hi : z.index < z.len) :
    z.fst.i + z.index < z.fst.slice.length ∧ z.index < z.snd.chunks.length := by
  rcases h with ⟨ha, hl, _⟩
  omega

theorem next_preserves_valid {T U : Type} (z : State T U)
    (h : valid z) (hi : z.index < z.len) :
    valid { z with index := z.index + 1 } := by
  rcases h with ⟨ha, hl, _⟩
  exact ⟨ha, hl, hi⟩

theorem make_actual {T U : Type}
    (IA : MutableIterator (core.slice.iter.IterMut T) T)
    (a : core.slice.iter.IterMut T) (b : core.slice.iter.ChunksExact U) :
    make IA (core.iter.traits.collect.IntoIterator.Blanket
      (core.iter.traits.iterator.IteratorChunksExact U)) a b =
    ok (⟨a, b, 0, min (a.slice.length - a.i) b.chunks.length⟩, fun z => z.fst) := by
  simp [make, core.iter.traits.collect.IntoIterator.Blanket,
    core.iter.traits.collect.IntoIterator.Blanket.into_iter, bind_ok]

theorem make_state_valid {T U : Type}
    (a : core.slice.iter.IterMut T) (b : core.slice.iter.ChunksExact U)
    (h : a.i ≤ a.slice.length) :
    valid (⟨a, b, 0, min (a.slice.length - a.i) b.chunks.length⟩ : State T U) := by
  exact ⟨h, rfl, Nat.zero_le _⟩

theorem next_active {T U : Type}
    (IA : MutableIterator (core.slice.iter.IterMut T) T)
    (IB : core.iter.traits.iterator.Iterator (core.slice.iter.ChunksExact U) (Slice U))
    (z : State T U) (h : valid z) (hi : z.index < z.len) :
    next IA IB z =
      ok (some (z.fst.slice[z.fst.i + z.index]'(next_in_bounds z h hi).1,
          z.snd.chunks[z.index]'(next_in_bounds z h hi).2),
        { z with index := z.index + 1 }, putBack (z.fst.i + z.index)) := by
  have hs := next_in_bounds z h hi
  simp [next, hi, hs.1, hs.2]

#print axioms putBack_value
#print axioms putBack_other
#print axioms putBack_valid
#print axioms make_actual
#print axioms next_active

end PQ1Research.MutableZip
