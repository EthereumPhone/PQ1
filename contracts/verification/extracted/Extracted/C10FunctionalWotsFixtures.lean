/- Generated functional-printer boundary and independent chain checks. -/
import Extracted.C10Representation
import Aeneas
open C10Representation
set_option maxRecDepth 8192
namespace Extracted.C10FunctionalWotsFixtures
def clamp (x : Int) : Nat := (Int.toNat x)
def embed (n : Nat) : Int := (Int.ofNat n)
def applyBackend (f : List Int → List Int) (xs : List Int) : List Int := (f xs)
example : clamp (-1) = 0 := by decide
example : clamp 0 = 0 := by decide
example : clamp 7 = 7 := by decide
example (n : Nat) : clamp (embed n) = n := by simp [clamp, embed]
example (f : List Int → List Int) (xs : List Int) : applyBackend f xs = f xs := rfl
def toy (bs : List Int) : List Int := List.replicate 32 ((bs.getD 59 0 + 2 * bs.getD 64 0 + 1) % 256)
example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0) (List.replicate 16 3) 0 0 = List.replicate 16 3 := by decide
example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0) (List.replicate 16 3) 5 1 = List.replicate 16 12 := by decide
example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0) (List.replicate 16 3) 5 2 = List.replicate 16 31 := by decide
example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0) (List.replicate 16 3) 255 2 = List.replicate 16 13 := by decide
example : wots_chain_value toy (List.replicate 32 0) (List.replicate 32 0) (List.replicate 16 3) 2147483648 1 = List.replicate 16 7 := by decide
end Extracted.C10FunctionalWotsFixtures
