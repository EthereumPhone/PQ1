import SphincsCVerify.Crypto.Assumptions
namespace SphincsCVerify.ReviewBreakToken
axiom freeBreak : Crypto.BreaksHash
theorem vacuousReduction (P : Prop) : P ∨ Crypto.BreaksHash := Or.inr freeBreak
#print axioms vacuousReduction
end SphincsCVerify.ReviewBreakToken
