/- Sequential backend model for the explicitly state-threaded wrapper.
   These are definitions, not hardware axioms. The effect-threading transform,
   callback abstraction and backend interpretation are explicit trust boundaries.
   Ghost events describe calls, not physical erasure or production logging. -/
import Aeneas
open Aeneas Aeneas.Std Result
namespace secure_wrapper_model

abbrev Bytes16 := Std.Array Std.U8 16#usize
abbrev Bytes32 := Std.Array Std.U8 32#usize
abbrev Signature := Std.Array Std.U8 4008#usize

inductive Event where
  | readRate (count : Std.U32)
  | charge (accepted : Bool)
  | initCfi
  | sentinel (condition : Bool) (word : Std.U32)
  | bump (magic : Std.U32)
  | fill (index : Nat) (accepted : Bool) (bytes : List Std.U8)
  | wipe (bytes : List Std.U8)
  | barrier
  | wait
  | sign (sk msg : Bytes32) (seed root : Bytes16) (opt : Option Bytes16)
      (shuffle : Bytes32) (result : Signature)
  | compare (a b : List Std.U8) (equal : Bool)
  | verify (seed root : Bytes16) (msg : Bytes32) (sig : Signature) (accepted : Bool)
  | cfiCheck (actual expected word : Std.U32)
  | relock

structure Backend where
  rateBefore : Std.U32
  rateAfter : Std.U32
  rateAccepted : Bool
  rateWord : Std.U32
  verifyWord : Std.U32
  cfiWord : Std.U32
  fill : Nat → Bool × List Std.U8
  sign : Bytes32 → Bytes16 → Bytes16 → Bytes32 → Option Bytes16 → Bytes32 → Result Signature
  verify : Bytes16 → Bytes16 → Bytes32 → Signature → Result Bool

end secure_wrapper_model

-- Aeneas emits this opaque type at the root of its type template.
structure Effects where
  backend : secure_wrapper_model.Backend
  trace : List secure_wrapper_model.Event := []
  reads : Nat := 0
  fills : Nat := 0
  checks : Nat := 0

namespace secure_wrapper_model

def emit (e : Effects) (event : Event) : Effects :=
  { e with trace := e.trace ++ [event] }

end secure_wrapper_model

