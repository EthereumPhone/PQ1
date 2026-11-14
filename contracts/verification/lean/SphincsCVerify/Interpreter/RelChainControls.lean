/-
SphincsCVerify.Interpreter.RelChainControls — RESEARCH (#1155 gas track, batch 8): non-vacuity
controls for the WOTS-chain coupling `StepRel` (RelChain.lean), adapted from the batch-8
review's probe.

* `coupled`: concrete reference / optimized states (all-zero memory) satisfy `StepRel`.
* `adrs_rejected` / `seed_rejected`: changing ONE optimized ADRS byte (`0x20 + 5`) or ONE seed
  byte (`5`) breaks it.
* `index_rejected` / `value_rejected` (batch 9, after the batch-9 review): changing the optimized
  chain-index byte (`55`, ADRS byte 23) or ONE optimized value byte (`0x40 + 5`) breaks it too.
* The `#guard`: with a concrete hash oracle that reads input bytes 5 (seed), 37 (ADRS), 55
  (chain index) and 69 (value), one reference step and one optimized step from the coupled
  states produce the same value bytes, and from each of the four mutated states they do not.
  The guard exercises the executed programs, not `StepRel` itself; the four rejection theorems
  are what tie each mutation to a `StepRel` conjunct.

Mathlib-free; no `sorry`/`admit`/`native_decide`.
-/

import SphincsCVerify.Interpreter.RelChain

namespace SphincsCVerify.Interpreter.C10.RelChainControls

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Spec (ByteVec)

def zmem : ByteMemory := fun _ => 0
def refVM : VM := ⟨zmem, fun x => if x = "N_MASK" then NMASK else if x = "OUT" then 0x600 else 0⟩
def headVM : VM := ⟨zmem, fun _ => 0⟩
def badAdrs : VM := { headVM with mem := mstore8Mem headVM.mem 37 1 }
def badSeed : VM := { headVM with mem := mstore8Mem headVM.mem 5 1 }
def badIndex : VM := { headVM with mem := mstore8Mem headVM.mem 55 1 }
def badValue : VM := { headVM with mem := mstore8Mem headVM.mem 69 1 }

theorem coupled : StepRel 0 0 0 zmem zmem refVM headVM := by
  simp [StepRel, refVM, headVM, zmem, cbOf, beByte]

theorem adrs_rejected : ¬ StepRel 0 0 0 zmem zmem refVM badAdrs := by
  intro hr
  have hx := hr.2.2.2.2.2.1 5 (by decide) (by decide) (by decide)
  change (1 : UInt8) = 0 at hx
  exact (by decide : (1 : UInt8) ≠ 0) hx

theorem seed_rejected : ¬ StepRel 0 0 0 zmem zmem refVM badSeed := by
  intro hr
  have hx := hr.2.2.2.2.1 5 (by decide)
  change (1 : UInt8) = 0 at hx
  exact (by decide : (1 : UInt8) ≠ 0) hx

theorem index_rejected : ¬ StepRel 0 0 0 zmem zmem refVM badIndex := by
  intro hr
  have hx := hr.2.2.2.2.2.2.1
  change (1 : UInt8) = UInt8.ofNat 0 at hx
  exact (by decide : (1 : UInt8) ≠ UInt8.ofNat 0) hx

theorem value_rejected : ¬ StepRel 0 0 0 zmem zmem refVM badValue := by
  intro hr
  have hx := hr.2.2.2.2.2.2.2.1 5 (by decide)
  change (1 : UInt8) = beByte 0 5 at hx
  exact (by decide : (1 : UInt8) ≠ beByte 0 5) hx

/-- A concrete oracle that depends on input bytes 5 (seed), 37 (ADRS), 55 (chain index) and
    69 (value). -/
def probeSha (xs : List UInt8) : ByteVec 32 :=
  ⟨Array.replicate 32 (xs.getD 5 0 + xs.getD 37 0 + xs.getD 55 0 + xs.getD 69 0 + 7), by simp⟩

def emptySig : ByteVec 0 := ⟨#[], rfl⟩

def outR : VM := (execList probeSha emptySig wotsChainStepBody { refVM with env := setVar refVM.env "step" 0 }).1
def outH (v : VM) : VM := (execList probeSha emptySig headStepBody { v with env := setVar v.env "p" 0 }).1
def sameOutput (v : VM) : Bool :=
  (List.range 32).all fun k => (outH v).mem (64 + k) == beByte (outR.env "val") k

#guard sameOutput headVM && !sameOutput badAdrs && !sameOutput badSeed
  && !sameOutput badIndex && !sameOutput badValue

end SphincsCVerify.Interpreter.C10.RelChainControls
