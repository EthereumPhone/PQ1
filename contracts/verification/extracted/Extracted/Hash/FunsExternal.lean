-- [sphincs_c10] external declarations for the hash-fns extraction.
--
-- §33 axiom-collapse: `sha256_bytes` is the SINGLE opaque boundary of the
-- five tweakable-hash primitives, and it is NOT an axiom — it delegates to
-- `sha256_pure`, the computable vendored FIPS 180-4 implementation
-- (`Extracted/Sha256Pure.lean`, CAVP-pinned). The three `Step<u32>` trait
-- methods the chain_hash Range loop needs are total DEFs mirroring Aeneas's
-- own `StepUsize` instance (`Aeneas/Std/Core/Iter.lean`) at u32 — the
-- `into_iter` no-content-axiom pattern.
import Aeneas
import Extracted.Hash.Types
import Extracted.HashPure
open Aeneas Aeneas.Std Result

open sphincs_c10

/-- [core::iter::range::{core::iter::range::Step<u32>}::steps_between]:
    mirrors `core.iter.range.StepUsize.steps_between` at u32 (u32 distances
    always fit usize). -/
@[rust_fun "core::iter::range::{core::iter::range::Step<u32>}::steps_between"]
def U32.Insts.CoreIterRangeStep.steps_between
    (start «end» : Std.U32) : Result (Std.Usize × (Option Std.Usize)) :=
  if start.val > «end».val then ok ⟨0#usize, none⟩
  else
    let steps := Usize.ofNatCore («end».val - start.val) (by scalar_tac)
    ok ⟨steps, some steps⟩

/-- [core::iter::range::{core::iter::range::Step<u32>}::forward_checked]:
    `u32::try_from(count).ok().and_then(|c| start.checked_add(c))` — `some`
    exactly when `start + count` fits u32. -/
@[rust_fun "core::iter::range::{core::iter::range::Step<u32>}::forward_checked"]
def U32.Insts.CoreIterRangeStep.forward_checked
    (start : Std.U32) (count : Std.Usize) : Result (Option Std.U32) :=
  ok (if start.val + count.val ≤ U32.max
      then some ⟨BitVec.ofNat 32 (start.val + count.val)⟩
      else none)

/-- [core::iter::range::{core::iter::range::Step<u32>}::backward_checked]:
    `u32::try_from(count).ok().and_then(|c| start.checked_sub(c))` — `some`
    exactly when `count ≤ start`. -/
@[rust_fun "core::iter::range::{core::iter::range::Step<u32>}::backward_checked"]
def U32.Insts.CoreIterRangeStep.backward_checked
    (start : Std.U32) (count : Std.Usize) : Result (Option Std.U32) :=
  ok (if count.val ≤ start.val
      then some ⟨BitVec.ofNat 32 (start.val - count.val)⟩
      else none)

/-- [sphincs_c10::hash::sha256_bytes]: the one-shot SHA-256 boundary —
    total wrapper over the vendored FIPS 180-4 `sha256_pure`. -/
@[rust_fun "sphincs_c10::hash::sha256_bytes"]
def hash.sha256_bytes (data : Slice Std.U8) :
    Result (Array Std.U8 32#usize) :=
  ok (sha256_pure data.val)

/-- Step spec: sha256_bytes always succeeds with the FIPS digest of its
    exact input bytes. -/
@[step] theorem hash.sha256_bytes_spec (data : Slice Std.U8) :
    hash.sha256_bytes data ⦃ r => r = sha256_pure data.val ⦄ := by
  simp [hash.sha256_bytes, WP.spec_ok]

/-- Explicit streaming backend model: ordered slices denote their concatenation.
    This supplied definition does not extract or verify RustCrypto or the
    hardware stream implementation. The caller's five arguments are extracted. -/
@[rust_fun "sphincs_c10::hash::sha256_parts"]
def hash.sha256_parts (parts : Slice (Slice Std.U8)) :
    Result (Array Std.U8 32#usize) :=
  ok (sha256_pure ((parts.val.map (fun part => part.val)).flatten))
