/- Explicit functional interpretations of the wrapper's dependencies.
   RNG, signing and verification responses remain supplied by Backend.
   A failed or divergent signer remains a failed/divergent computation;
   it is never converted to the wrapper's recoverable Err return. -/
import Extracted.SecureWrapper.Types
open Aeneas Aeneas.Std Result
namespace secure_wrapper_model

@[rust_fun "core::hint::black_box"]
def core.hint.black_box {T : Type} (x : T) : Result T := .ok x
@[rust_fun "core::result::{core::result::Result<@T, @E>}::is_err"]
def core.result.Result.is_err {T E : Type} (r : Aeneas.Std.core.result.Result T E) : Result Bool :=
  .ok (match r with | .Ok _ => false | .Err _ => true)
@[rust_fun
  "core::result::{core::ops::try_trait::Try<core::result::Result<@T, @E>>}::branch"]
def core.result.Result.Insts.CoreOpsTry_traitTry.branch {T E : Type}
    (r : Aeneas.Std.core.result.Result T E) :
    Result (Aeneas.Std.core.ops.control_flow.ControlFlow
      (Aeneas.Std.core.result.Result Aeneas.Std.core.convert.Infallible E) T) :=
  .ok (match r with | .Ok x => .Continue x | .Err e => .Break (.Err e))
@[rust_fun
  "core::result::{core::ops::try_trait::FromResidual<core::result::Result<@T, @F>, core::result::Result<core::convert::Infallible, @E>>}::from_residual"]
def core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual
    (T : Type) {E F : Type} (convert : Aeneas.Std.core.convert.From F E)
    (r : Aeneas.Std.core.result.Result Aeneas.Std.core.convert.Infallible E) :
    Result (Aeneas.Std.core.result.Result T F) :=
  match r with
  | .Ok x => nomatch x
  | .Err e => do let f ← convert.from_ e; .ok (.Err f)

@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::index"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index
    {T : Type} (_ : core.ops.range.RangeFull) (s : Slice T) : Result (Slice T) := .ok s
@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::index_mut"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.index_mut
    {T : Type} (_ : core.ops.range.RangeFull) (s : Slice T) :
    Result (Slice T × (Slice T → Slice T)) := .ok (s, id)
@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get
    {T : Type} (_ : core.ops.range.RangeFull) (s : Slice T) : Result (Option (Slice T)) := .ok (some s)
@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_mut"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_mut
    {T : Type} (_ : core.ops.range.RangeFull) (s : Slice T) :
    Result (Option (Slice T) × (Option (Slice T) → Slice T)) :=
  .ok (some s, fun x => x.getD s)
@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_unchecked"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked
    {T : Type} (_ : core.ops.range.RangeFull) (p : ConstRawPtr (Slice T)) :
    Result (ConstRawPtr (Slice T)) := .ok p
@[rust_fun
  "core::slice::index::{core::slice::index::SliceIndex<core::ops::range::RangeFull, [@T], [@T]>}::get_unchecked_mut"]
def core.ops.range.RangeFull.Insts.CoreSliceIndexSliceIndexSliceSlice.get_unchecked_mut
    {T : Type} (_ : core.ops.range.RangeFull) (p : MutRawPtr (Slice T)) :
    Result (MutRawPtr (Slice T)) := .ok p

def fi.CfiCounter.INIT_VALUE : Result Std.U32 := .ok 324478056#u32
def fi.CfiCounter.new (e : Effects) : Result (fi.CfiCounter × Effects) :=
  .ok (⟨324478056#u32⟩, emit e .initCfi)
def fi.CfiCounter.bump (c : fi.CfiCounter) (e : Effects) (magic : Std.U32) :
    Result (fi.CfiCounter × Effects) :=
  .ok (⟨Aeneas.Std.core.num.U32.wrapping_add c.accum magic⟩, emit e (.bump magic))
def fi.CfiCounter.check_into_sentinel (c : fi.CfiCounter) (e : Effects) (expected : Std.U32) :
    Result (Std.U32 × Effects) :=
  let word := if c.accum = expected then e.backend.cfiWord else 0#u32
  .ok (word, emit e (.cfiCheck c.accum expected word))
def fi.check_true_into_sentinel {F : Type}
    (fnInst : Aeneas.Std.core.ops.function.FnMut F Unit Bool)
    (e : Effects) (closure : F) : Result (Std.U32 × Effects) := do
  let (condition, _) ← fnInst.call_mut closure ()
  let word := if condition then
    (if e.checks = 0 then e.backend.rateWord else e.backend.verifyWord) else 0#u32
  .ok (word, emit { e with checks := e.checks + 1 } (.sentinel condition word))
def fi.zeroize_barrier (e : Effects) : Result Effects := .ok (emit e .barrier)
def fi.wait_random (e : Effects) : Result Effects := .ok (emit e .wait)
def sign_rate.signs_this_session (e : Effects) : Result (Std.U32 × Effects) :=
  let value := if e.reads = 0 then e.backend.rateBefore else e.backend.rateAfter
  .ok (value, emit { e with reads := e.reads + 1 } (.readRate value))
def sign_rate.pre_sign (e : Effects) :
    Result (Aeneas.Std.core.result.Result Unit Unit × Effects) :=
  .ok ((if e.backend.rateAccepted then .Ok () else .Err ()),
    emit e (.charge e.backend.rateAccepted))
def rng_strong.fill {N : Std.Usize} (e : Effects) (_ : Std.Array Std.U8 N) :
    Result (Aeneas.Std.core.result.Result Unit Unit × Effects × Std.Array Std.U8 N) :=
  let (accepted, bytes) := e.backend.fill e.fills
  if h : bytes.length = N.val then
    .ok ((if accepted then .Ok () else .Err ()),
      emit { e with fills := e.fills + 1 } (.fill e.fills accepted bytes), ⟨bytes,h⟩)
  else .fail .arrayOutOfBounds
def nsc.zeroize_sensitive_state (e : Effects) : Result Effects := .ok (emit e .relock)
def ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize {N : Std.Usize}
    (bytes : Std.Array Std.U8 N) (e : Effects) : Result (Std.Array Std.U8 N × Effects) :=
  .ok (Array.repeat N 0#u8, emit e (.wipe bytes.val))
def SliceU8.Insts.Secure_wrapper_modelSubtleConstantTimeEq.ct_eq
    (a : Slice Std.U8) (e : Effects) (b : Slice Std.U8) : Result (Bool × Effects) :=
  let equal := decide (a.val = b.val)
  .ok (equal, emit e (.compare a.val b.val equal))
def sphincs_c10.SigningKey.sign_with_shuffle (sk : sphincs_c10.SigningKey) (e : Effects)
    (msg : Bytes32) (opt : Option Bytes16) (shuffle : sphincs_c10.shuffle.ShuffleSeed)
    (_ : Unit) : Result (Signature × Effects) := do
  let sig ← e.backend.sign sk.sk_seed sk.pk_seed sk.pk_root msg opt shuffle
  .ok (sig, emit e (.sign sk.sk_seed msg sk.pk_seed sk.pk_root opt shuffle sig))
def sphincs_c10.SigningKey.impl.pk_seed (sk : sphincs_c10.SigningKey) : Result Bytes16 := .ok sk.pk_seed
def sphincs_c10.SigningKey.impl.pk_root (sk : sphincs_c10.SigningKey) : Result Bytes16 := .ok sk.pk_root
def sphincs_c10.verify (e : Effects) (seed root : Bytes16) (msg : Bytes32) (sig : Signature) :
    Result (Bool × Effects) := do
  let accepted ← e.backend.verify seed root msg sig
  .ok (accepted, emit e (.verify seed root msg sig accepted))

end secure_wrapper_model
