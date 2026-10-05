/- §33 rank — `domain::deserialize_pin_state` malformed-length rejection.

   `deserialize_pin_state` (`domain/src/lib.rs:855`) is the PIN-state blob parser.
   This rank proves the anti-malformed-input property: every blob whose declared
   length is 0 or exceeds the maximum (`PIN_STATE_MAX_LEN = 1 + MAX_ATTEMPTS *
   PER_SLOT_CT_LEN = 481`) is REJECTED with `Err` — the parser never proceeds to
   populate the fixed `[[u8;48];10]` array, and (totality) never panics on those
   inputs. Both reject paths are straight-line guards that fire BEFORE the
   `chunks(48).enumerate()` loop, so the proof needs only the length guards (the
   loop externals — the `Chunks` iterator model in FunsExternal.lean — merely
   have to exist, which they do).

   The deeper round-trip (`deserialize (serialize …) = Ok …`, via a chunks/
   enumerate fold invariant) is a separate, deeper rank.

   Additions-only, kernel-clean, does NOT touch SphincsCVerify / theft_free.
   Proof shape mirrors `decode_item_spec` (the rank-8 parser analog): state the
   result in Aeneas WP form `prog ⦃ r => … ⦄` and let `step*` step the monad
   (incl. the `PIN_STATE_MAX_LEN` checked arithmetic via the `@[step]` scalar
   specs) with `scalar_tac` discharging the bound side-goals. -/
import Extracted.PinState.Funs
open Aeneas Aeneas.Std Result

set_option linter.unusedTactic false
set_option linter.unreachableTactic false

namespace Extracted.Equiv

open pqsigner_domain

/-- **Malformed-length rejection (+ totality).** Any blob whose declared length
    is `0` or `> 481 = PIN_STATE_MAX_LEN` is rejected with `Err` — the parser
    succeeds (no panic) and yields `Err` without entering the chunk loop. -/
theorem deserialize_pin_state_rejects_bad_len
    (blob : Slice Std.U8) (blob_len : Std.Usize)
    (h : blob_len.val = 0 ∨ blob_len.val > 481) :
    deserialize_pin_state blob blob_len ⦃ r => r = core.result.Result.Err () ⦄ := by
  unfold deserialize_pin_state
  rcases h with h0 | hgt
  · -- length 0 → first guard fires
    have hz : blob_len = 0#usize := by scalar_tac
    rw [if_pos hz]
    simp [WP.spec_ok]
  · -- length > 481 → second guard fires (after PIN_STATE_MAX_LEN = 481)
    have hne : ¬ blob_len = 0#usize := by
      intro hc; rw [hc] at hgt; simp at hgt
    rw [if_neg hne]
    unfold PIN_STATE_MAX_LEN PER_SLOT_CT_LEN AES_GCM_TAG_LEN pqsigner_proto.MAX_ATTEMPTS
    simp only [lift, bind_tc_ok]
    step* +splitIte <;>
      first | (simp [WP.spec_ok]) | scalar_tac | skip

end Extracted.Equiv
