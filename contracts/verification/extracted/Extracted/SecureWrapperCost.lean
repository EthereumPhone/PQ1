/- Call accounting for normal returns of the sequential extracted wrapper.
   Weights are abstract nonnegative per-call budgets, not physical timing.
   Aeneas failure/divergence has no final Effects value and is not covered. -/
import Extracted.SecureWrapperSpec
import Mathlib.Tactic.ClearExcept
open Aeneas Aeneas.Std Result
namespace secure_wrapper_model
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

/-- Only the signing and verification calls are charged by this accounting.
    RNG, callbacks and other hardware dependencies need separate budgets. -/
def eventCallCost (signCost verifyCost : Nat) : Event → Nat
  | .sign .. => signCost
  | .verify .. => verifyCost
  | _ => 0

def traceCallCost (signCost verifyCost : Nat) (trace : List Event) : Nat :=
  (trace.map (eventCallCost signCost verifyCost)).sum

@[simp] theorem traceCallCost_append (s v : Nat) (a b : List Event) :
    traceCallCost s v (a ++ b) = traceCallCost s v a + traceCallCost s v b := by
  simp [traceCallCost, List.sum_append]

private theorem bind_success {α β : Type} (a : Result α) (f : α → Result β) (b : β)
    (h : (a >>= f) = .ok b) : ∃ x, a = .ok x ∧ f x = .ok b := by
  cases a <;> simp_all
private theorem if_result {α : Type} (p : Prop) [Decidable p] (a b c : α)
    (h : (if p then a else b) = c) : (p ∧ a = c) ∨ (¬p ∧ b = c) := by
  by_cases hp : p <;> simp_all

private theorem fill_call_cost (s v : Nat) {N : Std.Usize} (e out : Effects)
    (before after : Std.Array Std.U8 N) (r : Aeneas.Std.core.result.Result Unit Unit)
    (h : rng_strong.fill e before = .ok (r,out,after)) :
    traceCallCost s v out.trace = traceCallCost s v e.trace := by
  unfold rng_strong.fill at h
  generalize hh : e.backend.fill e.fills = pair at h
  rcases pair with ⟨accepted,bytes⟩
  dsimp only at h
  by_cases hl : bytes.length = N.val
  · simp only [dif_pos hl, Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨_,rfl,_⟩
    simp [emit,traceCallCost,List.sum_append,eventCallCost]
  · simp only [dif_neg hl] at h
    cases h

private theorem sign_call_cost (s v : Nat) (sk : sphincs_c10.SigningKey)
    (e out : Effects) (msg : Bytes32) (opt : Option Bytes16) (shuffle : Bytes32)
    (sig : Signature)
    (h : sphincs_c10.SigningKey.sign_with_shuffle sk e msg opt shuffle () = .ok (sig,out)) :
    traceCallCost s v out.trace = traceCallCost s v e.trace + s := by
  unfold sphincs_c10.SigningKey.sign_with_shuffle at h
  obtain ⟨sig',_,h⟩ := bind_success _ _ _ h
  simp only [Result.ok.injEq, Prod.mk.injEq] at h
  rcases h with ⟨rfl,rfl⟩
  simp [emit,traceCallCost,List.sum_append,eventCallCost]

private theorem verify_call_cost (s v : Nat) (e out : Effects)
    (seed root : Bytes16) (msg : Bytes32) (sig : Signature) (valid : Bool)
    (h : sphincs_c10.verify e seed root msg sig = .ok (valid,out)) :
    traceCallCost s v out.trace = traceCallCost s v e.trace + v := by
  unfold sphincs_c10.verify at h
  obtain ⟨valid',_,h⟩ := bind_success _ _ _ h
  simp only [Result.ok.injEq, Prod.mk.injEq] at h
  rcases h with ⟨rfl,rfl⟩
  simp [emit,traceCallCost,List.sum_append,eventCallCost]

private theorem zero_pair_cost {α : Type} (s v : Nat) (e out : Effects)
    (x y : α) (event : Event)
    (h : Result.ok (x,emit e event) = Result.ok (y,out))
    (hz : eventCallCost s v event = 0) :
    traceCallCost s v out.trace = traceCallCost s v e.trace := by
  simp only [Result.ok.injEq,Prod.mk.injEq] at h
  rcases h with ⟨_,rfl⟩
  simp [emit,traceCallCost,List.sum_append,hz]

private theorem zero_effect_cost (s v : Nat) (e out : Effects) (event : Event)
    (h : Result.ok (emit e event) = Result.ok out)
    (hz : eventCallCost s v event = 0) :
    traceCallCost s v out.trace = traceCallCost s v e.trace := by
  cases h
  simp [emit,traceCallCost,List.sum_append,hz]

local macro "finish_cost" hs:ident* : tactic => `(tactic| (
  clear * - $hs*
  simp [emit, traceCallCost, List.sum_append, eventCallCost, two_mul] at *
  <;> omega))

/-- Every normal inner return costs at most two signing calls and one verify;
    success costs exactly that amount, even with an arbitrary prior trace. -/
theorem wrapper_inner_call_cost (signCost verifyCost : Nat)
    (sk : sphincs_c10.SigningKey) (msg : Bytes32) (progress : Unit × Unit)
    (e out : Effects) (result : Aeneas.Std.core.result.Result Signature Unit)
    (h : production.c10_sign_verified_with_progress_inner sk msg progress e fi.OK_SENTINEL =
      .ok (result,out)) :
    traceCallCost signCost verifyCost e.trace ≤ traceCallCost signCost verifyCost out.trace ∧
    traceCallCost signCost verifyCost out.trace ≤
      traceCallCost signCost verifyCost e.trace + 2*signCost + verifyCost ∧
    (∀ sig, result = .Ok sig → traceCallCost signCost verifyCost out.trace =
      traceCallCost signCost verifyCost e.trace + 2*signCost + verifyCost) := by
  simp only [production.c10_sign_verified_with_progress_inner,
    fi.CfiCounter.new, fi.check_true_into_sentinel,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
    core.hint.black_box, bind_tc_ok, uncurry_apply_pair, decide_true, if_true] at h
  replace h := if_result _ _ _ _ h
  rcases h with ⟨hgate, h⟩ | ⟨_, h⟩
  · simp only [Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨rfl,rfl⟩
    finish_cost
  · replace h := bind_success _ _ _ h
    rcases h with ⟨⟨cfi,e1⟩, hc, h⟩
    have hcTrace : traceCallCost signCost verifyCost e1.trace =
        traceCallCost signCost verifyCost e.trace := by
      simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
        zero_pair_cost signCost verifyCost _ _ _ _ _ hc rfl
    try simp only [uncurry_apply_pair] at h
    replace h := bind_success _ _ _ h
    rcases h with ⟨⟨r,e2,random⟩, hr, h⟩
    have hrCost := fill_call_cost signCost verifyCost _ _ _ _ _ hr
    try simp only [uncurry_apply_pair] at h
    cases r <;> simp only [core.result.Result.is_err, bind_tc_ok,
      Bool.false_eq_true, if_false, if_true] at h
    · simp only [lift, bind_tc_ok] at h
      replace h := bind_success _ _ _ h
      rcases h with ⟨iter, hi, h⟩
      try simp only [uncurry_apply_pair] at h
      replace h := bind_success _ _ _ h
      rcases h with ⟨acc, ha, h⟩
      try simp only [uncurry_apply_pair] at h
      replace h := if_result _ _ _ _ h
      rcases h with ⟨_, h⟩ | ⟨_, h⟩
      · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
          fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
          uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
        rcases h with ⟨rfl,rfl⟩
        finish_cost hcTrace hrCost
      · replace h := bind_success _ _ _ h
        rcases h with ⟨⟨cfi2,e3⟩, hc2, h⟩
        have hc2Trace : traceCallCost signCost verifyCost e3.trace =
            traceCallCost signCost verifyCost e2.trace := by
          simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
            zero_pair_cost signCost verifyCost _ _ _ _ _ hc2 rfl
        try simp only [uncurry_apply_pair] at h
        replace h := bind_success _ _ _ h
        rcases h with ⟨⟨r,e4,sha⟩, hra, h⟩
        have hraCost := fill_call_cost signCost verifyCost _ _ _ _ _ hra
        try simp only [uncurry_apply_pair] at h
        cases r <;> simp only [Bool.false_eq_true, if_false, if_true] at h
        · replace h := bind_success _ _ _ h
          rcases h with ⟨⟨r,e5,shb⟩, hrb, h⟩
          have hrbCost := fill_call_cost signCost verifyCost _ _ _ _ _ hrb
          try simp only [uncurry_apply_pair] at h
          cases r <;> simp only [Bool.false_eq_true, if_false, if_true] at h
          · replace h := bind_success _ _ _ h
            rcases h with ⟨⟨aa,ab⟩, hab, h⟩
            try simp only [uncurry_apply_pair] at h
            replace h := if_result _ _ _ _ h
            rcases h with ⟨_, h⟩ | ⟨_, h⟩
            · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
              rcases h with ⟨rfl,rfl⟩
              finish_cost hcTrace hrCost hc2Trace hraCost hrbCost
            · replace h := if_result _ _ _ _ h
              rcases h with ⟨_, h⟩ | ⟨_, h⟩
              · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                  fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                  uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                rcases h with ⟨rfl,rfl⟩
                finish_cost hcTrace hrCost hc2Trace hraCost hrbCost
              · replace h := bind_success _ _ _ h
                rcases h with ⟨⟨_,e6⟩, hw1, h⟩
                have hw1Trace : traceCallCost signCost verifyCost e6.trace =
                    traceCallCost signCost verifyCost e5.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ hw1 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨_,e7⟩, hw2, h⟩
                have hw2WipeTrace : traceCallCost signCost verifyCost e7.trace =
                    traceCallCost signCost verifyCost e6.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ hw2 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨e8, hb1, h⟩
                have hb1Trace : traceCallCost signCost verifyCost e8.trace =
                    traceCallCost signCost verifyCost e7.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_effect_cost signCost verifyCost _ _ _ hb1 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi3,e9⟩, hc3, h⟩
                have hc3Trace : traceCallCost signCost verifyCost e9.trace =
                    traceCallCost signCost verifyCost e8.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ hc3 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨sig_a,e10⟩, hsa, h⟩
                have hsaCost := sign_call_cost signCost verifyCost _ _ _ _ _ _ _ hsa
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi4,e11⟩, hc4, h⟩
                have hc4Trace : traceCallCost signCost verifyCost e11.trace =
                    traceCallCost signCost verifyCost e10.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ hc4 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨e12, hw, h⟩
                have hwTrace : traceCallCost signCost verifyCost e12.trace =
                    traceCallCost signCost verifyCost e11.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_effect_cost signCost verifyCost _ _ _ hw rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨sig_b,e13⟩, hsb, h⟩
                have hsbCost := sign_call_cost signCost verifyCost _ _ _ _ _ _ _ hsb
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi5,e14⟩, hc5, h⟩
                have hc5Trace : traceCallCost signCost verifyCost e14.trace =
                    traceCallCost signCost verifyCost e13.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ hc5 rfl
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨sa, hsla, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨sb, hslb, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨equal,e15⟩, heq, h⟩
                have heqTrace : traceCallCost signCost verifyCost e15.trace =
                    traceCallCost signCost verifyCost e14.trace := by
                  simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                    zero_pair_cost signCost verifyCost _ _ _ _ _ heq rfl
                try simp only [uncurry_apply_pair] at h
                simp only [lift, core.convert.FromSame.from_, bind_tc_ok] at h
                replace h := if_result _ _ _ _ h
                rcases h with ⟨hcompare, h⟩ | ⟨hcompare, h⟩
                · replace h := bind_success _ _ _ h
                  rcases h with ⟨⟨cfi6,e16⟩, hc6, h⟩
                  have hc6Trace : traceCallCost signCost verifyCost e16.trace =
                      traceCallCost signCost verifyCost e15.trace := by
                    simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                      zero_pair_cost signCost verifyCost _ _ _ _ _ hc6 rfl
                  try simp only [uncurry_apply_pair] at h
                  replace h := bind_success _ _ _ h
                  rcases h with ⟨e17, hw2, h⟩
                  have hw2WaitTrace : traceCallCost signCost verifyCost e17.trace =
                      traceCallCost signCost verifyCost e16.trace := by
                    simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                      zero_effect_cost signCost verifyCost _ _ _ hw2 rfl
                  try simp only [uncurry_apply_pair] at h
                  simp only [sphincs_c10.SigningKey.impl.pk_seed,
                    sphincs_c10.SigningKey.impl.pk_root, bind_tc_ok] at h
                  replace h := bind_success _ _ _ h
                  rcases h with ⟨⟨valid,e18⟩, hv, h⟩
                  have hvCost := verify_call_cost signCost verifyCost _ _ _ _ _ _ _ hv
                  try simp only [uncurry_apply_pair] at h
                  simp only [production.c10_sign_verified_with_progress_inner.closure_1.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
                    core.hint.black_box, bind_tc_ok, uncurry_apply_pair] at h
                  cases valid
                  · simp [fi.OK_SENTINEL, ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                      fi.zeroize_barrier, nsc.zeroize_sensitive_state, uncurry_apply_pair] at h
                    rcases h with ⟨rfl,rfl⟩
                    finish_cost hcTrace hrCost hc2Trace hraCost hrbCost hw1Trace hw2WipeTrace hb1Trace hc3Trace hsaCost hc4Trace hwTrace hsbCost hc5Trace heqTrace hc6Trace hw2WaitTrace hvCost
                  · simp only [if_true] at h
                    replace h := if_result _ _ _ _ h
                    rcases h with ⟨hverifyGate, h⟩ | ⟨hverifyGate, h⟩
                    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                      rcases h with ⟨rfl,rfl⟩
                      finish_cost hcTrace hrCost hc2Trace hraCost hrbCost hw1Trace hw2WipeTrace hb1Trace hc3Trace hsaCost hc4Trace hwTrace hsbCost hc5Trace heqTrace hc6Trace hw2WaitTrace hvCost
                    · replace h := bind_success _ _ _ h
                      rcases h with ⟨⟨cfi7,e19⟩,hc7,h⟩
                      have hc7Trace : traceCallCost signCost verifyCost e19.trace =
                          traceCallCost signCost verifyCost e18.trace := by
                        simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                          zero_pair_cost signCost verifyCost _ _ _ _ _ hc7 rfl
                      simp only [uncurry_apply_pair] at h
                      replace h := bind_success _ _ _ h
                      rcases h with ⟨expected,hcExpected,h⟩
                      replace h := bind_success _ _ _ h
                      rcases h with ⟨⟨word,e20⟩,hfinal,h⟩
                      have hfinalTrace : traceCallCost signCost verifyCost e20.trace =
                          traceCallCost signCost verifyCost e19.trace := by
                        simpa [emit,traceCallCost,List.sum_append,eventCallCost] using
                          zero_pair_cost signCost verifyCost _ _ _ _ _ hfinal rfl
                      simp only [uncurry_apply_pair] at h
                      replace h := if_result _ _ _ _ h
                      rcases h with ⟨hCFIgate,h⟩ | ⟨hCFIgate,h⟩
                      · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                          fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                          uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                        rcases h with ⟨rfl,rfl⟩
                        finish_cost hcTrace hrCost hc2Trace hraCost hrbCost hw1Trace hw2WipeTrace hb1Trace hc3Trace hsaCost hc4Trace hwTrace hsbCost hc5Trace heqTrace hc6Trace hw2WaitTrace hvCost hc7Trace hfinalTrace
                      · simp only [fi.delay_source_failed, bind_tc_ok, uncurry_apply_pair] at h
                        cases hDelay : e20.backend.delayFailed <;>
                          simp only [hDelay, Bool.false_eq_true, if_false, if_true,
                            ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                            fi.zeroize_barrier, bind_tc_ok, uncurry_apply_pair,
                            Result.ok.injEq, Prod.mk.injEq] at h <;>
                          rcases h with ⟨rfl,rfl⟩ <;>
                          finish_cost hcTrace hrCost hc2Trace hraCost hrbCost hw1Trace hw2WipeTrace hb1Trace hc3Trace hsaCost hc4Trace hwTrace hsbCost hc5Trace heqTrace hc6Trace hw2WaitTrace hvCost hc7Trace hfinalTrace



                · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                    uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                  rcases h with ⟨rfl,rfl⟩
                  finish_cost hcTrace hrCost hc2Trace hraCost hrbCost hw1Trace hw2WipeTrace hb1Trace hc3Trace hsaCost hc4Trace hwTrace hsbCost hc5Trace heqTrace
          · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
              fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
              uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
            rcases h with ⟨rfl,rfl⟩
            finish_cost hcTrace hrCost hc2Trace hraCost hrbCost
        · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
            fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
            uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
          rcases h with ⟨rfl,rfl⟩
          finish_cost hcTrace hrCost hc2Trace hraCost
    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      rcases h with ⟨rfl,rfl⟩
      finish_cost hcTrace hrCost



/-- The ordinary entry's rate gates add no signing/verifying calls. The bound
    includes every normal refusal and preserves the pre-existing trace cost. -/
theorem wrapper_entry_call_cost (signCost verifyCost : Nat)
    (sk : sphincs_c10.SigningKey) (msg : Bytes32) (progress : Unit × Unit)
    (e out : Effects) (result : Aeneas.Std.core.result.Result Signature Unit)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (result,out)) :
    traceCallCost signCost verifyCost e.trace ≤ traceCallCost signCost verifyCost out.trace ∧
    traceCallCost signCost verifyCost out.trace ≤
      traceCallCost signCost verifyCost e.trace + 2*signCost + verifyCost ∧
    (∀ sig, result = .Ok sig → traceCallCost signCost verifyCost out.trace =
      traceCallCost signCost verifyCost e.trace + 2*signCost + verifyCost) := by
  unfold production.c10_sign_verified_with_progress at h
  replace h := bind_success _ _ _ h
  rcases h with ⟨⟨before,e1⟩,hr,h⟩
  have hrTrace : traceCallCost signCost verifyCost e1.trace =
      traceCallCost signCost verifyCost e.trace := by
    simp only [sign_rate.signs_this_session, Result.ok.injEq, Prod.mk.injEq] at hr
    rcases hr with ⟨_,rfl⟩
    simp [emit,traceCallCost,List.sum_append,eventCallCost]
  simp only [uncurry_apply_pair] at h
  replace h := bind_success _ _ _ h
  rcases h with ⟨⟨r,e2⟩,hp,h⟩
  have hpTrace : traceCallCost signCost verifyCost e2.trace =
      traceCallCost signCost verifyCost e1.trace := by
    simp only [sign_rate.pre_sign, Result.ok.injEq, Prod.mk.injEq] at hp
    rcases hp with ⟨_,rfl⟩
    simp [emit,traceCallCost,List.sum_append,eventCallCost]
  simp only [uncurry_apply_pair] at h
  cases r <;> simp only [core.result.Result.Insts.CoreOpsTry_traitTry.branch, bind_tc_ok] at h
  · replace h := bind_success _ _ _ h
    rcases h with ⟨⟨after,e3⟩,ha,h⟩
    have haTrace : traceCallCost signCost verifyCost e3.trace =
        traceCallCost signCost verifyCost e2.trace := by
      simp only [sign_rate.signs_this_session, Result.ok.injEq, Prod.mk.injEq] at ha
      rcases ha with ⟨_,rfl⟩
      simp [emit,traceCallCost,List.sum_append,eventCallCost]
    simp only [uncurry_apply_pair,lift,bind_tc_ok] at h
    replace h := if_result _ _ _ _ h
    rcases h with ⟨_,h⟩ | ⟨_,h⟩
    · simp only [Result.ok.injEq,Prod.mk.injEq] at h
      rcases h with ⟨rfl,rfl⟩
      finish_cost hrTrace hpTrace haTrace
    · have prior : traceCallCost signCost verifyCost e3.trace =
          traceCallCost signCost verifyCost e.trace := haTrace.trans (hpTrace.trans hrTrace)
      simpa only [prior] using
        wrapper_inner_call_cost signCost verifyCost sk msg progress e3 out result h
  · simp only [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
      Aeneas.Std.core.convert.FromSame, Aeneas.Std.core.convert.FromSame.from_, lift,
      uncurry_apply_pair,bind_tc_ok,Result.ok.injEq,Prod.mk.injEq] at h
    rcases h with ⟨rfl,rfl⟩
    finish_cost hrTrace hpTrace

/-- Unit weights count the two kinds of calls separately on every normal return. -/
theorem wrapper_entry_call_bounds (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects)
    (result : Aeneas.Std.core.result.Result Signature Unit)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (result,out)) :
    traceCallCost 1 0 e.trace ≤ traceCallCost 1 0 out.trace ∧
    traceCallCost 1 0 out.trace ≤ traceCallCost 1 0 e.trace + 2 ∧
    traceCallCost 0 1 e.trace ≤ traceCallCost 0 1 out.trace ∧
    traceCallCost 0 1 out.trace ≤ traceCallCost 0 1 e.trace + 1 := by
  have hs := wrapper_entry_call_cost 1 0 sk msg progress e out result h
  have hv := wrapper_entry_call_cost 0 1 sk msg progress e out result h
  simpa using And.intro hs.1 (And.intro hs.2.1 (And.intro hv.1 hv.2.1))

/-- Release accounts for both signs and internal verification, even when the
    pre-existing trace already contains arbitrary calls of either kind. -/
theorem wrapper_entry_success_call_counts (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (.Ok sig,out)) :
    traceCallCost 1 0 out.trace = traceCallCost 1 0 e.trace + 2 ∧
    traceCallCost 0 1 out.trace = traceCallCost 0 1 e.trace + 1 := by
  have hs := (wrapper_entry_call_cost 1 0 sk msg progress e out (.Ok sig) h).2.2 sig rfl
  have hv := (wrapper_entry_call_cost 0 1 sk msg progress e out (.Ok sig) h).2.2 sig rfl
  simpa using And.intro hs hv

end secure_wrapper_model
