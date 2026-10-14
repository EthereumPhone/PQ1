/- Cleanup postcondition for every normally returning path, including refusal.
   Aeneas fail/divergence is not converted to a recoverable return. -/
import Extracted.SecureWrapperSpec
open Aeneas Aeneas.Std Result
namespace secure_wrapper_model
set_option maxHeartbeats 1000000
set_option maxRecDepth 8192

private theorem bind_success {α β : Type} (a : Result α) (f : α → Result β) (b : β)
    (h : (a >>= f) = .ok b) : ∃ x, a = .ok x ∧ f x = .ok b := by
  cases a <;> simp_all
private theorem if_result {α : Type} (p : Prop) [Decidable p] (a b c : α)
    (h : (if p then a else b) = c) : (p ∧ a = c) ∨ (¬p ∧ b = c) := by
  by_cases hp : p <;> simp_all
private theorem wipe_barrier_suffix (bytes : List Std.U8) (e : Effects) :
    (emit (emit e (.wipe bytes)) .barrier).trace = e.trace ++ [.wipe bytes,.barrier] := by
  simp [emit,List.append_assoc]

theorem wrapper_inner_cleanup (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (result : Aeneas.Std.core.result.Result Signature Unit)
    (h : production.c10_sign_verified_with_progress_inner sk msg progress e fi.OK_SENTINEL =
      .ok (result, out)) :
    (∃ word, result = .Err () ∧ word ≠ fi.OK_SENTINEL ∧
      out.trace = e.trace ++ [.initCfi,.sentinel true word]) ∨
    (∃ prior bytes, out.trace = prior ++ [.wipe bytes,.barrier]) := by
  simp only [production.c10_sign_verified_with_progress_inner,
    fi.CfiCounter.new, fi.check_true_into_sentinel,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
    core.hint.black_box, bind_tc_ok, uncurry_apply_pair, decide_true, if_true] at h
  replace h := if_result _ _ _ _ h
  rcases h with ⟨hgate, h⟩ | ⟨_, h⟩
  · simp only [Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨rfl,rfl⟩
    refine Or.inl ⟨(if e.checks = 0 then e.backend.rateWord else e.backend.verifyWord),rfl,?_,?_⟩
    · intro he; simp only [emit] at hgate; simp [he] at hgate
    · simp [emit,List.append_assoc]
  · replace h := bind_success _ _ _ h
    rcases h with ⟨⟨cfi,e1⟩, hc, h⟩
    try simp only [uncurry_apply_pair] at h
    replace h := bind_success _ _ _ h
    rcases h with ⟨⟨r,e2,random⟩, hr, h⟩
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
        exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
      · replace h := bind_success _ _ _ h
        rcases h with ⟨⟨cfi2,e3⟩, hc2, h⟩
        try simp only [uncurry_apply_pair] at h
        replace h := bind_success _ _ _ h
        rcases h with ⟨⟨r,e4,sha⟩, hra, h⟩
        try simp only [uncurry_apply_pair] at h
        cases r <;> simp only [Bool.false_eq_true, if_false, if_true] at h
        · replace h := bind_success _ _ _ h
          rcases h with ⟨⟨r,e5,shb⟩, hrb, h⟩
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
              exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
            · replace h := if_result _ _ _ _ h
              rcases h with ⟨_, h⟩ | ⟨_, h⟩
              · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                  fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                  uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                rcases h with ⟨rfl,rfl⟩
                exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
              · replace h := bind_success _ _ _ h
                rcases h with ⟨⟨_,e6⟩, hw1, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨_,e7⟩, hw2, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨e8, hb1, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi3,e9⟩, hc3, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨sig_a,e10⟩, hsa, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi4,e11⟩, hc4, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨e12, hw, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨sig_b,e13⟩, hsb, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨cfi5,e14⟩, hc5, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨sa, hsla, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨sb, hslb, h⟩
                try simp only [uncurry_apply_pair] at h
                replace h := bind_success _ _ _ h
                rcases h with ⟨⟨equal,e15⟩, heq, h⟩
                try simp only [uncurry_apply_pair] at h
                simp only [lift, core.convert.FromSame.from_, bind_tc_ok] at h
                replace h := if_result _ _ _ _ h
                rcases h with ⟨hcompare, h⟩ | ⟨hcompare, h⟩
                · replace h := bind_success _ _ _ h
                  rcases h with ⟨⟨cfi6,e16⟩, hc6, h⟩
                  try simp only [uncurry_apply_pair] at h
                  replace h := bind_success _ _ _ h
                  rcases h with ⟨e17, hw2, h⟩
                  try simp only [uncurry_apply_pair] at h
                  simp only [sphincs_c10.SigningKey.impl.pk_seed,
                    sphincs_c10.SigningKey.impl.pk_root, bind_tc_ok] at h
                  replace h := bind_success _ _ _ h
                  rcases h with ⟨⟨valid,e18⟩, hv, h⟩
                  try simp only [uncurry_apply_pair] at h
                  simp only [production.c10_sign_verified_with_progress_inner.closure_1.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
                    core.hint.black_box, bind_tc_ok, uncurry_apply_pair] at h
                  cases valid
                  · simp [fi.OK_SENTINEL, ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                      fi.zeroize_barrier, nsc.zeroize_sensitive_state, uncurry_apply_pair] at h
                    rcases h with ⟨rfl,rfl⟩
                    exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
                  · simp only [if_true] at h
                    replace h := if_result _ _ _ _ h
                    rcases h with ⟨hverifyGate, h⟩ | ⟨hverifyGate, h⟩
                    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                      rcases h with ⟨rfl,rfl⟩
                      exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
                    · replace h := bind_success _ _ _ h
                      rcases h with ⟨⟨cfi7,e19⟩,hc7,h⟩
                      simp only [uncurry_apply_pair] at h
                      replace h := bind_success _ _ _ h
                      rcases h with ⟨expected,hcExpected,h⟩
                      replace h := bind_success _ _ _ h
                      rcases h with ⟨⟨word,e20⟩,hfinal,h⟩
                      simp only [uncurry_apply_pair] at h
                      replace h := if_result _ _ _ _ h
                      rcases h with ⟨hCFIgate,h⟩ | ⟨hCFIgate,h⟩
                      · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                          fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                          uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                        rcases h with ⟨rfl,rfl⟩
                        exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
                      · simp only [fi.delay_source_failed, bind_tc_ok, uncurry_apply_pair] at h
                        cases hDelay : e20.backend.delayFailed <;>
                          simp only [hDelay, Bool.false_eq_true, if_false, if_true,
                            ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                            fi.zeroize_barrier, bind_tc_ok, uncurry_apply_pair,
                            Result.ok.injEq, Prod.mk.injEq] at h <;>
                          rcases h with ⟨rfl,rfl⟩ <;>
                          exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩



                · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                    uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                  rcases h with ⟨rfl,rfl⟩
                  exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
          · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
              fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
              uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
            rcases h with ⟨rfl,rfl⟩
            exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
        · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
            fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
            uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
          rcases h with ⟨rfl,rfl⟩
          exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩
    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      rcases h with ⟨rfl,rfl⟩
      exact Or.inr ⟨_,_,wipe_barrier_suffix _ _⟩


end secure_wrapper_model
