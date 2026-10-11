/- Refusal paths retain an explicit entropy-cleanup or fault/relock suffix. -/
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
private theorem fill_trace {N : Std.Usize} (e out : Effects)
    (before after : Std.Array Std.U8 N) (r : Aeneas.Std.core.result.Result Unit Unit)
    (h : rng_strong.fill e before = .ok (r,out,after)) :
    ∃ accepted, out.trace = e.trace ++ [.fill e.fills accepted after.val] := by
  unfold rng_strong.fill at h
  generalize hh : e.backend.fill e.fills = pair at h
  rcases pair with ⟨accepted,bytes⟩
  dsimp only at h
  by_cases hl : bytes.length = N.val
  · simp only [dif_pos hl, Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨_,rfl,rfl⟩
    exact ⟨accepted,rfl⟩
  · simp only [dif_neg hl] at h
    cases h

def EntropyRefusal (trace : List Event) : Prop :=
  ∃ prior index accepted bytes, ∃ wiped : List (List Std.U8),
    trace = prior ++ [.fill index accepted bytes] ++ wiped.map Event.wipe ++ [.barrier]

def FaultGuard : Event → Prop
  | .compare _ _ equal => equal = false
  | .sentinel _ word => word ≠ fi.OK_SENTINEL
  | .cfiCheck _ _ word => word ≠ fi.OK_SENTINEL
  | _ => False

def FaultRefusal (trace : List Event) : Prop :=
  ∃ prior guard bytes, FaultGuard guard ∧ trace = prior ++ [guard,.relock,.wipe bytes,.barrier]

theorem wrapper_inner_refusal (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects)
    (h : production.c10_sign_verified_with_progress_inner sk msg progress e fi.OK_SENTINEL =
      .ok (.Err (), out)) :
    (∃ word, word ≠ fi.OK_SENTINEL ∧ out.trace = e.trace ++ [.initCfi,.sentinel true word]) ∨
    EntropyRefusal out.trace ∨ FaultRefusal out.trace := by
  simp only [production.c10_sign_verified_with_progress_inner,
    fi.CfiCounter.new, fi.check_true_into_sentinel,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
    core.hint.black_box, bind_tc_ok, uncurry_apply_pair, decide_true, if_true] at h
  replace h := if_result _ _ _ _ h
  rcases h with ⟨hgate, h⟩ | ⟨_, h⟩
  · simp only [Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨_,rfl⟩
    refine Or.inl ⟨(if e.checks = 0 then e.backend.rateWord else e.backend.verifyWord),?_,?_⟩
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
        rcases h with ⟨_,rfl⟩
        obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hr
        refine Or.inr (Or.inl ⟨e1.trace,e1.fills,accepted,random.val,[(random).val],?_⟩)
        simp [emit,List.append_assoc,ht]
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
              rcases h with ⟨_,rfl⟩
              obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hrb
              refine Or.inr (Or.inl ⟨e4.trace,e4.fills,accepted,shb.val,[(sha).val,(shb).val,(random).val],?_⟩)
              simp [emit,List.append_assoc,ht]
            · replace h := if_result _ _ _ _ h
              rcases h with ⟨_, h⟩ | ⟨_, h⟩
              · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                  fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                  uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                rcases h with ⟨_,rfl⟩
                obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hrb
                refine Or.inr (Or.inl ⟨e4.trace,e4.fills,accepted,shb.val,[(sha).val,(shb).val,(random).val],?_⟩)
                simp [emit,List.append_assoc,ht]
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
                    rcases h with ⟨_,rfl⟩
                    refine Or.inr (Or.inr ⟨e18.trace,.sentinel false 0#u32,random.val,?_,?_⟩)
                    · change (0#u32) ≠ fi.OK_SENTINEL; unfold fi.OK_SENTINEL; decide
                    · simp [emit,List.append_assoc]
                  · simp only [if_true] at h
                    replace h := if_result _ _ _ _ h
                    rcases h with ⟨hverifyGate, h⟩ | ⟨hverifyGate, h⟩
                    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                      rcases h with ⟨_,rfl⟩
                      refine Or.inr (Or.inr ⟨e18.trace,.sentinel true
                        (if e18.checks = 0 then e18.backend.rateWord else e18.backend.verifyWord),random.val,?_,?_⟩)
                      · change (if e18.checks = 0 then e18.backend.rateWord else e18.backend.verifyWord) ≠ fi.OK_SENTINEL
                        intro he; simp [he] at hverifyGate
                      · simp [emit,List.append_assoc]
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
                        rcases h with ⟨_,rfl⟩
                        simp only [fi.CfiCounter.check_into_sentinel,Result.ok.injEq,Prod.mk.injEq] at hfinal
                        rcases hfinal with ⟨hword,rfl⟩
                        refine Or.inr (Or.inr ⟨e19.trace,.cfiCheck cfi7.accum expected
                          (if cfi7.accum = expected then e19.backend.cfiWord else 0#u32),random.val,?_,?_⟩)
                        · change (if cfi7.accum = expected then e19.backend.cfiWord else 0#u32) ≠ fi.OK_SENTINEL
                          intro he; rw [← hword,he] at hCFIgate; simp at hCFIgate
                        · simp [emit,List.append_assoc]
                      · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                          fi.zeroize_barrier, bind_tc_ok, uncurry_apply_pair,
                          Result.ok.injEq, Prod.mk.injEq] at h
                        cases h.1



                · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                    uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                  rcases h with ⟨_,rfl⟩
                  simp only [SliceU8.Insts.Secure_wrapper_modelSubtleConstantTimeEq.ct_eq,
                    Result.ok.injEq,Prod.mk.injEq] at heq
                  rcases heq with ⟨hvalue,rfl⟩
                  refine Or.inr (Or.inr ⟨e14.trace,.compare sa.val sb.val (decide (sa.val=sb.val)),random.val,?_,?_⟩)
                  · change decide (sa.val=sb.val) = false
                    rw [hvalue]; exact Bool.eq_false_iff.mpr hcompare
                  · simp [emit,List.append_assoc]
          · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
              fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
              uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
            rcases h with ⟨_,rfl⟩
            obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hrb
            refine Or.inr (Or.inl ⟨e4.trace,e4.fills,accepted,shb.val,[(sha).val,(shb).val,(random).val],?_⟩)
            simp [emit,List.append_assoc,ht]
        · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
            fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
            uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
          rcases h with ⟨_,rfl⟩
          obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hra
          refine Or.inr (Or.inl ⟨e3.trace,e3.fills,accepted,sha.val,[(sha).val,(Array.repeat 32#usize 0#u8).val,(random).val],?_⟩)
          simp [emit,List.append_assoc,ht]
    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      rcases h with ⟨_,rfl⟩
      obtain ⟨accepted,ht⟩ := fill_trace _ _ _ _ _ hr
      refine Or.inr (Or.inl ⟨e1.trace,e1.fills,accepted,random.val,[(random).val],?_⟩)
      simp [emit,List.append_assoc,ht]


end secure_wrapper_model
