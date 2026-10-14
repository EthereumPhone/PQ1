import Extracted.SecureWrapper.Funs
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

private theorem fill_backend {N : Std.Usize} (e out : Effects)
    (before after : Std.Array Std.U8 N) (r : Aeneas.Std.core.result.Result Unit Unit)
    (h : rng_strong.fill e before = .ok (r,out,after)) : out.backend = e.backend := by
  unfold rng_strong.fill at h
  generalize hh : e.backend.fill e.fills = pair at h
  rcases pair with ⟨accepted,bytes⟩
  dsimp only at h
  by_cases hl : bytes.length = N.val
  · simp only [dif_pos hl, Result.ok.injEq, Prod.mk.injEq] at h
    rcases h with ⟨_,rfl,_⟩
    rfl
  · simp only [dif_neg hl] at h
    cases h

def releaseEvents (sk : sphincs_c10.SigningKey) (msg : Bytes32) (sig : Signature)
    (opt : Bytes16) (sha shb : Bytes32) (actual expected : Std.U32) : List Event :=
  [.sign sk.sk_seed msg sk.pk_seed sk.pk_root (some opt) sha sig,
   .bump production.CFI_STEP_SIGN_A, .wait,
   .sign sk.sk_seed msg sk.pk_seed sk.pk_root (some opt) shb sig,
   .bump production.CFI_STEP_SIGN_B, .compare sig.val sig.val true,
   .bump production.CFI_STEP_CT_EQ, .wait,
   .verify sk.pk_seed sk.pk_root msg sig true, .sentinel true fi.OK_SENTINEL,
   .bump production.CFI_STEP_VERIFY_GATE, .cfiCheck actual expected fi.OK_SENTINEL,
   .delaySource false, .wipe opt.val, .barrier]

/-- A successful return has this exact final call transcript: two byte-equal
    signing outputs with identical key/message/OptRand, verification of the
    returned bytes, the matching CFI sum, a successful delay-source status check, then cleanup. -/
theorem wrapper_success_certificate (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress_inner sk msg progress e fi.OK_SENTINEL =
      .ok (.Ok sig, out)) :
    ∃ opt sha shb prior actual expected,
      actual = expected ∧
      production.c10_sign_verified_with_progress_inner.CFI_EXPECTED = .ok expected ∧
      out.trace = prior ++ releaseEvents sk msg sig opt sha shb actual expected ∧
      e.backend.sign sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) sha = .ok sig ∧
      e.backend.sign sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) shb = .ok sig ∧
      e.backend.verify sk.pk_seed sk.pk_root msg sig = .ok true ∧
      e.backend.delayFailed = false := by
  simp only [production.c10_sign_verified_with_progress_inner,
    fi.CfiCounter.new, fi.check_true_into_sentinel,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
    core.hint.black_box, bind_tc_ok, uncurry_apply_pair, decide_true, if_true] at h
  replace h := if_result _ _ _ _ h
  rcases h with ⟨_, h⟩ | ⟨_, h⟩
  · cases h
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
        cases h.1
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
              cases h.1
            · replace h := if_result _ _ _ _ h
              rcases h with ⟨_, h⟩ | ⟨_, h⟩
              · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                  fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                  uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                cases h.1
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
                have he1 : e1.backend = e.backend := by
                  simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc
                  rcases hc with ⟨_,rfl⟩; rfl
                have he2 := fill_backend _ _ _ _ _ hr
                have he3 : e3.backend = e2.backend := by
                  simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc2
                  rcases hc2 with ⟨_,rfl⟩; rfl
                have he4 := fill_backend _ _ _ _ _ hra
                have he5 := fill_backend _ _ _ _ _ hrb
                have he6 : e6.backend = e5.backend := by
                  simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    Result.ok.injEq, Prod.mk.injEq] at hw1
                  rcases hw1 with ⟨_,rfl⟩; rfl
                have he7 : e7.backend = e6.backend := by
                  simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    Result.ok.injEq, Prod.mk.injEq] at hw2
                  rcases hw2 with ⟨_,rfl⟩; rfl
                have he8 : e8.backend = e7.backend := by
                  cases hb1; rfl
                have he9 : e9.backend = e8.backend := by
                  simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc3
                  rcases hc3 with ⟨_,rfl⟩; rfl
                have hBackend : e9.backend = e.backend :=
                  he9.trans (he8.trans (he7.trans (he6.trans
                    (he5.trans (he4.trans (he3.trans (he2.trans he1)))))))
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
                  · replace h := if_result _ _ _ _ h
                    rcases h with ⟨_,h⟩ | ⟨hgate,_⟩
                    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                        fi.zeroize_barrier,nsc.zeroize_sensitive_state,bind_tc_ok,
                        uncurry_apply_pair,Result.ok.injEq,Prod.mk.injEq] at h
                      cases h.1
                    · have hz : ((0#u32) != fi.OK_SENTINEL) = true := by
                        unfold fi.OK_SENTINEL; decide
                      simp only [Bool.false_eq_true,if_false] at hgate
                      exact False.elim (hgate hz)
                  · simp only [if_true] at h
                    replace h := if_result _ _ _ _ h
                    rcases h with ⟨hverifyGate, h⟩ | ⟨hverifyGate, h⟩
                    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                      cases h.1
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
                        cases h.1
                      · simp only [fi.delay_source_failed, bind_tc_ok, uncurry_apply_pair] at h
                        have hDelay : e20.backend.delayFailed = false := by
                          by_contra hn
                          have ht : e20.backend.delayFailed = true := Bool.eq_true_of_not_eq_false hn
                          simp only [ht, if_true,
                            ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                            fi.zeroize_barrier, bind_tc_ok, uncurry_apply_pair,
                            Result.ok.injEq, Prod.mk.injEq] at h
                          cases h.1
                        simp only [hDelay, Bool.false_eq_true, if_false] at h
                        simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                          fi.zeroize_barrier, bind_tc_ok, uncurry_apply_pair,
                          Result.ok.injEq, Prod.mk.injEq,
                          Aeneas.Std.core.result.Result.Ok.injEq] at h
                        rcases h with ⟨rfl,rfl⟩
                        change Result.ok (Array.to_slice sig_a) = Result.ok sa at hsla
                        change Result.ok (Array.to_slice sig_b) = Result.ok sb at hslb
                        cases hsla
                        cases hslb
                        cases hcompare
                        simp only [SliceU8.Insts.Secure_wrapper_modelSubtleConstantTimeEq.ct_eq,
                          Array.to_slice, Result.ok.injEq, Prod.mk.injEq,
                          decide_eq_true_eq] at heq
                        have hsigs : sig_a = sig_b := Subtype.ext heq.1
                        subst sig_b
                        rcases heq with ⟨_, rfl⟩
                        unfold sphincs_c10.SigningKey.sign_with_shuffle at hsa hsb
                        replace hsa := bind_success _ _ _ hsa
                        rcases hsa with ⟨sig0, hbackend_a, hsa⟩
                        simp only [Result.ok.injEq, Prod.mk.injEq] at hsa
                        rcases hsa with ⟨rfl, rfl⟩
                        simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc4
                        rcases hc4 with ⟨rfl,rfl⟩
                        simp only [fi.wait_random, Result.ok.injEq] at hw
                        subst e12
                        replace hsb := bind_success _ _ _ hsb
                        rcases hsb with ⟨sig1,hbackend_b,hsb⟩
                        simp only [Result.ok.injEq,Prod.mk.injEq] at hsb
                        rcases hsb with ⟨rfl,rfl⟩
                        simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc5 hc6
                        rcases hc5 with ⟨rfl,rfl⟩
                        rcases hc6 with ⟨rfl,rfl⟩
                        simp only [fi.wait_random, Result.ok.injEq] at hw2
                        subst e17
                        have hverifyWord : (if e18.checks = 0 then e18.backend.rateWord else e18.backend.verifyWord) = fi.OK_SENTINEL := by
                          apply UScalar.eq_of_val_eq
                          simpa using hverifyGate
                        have hword : word = fi.OK_SENTINEL := by
                          apply UScalar.eq_of_val_eq
                          simpa using hCFIgate
                        have hactual : cfi7.accum = expected := by
                          by_contra hn
                          have hx := hfinal
                          simp only [fi.CfiCounter.check_into_sentinel, if_neg hn,
                            Result.ok.injEq, Prod.mk.injEq] at hx
                          have hz : (0#u32) = fi.OK_SENTINEL := hx.1.trans hword
                          have hne : (0#u32) ≠ fi.OK_SENTINEL := by unfold fi.OK_SENTINEL; decide
                          exact hne hz
                        unfold sphincs_c10.verify at hv
                        replace hv := bind_success _ _ _ hv
                        rcases hv with ⟨value,hbackend,hv⟩
                        simp only [Result.ok.injEq,Prod.mk.injEq] at hv
                        rcases hv with ⟨rfl,rfl⟩
                        simp only [fi.CfiCounter.bump, Result.ok.injEq, Prod.mk.injEq] at hc7
                        rcases hc7 with ⟨rfl,rfl⟩
                        simp only [fi.CfiCounter.check_into_sentinel,
                          Result.ok.injEq, Prod.mk.injEq] at hfinal
                        rcases hfinal with ⟨hwordEq,rfl⟩
                        simp only [emit] at hverifyWord hactual hwordEq
                        simp only [if_pos hactual] at hwordEq
                        have hcfiWord := hwordEq.trans hword
                        refine ⟨random,sha,shb,e9.trace,expected,expected,rfl,hcExpected,?_⟩
                        refine ⟨?_, ?_, ?_, ?_, ?_⟩
                        · simp [emit, releaseEvents, List.append_assoc, hverifyWord,
                            hactual, hwordEq, hword, hcfiWord, hDelay]
                        · simpa only [hBackend] using hbackend_a
                        · simpa only [emit,hBackend] using hbackend_b
                        · simpa only [emit,hBackend] using hbackend
                        · simpa only [emit,hBackend] using hDelay


                · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
                    fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
                    uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
                  cases h.1
          · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
              fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
              uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
            cases h.1
        · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
            fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
            uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
          cases h.1
    · simp only [ArrayU8N.Insts.Secure_wrapper_modelZeroizeZeroize.zeroize,
        fi.zeroize_barrier, nsc.zeroize_sensitive_state, bind_tc_ok,
        uncurry_apply_pair, Result.ok.injEq, Prod.mk.injEq] at h
      cases h.1

/-- Projection of the backend certificate to the exact release call trace. -/
theorem wrapper_success_transcript (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress_inner sk msg progress e fi.OK_SENTINEL =
      .ok (.Ok sig, out)) :
    ∃ opt sha shb prior actual expected,
      actual = expected ∧
      production.c10_sign_verified_with_progress_inner.CFI_EXPECTED = .ok expected ∧
      out.trace = prior ++ releaseEvents sk msg sig opt sha shb actual expected := by
  obtain ⟨opt,sha,shb,prior,actual,expected,ha,hc,ht,_,_,_,_⟩ :=
    wrapper_success_certificate sk msg progress e out sig h
  exact ⟨opt,sha,shb,prior,actual,expected,ha,hc,ht⟩

/-- The ordinary public entry retains the same release certificate after
    its rate-charge and wrapping-increment read-back gates. -/
theorem wrapper_entry_success_certificate (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (.Ok sig,out)) :
    ∃ opt sha shb prior actual expected,
      actual = expected ∧
      production.c10_sign_verified_with_progress_inner.CFI_EXPECTED = .ok expected ∧
      out.trace = prior ++ releaseEvents sk msg sig opt sha shb actual expected ∧
      e.backend.sign sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) sha = .ok sig ∧
      e.backend.sign sk.sk_seed sk.pk_seed sk.pk_root msg (some opt) shb = .ok sig ∧
      e.backend.verify sk.pk_seed sk.pk_root msg sig = .ok true ∧
      e.backend.delayFailed = false := by
  unfold production.c10_sign_verified_with_progress at h
  replace h := bind_success _ _ _ h
  rcases h with ⟨⟨before,e1⟩,hr,h⟩
  simp only [uncurry_apply_pair] at h
  replace h := bind_success _ _ _ h
  rcases h with ⟨⟨r,e2⟩,hp,h⟩
  simp only [uncurry_apply_pair] at h
  cases r <;> simp only [core.result.Result.Insts.CoreOpsTry_traitTry.branch, bind_tc_ok] at h
  · replace h := bind_success _ _ _ h
    rcases h with ⟨⟨after,e3⟩,ha,h⟩
    simp only [uncurry_apply_pair,lift,bind_tc_ok] at h
    replace h := if_result _ _ _ _ h
    rcases h with ⟨_,h⟩ | ⟨_,h⟩
    · cases h
    · have he1 : e1.backend = e.backend := by
        simp only [sign_rate.signs_this_session, Result.ok.injEq, Prod.mk.injEq] at hr
        rcases hr with ⟨_,rfl⟩; rfl
      have he2 : e2.backend = e1.backend := by
        simp only [sign_rate.pre_sign, Result.ok.injEq, Prod.mk.injEq] at hp
        rcases hp with ⟨_,rfl⟩; rfl
      have he3 : e3.backend = e2.backend := by
        simp only [sign_rate.signs_this_session, Result.ok.injEq, Prod.mk.injEq] at ha
        rcases ha with ⟨_,rfl⟩; rfl
      have hb := he3.trans (he2.trans he1)
      simpa only [hb] using wrapper_success_certificate sk msg progress e3 out sig h
  · simp [core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
      Aeneas.Std.core.convert.FromSame, Aeneas.Std.core.convert.FromSame.from_, lift,
      uncurry_apply_pair] at h

/-- The public entry's exact release call trace. -/
theorem wrapper_entry_success_transcript (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (.Ok sig,out)) :
    ∃ opt sha shb prior actual expected,
      actual = expected ∧
      production.c10_sign_verified_with_progress_inner.CFI_EXPECTED = .ok expected ∧
      out.trace = prior ++ releaseEvents sk msg sig opt sha shb actual expected := by
  obtain ⟨opt,sha,shb,prior,actual,expected,ha,hc,ht,_,_,_,_⟩ :=
    wrapper_entry_success_certificate sk msg progress e out sig h
  exact ⟨opt,sha,shb,prior,actual,expected,ha,hc,ht⟩

/-- The verified event concerns the returned signature, original public key
    and exact caller message, not an unrelated verifier invocation. -/
theorem wrapper_entry_success_verified (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress e = .ok (.Ok sig,out)) :
    Event.verify sk.pk_seed sk.pk_root msg sig true ∈ out.trace := by
  obtain ⟨opt,sha,shb,prior,actual,expected,_,_,ht⟩ :=
    wrapper_entry_success_transcript sk msg progress e out sig h
  rw [ht]
  simp [releaseEvents]

/-- A refused rate charge never reaches entropy, signing, verification or
    relock; it leaves exactly the read and charge events. -/
theorem wrapper_rate_refusal (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (h : b.rateAccepted = false) :
    production.c10_sign_verified_with_progress sk msg progress ⟨b,[],0,0,0⟩ =
      .ok (.Err (),⟨b,[.readRate b.rateBefore,.charge false],1,0,0⟩) := by
  simp [production.c10_sign_verified_with_progress,sign_rate.signs_this_session,
    sign_rate.pre_sign,h,emit,core.result.Result.Insts.CoreOpsTry_traitTry.branch,
    core.result.Result.Insts.CoreOpsTry_traitFromResidualResultInfallibleE.from_residual,
    Aeneas.Std.core.convert.FromSame,Aeneas.Std.core.convert.FromSame.from_,lift,
    uncurry_apply_pair]

/-- A charge that fails its wrapping read-back is refused before entropy or CFI. -/
theorem wrapper_rate_readback_refusal (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (h : b.rateAccepted = true)
    (hm : b.rateAfter ≠ Aeneas.Std.core.num.U32.wrapping_add b.rateBefore 1#u32) :
    production.c10_sign_verified_with_progress sk msg progress ⟨b,[],0,0,0⟩ =
      .ok (.Err (),⟨b,[.readRate b.rateBefore,.charge true,.readRate b.rateAfter],2,0,0⟩) := by
  have hv : b.rateAfter.val ≠ (Aeneas.Std.core.num.U32.wrapping_add b.rateBefore 1#u32).val := by
    intro hv; exact hm (UScalar.eq_of_val_eq hv)
  simp [production.c10_sign_verified_with_progress,sign_rate.signs_this_session,
    sign_rate.pre_sign,h,emit,core.result.Result.Insts.CoreOpsTry_traitTry.branch,
    lift,uncurry_apply_pair,hv]
  intro he; exact False.elim (hv (by simpa using he))

/-- Invalid rate evidence is refused before any entropy or signing call. -/
theorem wrapper_rate_sentinel_refusal (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (e : Effects) (charge : Std.U32)
    (hc : charge ≠ fi.OK_SENTINEL) :
    production.c10_sign_verified_with_progress_inner sk msg progress e charge =
      .ok (.Err (),emit (emit {e with checks := e.checks+1} .initCfi) (.sentinel false 0#u32)) := by
  have hv : charge.val ≠ fi.OK_SENTINEL.val := by
    intro hv; exact hc (UScalar.eq_of_val_eq hv)
  have hn : charge ≠ 2779096485#u32 := by simpa only [fi.OK_SENTINEL] using hc
  simp [production.c10_sign_verified_with_progress_inner,fi.CfiCounter.new,
    fi.check_true_into_sentinel,
    production.c10_sign_verified_with_progress_inner.closure.Insts.CoreOpsFunctionFnMutTupleBool.call_mut,
    core.hint.black_box,hn,fi.OK_SENTINEL,emit,uncurry_apply_pair]

/-- Successful public release requires both an accepted rate charge and its
    exact wrapping increment. No readiness premise is supplied by the caller. -/
theorem wrapper_success_requires_rate (sk : sphincs_c10.SigningKey) (msg : Bytes32)
    (progress : Unit × Unit) (b : Backend) (out : Effects) (sig : Signature)
    (h : production.c10_sign_verified_with_progress sk msg progress ⟨b,[],0,0,0⟩ =
      .ok (.Ok sig,out)) :
    b.rateAccepted = true ∧
      b.rateAfter = Aeneas.Std.core.num.U32.wrapping_add b.rateBefore 1#u32 := by
  have hr : b.rateAccepted = true := by
    cases hb : b.rateAccepted
    · rw [wrapper_rate_refusal sk msg progress b hb] at h
      cases h
    · rfl
  refine ⟨hr,?_⟩
  by_contra hm
  rw [wrapper_rate_readback_refusal sk msg progress b hr hm] at h
  cases h

end secure_wrapper_model
