/-
SphincsCVerify.Interpreter.RelHmsg — RESEARCH (#1155 gas track, batch 10): obligation O1 of the
skeleton (`RelSkeleton.HmsgObl`), the H_msg prefix and the gates. Reference statements 0..18,
optimized 0..19. The two prefixes run the same statements except for the constants (the
optimized v1 adds `TB` and puts `OUT` at `0x620`) and the length gate's revert payload, which
the real signature length never reaches. Both key-shape gates and the forced-zero gate fire
alike, and on fall-through `HmsgExit` holds. Mathlib-free; no
`sorry`/`admit`/`native_decide`/`bv_decide` and no new axioms.
-/

import SphincsCVerify.Interpreter.RelSkeleton
import SphincsCVerify.Interpreter.RelMid

namespace SphincsCVerify.Interpreter.C10.RelHmsg

open SphincsCVerify.Interpreter
open SphincsCVerify.Interpreter.C10
open SphincsCVerify.Interpreter.C10.RelE1 (execList_single)
open SphincsCVerify.Interpreter.C10.RelChain
open SphincsCVerify.Interpreter.C10.RelWotsEntry
open SphincsCVerify.Interpreter.C10.RelSkeleton
open SphincsCVerify.Spec (ByteVec)

def ONES : Nat := 115792089237316195423570985008687907853269984665640564039457584007913129639935
def NMLIT : Nat := 115792089237316195423570985008687907852929702298719625575994209400481361428480

theorem nmlit_eq : NMLIT = NMASK := rfl

/-- The key-shape gate on `x` (statements 3/4 of the reference). -/
def keyGate (x : String) : Stmt :=
  .ifnz (.iszero (.bin .eq (.bin .band (.var x) (.var "N_MASK")) (.var x)))
    [ .mstore (.lit 0) (.lit 0), .ret (.lit 0) ]

/-- The shared H_msg body (reference statements 5..16, optimized 6..17). -/
def body1 : List Stmt :=
  [ .letv "seed" (.var "pkSeed"), .letv "root" (.var "pkRoot"), .mstore (.lit 0) (.var "seed")
  , .letv "R" (.bin .band (.calldataload .sigOffset) (.var "N_MASK"))
  , .mstore (.lit 32) (.var "root"), .mstore (.lit 64) (.var "R"), .mstore (.lit 96) (.var "message")
  , .mstore (.lit 128) (.lit ONES), .sha256 (.lit 0) (.lit 160) (.var "OUT")
  , .letv "digest" (.mload (.var "OUT"))
  , .letv "htIdx" (.bin .band (.bin .shr (.lit 143) (.var "digest")) (.lit 262143))
  , .letv "dVal" (.var "digest") ]

/-- The forced-zero gate and `sigBase`. -/
def tail1 : List Stmt :=
  [ .ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 2047)) [ .revert ]
  , .letv "sigBase" .sigOffset ]

def refLen : Stmt := .ifnz (.iszero (.bin .eq .sigLength (.lit 4008))) [ .revert ]
def headLen : Stmt := .ifnz (.iszero (.bin .eq .sigLength (.lit 4008)))
  [ .mstore (.lit 0) (.lit 3963877391197344453575983046348115674221700746820753546331534351508065746944)
  , .mstore (.lit 4) (.lit 32), .mstore (.lit 36) (.lit 18)
  , .mstore (.lit 68) (.lit 33214008156304899519981230437682874387184308421256086808908086100849852416000)
  , .revert ]

set_option maxRecDepth 100000 in
theorem refHmsg_split : refHmsg = [ .letv "N_MASK" (.lit NMLIT), .letv "OUT" (.lit 1536) ]
    ++ (refLen :: keyGate "pkSeed" :: keyGate "pkRoot" :: (body1 ++ tail1)) := rfl

set_option maxRecDepth 100000 in
theorem headHmsg_split : headHmsg = [ .letv "N_MASK" (.lit NMLIT), .letv "TB" (.lit 128),
    .letv "OUT" (.lit 1568) ] ++ (headLen :: keyGate "pkSeed" :: keyGate "pkRoot" :: (body1 ++ tail1)) := rfl

/-! ## 2. The pieces, executed -/

/-- The 160 bytes H_msg hashes: seed, root, `R`, message, the all-ones word. -/
def hm5 {n : Nat} (sig : ByteVec n) (w : VM) : ByteMemory :=
  mstore32 (mstore32 (mstore32 (mstore32 (mstore32 w.mem 0 (w.env "pkSeed")) 32 (w.env "pkRoot"))
    64 (calldataload sig 0 &&& w.env "N_MASK")) 96 (w.env "message")) 128 ONES

set_option maxHeartbeats 8000000 in
theorem body1_eval {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (w : VM)
    (hOUT : 0xA0 ≤ w.env "OUT") :
    (execList sha sig body1 w).2 = none
    ∧ (execList sha sig body1 w).1.env "digest" = wordOf (sha (slice (hm5 sig w) 0 160))
    ∧ (execList sha sig body1 w).1.env "htIdx"
        = (wordOf (sha (slice (hm5 sig w) 0 160)) >>> 143) &&& 262143
    ∧ (execList sha sig body1 w).1.env "dVal" = wordOf (sha (slice (hm5 sig w) 0 160))
    ∧ (execList sha sig body1 w).1.env "seed" = w.env "pkSeed"
    ∧ (execList sha sig body1 w).1.env "root" = w.env "pkRoot"
    ∧ (∀ k, k < 32 → (execList sha sig body1 w).1.mem k = beByte (w.env "pkSeed") k)
    ∧ (∀ k, 16 ≤ k → k < 32 →
        (execList sha sig body1 w).1.mem (64 + k) = beByte (calldataload sig 0 &&& w.env "N_MASK") k)
    ∧ (∀ x, x ≠ "seed" → x ≠ "root" → x ≠ "R" → x ≠ "digest" → x ≠ "htIdx" → x ≠ "dVal" →
        (execList sha sig body1 w).1.env x = w.env x)
    ∧ (∀ a, 0xA0 ≤ a → a < w.env "OUT" → (execList sha sig body1 w).1.mem a = w.mem a) := by
  unfold body1
  repeat rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt])]
  simp only [execList, execStmt, eval]
  simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  refine ⟨trivial, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_, ?_⟩
  · rw [mload32_digest]; rfl
  · rw [mload32_digest]; rfl
  · rw [mload32_digest]; rfl
  · trivial
  · trivial
  · intro k hk
    rw [writeRegion_frame _ _ _ k (by omega), mstore32_frame _ 128 _ k (by omega),
      mstore32_frame _ 96 _ k (by omega), mstore32_frame _ 64 _ k (by omega),
      mstore32_frame _ 32 _ k (by omega)]
    have h0 := mstore32_get w.mem 0 (w.env "pkSeed") k hk
    rw [Nat.zero_add] at h0
    exact h0
  · intro k h1 h2
    rw [writeRegion_frame _ _ _ (64 + k) (by omega), mstore32_frame _ 128 _ (64 + k) (by omega),
      mstore32_frame _ 96 _ (64 + k) (by omega), mstore32_get _ 64 _ k h2]
  · intro x a1 a2 a3 a4 a5 a6
    simp (disch := assumption) only [setVar_get_ne]
  · intro a h1 h2
    rw [writeRegion_frame _ _ _ a (Or.inl h2), mstore32_frame _ 128 _ a (by omega),
      mstore32_frame _ 96 _ a (by omega), mstore32_frame _ 64 _ a (by omega),
      mstore32_frame _ 32 _ a (by omega), mstore32_frame _ 0 _ a (by omega)]

theorem keyGate_pass {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (x : String) (w : VM)
    (h : w.env x &&& w.env "N_MASK" = w.env x) : execStmt sha sig (keyGate x) w = (w, none) := by
  simp [keyGate, execStmt, eval, h]

theorem keyGate_fire {n : Nat} (sha : List UInt8 → ByteVec 32) (sig : ByteVec n) (x : String) (w : VM)
    (h : ¬ w.env x &&& w.env "N_MASK" = w.env x) :
    (execStmt sha sig (keyGate x) w).2 = some (Halt.returned (mload32 (mstore32 w.mem 0 0) 0)) := by
  simp [keyGate, execStmt, eval, h]
  rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
  simp [execStmt, eval]

/-! ## 3. O1 discharged -/

theorem sigLen_eq : Spec.SignatureLen = 4008 := by decide

set_option maxHeartbeats 16000000 in
/-- The prefixes from any common starting state. -/
theorem hmsg_rel (sig : ByteVec Spec.SignatureLen) (v : VM)
    (hz0 : ∀ a, 0xC0 ≤ a → a < 0x260 → v.mem a = 0) :
    (execList c10Oracle sig refHmsg v).2 = (execList c10Oracle sig headHmsg v).2
    ∧ ((execList c10Oracle sig refHmsg v).2 = none →
        HmsgExit (execList c10Oracle sig refHmsg v).1 (execList c10Oracle sig headHmsg v).1) := by
  rw [refHmsg_split, headHmsg_split]
  have cR : execList c10Oracle sig [ .letv "N_MASK" (.lit NMLIT), .letv "OUT" (.lit 1536) ] v
      = ({ v with env := setVar (setVar v.env "N_MASK" NMLIT) "OUT" 1536 }, none) := by
    rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval]
  have cH : execList c10Oracle sig [ .letv "N_MASK" (.lit NMLIT), .letv "TB" (.lit 128),
      .letv "OUT" (.lit 1568) ] v
      = ({ v with env := setVar (setVar (setVar v.env "N_MASK" NMLIT) "TB" 128) "OUT" 1568 }, none) := by
    rw [execList_cons_none _ _ _ _ _ (by simp only [execStmt]),
      execList_cons_none _ _ _ _ _ (by simp only [execStmt]), execList_single]
    simp only [execStmt, eval]
  rw [app_none _ _ _ _ _ (by rw [cR]), cR, app_none _ _ _ _ _ (by rw [cH]), cH]
  generalize hwR : ({ v with env := setVar (setVar v.env "N_MASK" NMLIT) "OUT" 1536 } : VM) = wR
  generalize hwH : ({ v with env := setVar (setVar (setVar v.env "N_MASK" NMLIT) "TB" 128) "OUT" 1568 } : VM)
    = wH
  have mR : wR.mem = v.mem := by rw [← hwR]
  have mH : wH.mem = v.mem := by rw [← hwH]
  have gR : ∀ x, x ≠ "N_MASK" → x ≠ "OUT" → wR.env x = v.env x := by
    intro x a b; rw [← hwR]; simp only; rw [setVar_get_ne _ _ _ _ b, setVar_get_ne _ _ _ _ a]
  have gH : ∀ x, x ≠ "N_MASK" → x ≠ "TB" → x ≠ "OUT" → wH.env x = v.env x := by
    intro x a b c; rw [← hwH]; simp only
    rw [setVar_get_ne _ _ _ _ c, setVar_get_ne _ _ _ _ b, setVar_get_ne _ _ _ _ a]
  have nR : wR.env "N_MASK" = NMASK := by rw [← hwR]; simp (disch := decide) only [setVar_get_eq, setVar_get_ne]; rfl
  have nH : wH.env "N_MASK" = NMASK := by rw [← hwH]; simp (disch := decide) only [setVar_get_eq, setVar_get_ne]; rfl
  have oR : wR.env "OUT" = 0x600 := by rw [← hwR]; simp only [setVar_get_eq]
  have oH : wH.env "OUT" = 0x620 := by rw [← hwH]; simp only [setVar_get_eq]
  have tH : wH.env "TB" = 0x80 := by rw [← hwH]; simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
  -- the length gates are not taken
  have lR : execStmt c10Oracle sig refLen wR = (wR, none) := by simp [refLen, execStmt, eval, sigLen_eq]
  have lH : execStmt c10Oracle sig headLen wH = (wH, none) := by simp [headLen, execStmt, eval, sigLen_eq]
  rw [execList_cons_none c10Oracle sig refLen _ wR (by rw [lR]), lR,
    execList_cons_none c10Oracle sig headLen _ wH (by rw [lH]), lH]
  -- the key-shape gates fire alike
  by_cases hS : v.env "pkSeed" &&& NMASK = v.env "pkSeed"
  · have pR := keyGate_pass c10Oracle sig "pkSeed" wR (by rw [gR _ (by decide) (by decide), nR]; exact hS)
    have pH := keyGate_pass c10Oracle sig "pkSeed" wH
      (by rw [gH _ (by decide) (by decide) (by decide), nH]; exact hS)
    rw [execList_cons_none c10Oracle sig (keyGate "pkSeed") _ wR (by rw [pR]), pR,
      execList_cons_none c10Oracle sig (keyGate "pkSeed") _ wH (by rw [pH]), pH]
    by_cases hRt : v.env "pkRoot" &&& NMASK = v.env "pkRoot"
    · have pR := keyGate_pass c10Oracle sig "pkRoot" wR (by rw [gR _ (by decide) (by decide), nR]; exact hRt)
      have pH := keyGate_pass c10Oracle sig "pkRoot" wH
        (by rw [gH _ (by decide) (by decide) (by decide), nH]; exact hRt)
      rw [execList_cons_none c10Oracle sig (keyGate "pkRoot") _ wR (by rw [pR]), pR,
        execList_cons_none c10Oracle sig (keyGate "pkRoot") _ wH (by rw [pH]), pH]
      obtain ⟨bR0, bRd, bRh, bRv, bRs, bRr, bRm, bRp, bRf, _⟩ := body1_eval c10Oracle sig wR (by rw [oR]; decide)
      obtain ⟨bH0, bHd, bHh, bHv, bHs, bHr, bHm, bHp, bHf, bHz⟩ := body1_eval c10Oracle sig wH (by rw [oH]; decide)
      have h5 : hm5 sig wH = hm5 sig wR := by
        unfold hm5
        rw [mR, mH, gR "pkSeed" (by decide) (by decide), gH "pkSeed" (by decide) (by decide) (by decide),
          gR "pkRoot" (by decide) (by decide), gH "pkRoot" (by decide) (by decide) (by decide),
          gR "message" (by decide) (by decide), gH "message" (by decide) (by decide) (by decide), nR, nH]
      rw [app_none c10Oracle sig body1 _ wR bR0, app_none c10Oracle sig body1 _ wH bH0]
      generalize hDv : wordOf (c10Oracle (slice (hm5 sig wR) 0 160)) = Dv at bRd bRh bRv
      rw [h5, hDv] at bHd bHh bHv
      generalize hr1 : (execList c10Oracle sig body1 wR).1 = r1 at bRd bRh bRv bRs bRr bRm bRp bRf
      generalize hh1 : (execList c10Oracle sig body1 wH).1 = h1 at bHd bHh bHv bHs bHr bHm bHp bHf bHz
      unfold tail1
      by_cases hz : (Dv >>> 132) &&& 2047 = 0
      · have g1 : ∀ w : VM, w.env "dVal" = Dv →
            execStmt c10Oracle sig (.ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 2047)) [ .revert ]) w
              = (w, none) := by
          intro w hw; simp [execStmt, eval, hw, hz]
        rw [execList_cons_none c10Oracle sig _ _ r1 (by rw [g1 r1 bRv]), g1 r1 bRv,
          execList_cons_none c10Oracle sig _ _ h1 (by rw [g1 h1 bHv]), g1 h1 bHv, execList_single,
          execList_single]
        refine ⟨by simp only [execStmt], fun _ => ?_⟩
        simp only [execStmt, eval]
        constructor
        all_goals simp (disch := decide) only [setVar_get_eq, setVar_get_ne]
        · rw [bHs, bRs, gH _ (by decide) (by decide) (by decide), gR _ (by decide) (by decide)]
        · intro k hk; rw [bRm k hk, bRs]
        · intro k hk; rw [bHm k hk, bRs, gH _ (by decide) (by decide) (by decide),
            gR _ (by decide) (by decide)]
        · rw [bHr, bRr, gH _ (by decide) (by decide) (by decide), gR _ (by decide) (by decide)]
        · rw [bHh, bRh]
        · rw [bRh]; exact Nat.lt_of_le_of_lt Nat.and_le_right (by decide)
        · rw [bHv, bRv]
        · intro k h1' h2'; rw [bHp k h1' h2', nH]; exact beByte_masked_low _ _ h1'
        · rw [bRf _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), nR]
        · rw [bRf _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), oR]
        · rw [bHf _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), nH]
        · rw [bHf _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), tH]
        · rw [bHf _ (by decide) (by decide) (by decide) (by decide) (by decide) (by decide), oH]
        · intro a h1' h2'
          rw [bHz a (by omega) (by rw [oH]; omega), mH]; exact hz0 a h1' h2'
      · have g1 : ∀ w : VM, w.env "dVal" = Dv →
            (execStmt c10Oracle sig (.ifnz (.bin .band (.bin .shr (.lit 132) (.var "dVal")) (.lit 2047)) [ .revert ]) w).2
              = some Halt.reverted := by
          intro w hw; simp [execStmt, eval, hw, hz, execList_single]
        rw [cons_some _ _ _ _ _ _ (g1 r1 bRv), cons_some _ _ _ _ _ _ (g1 h1 bHv)]
        exact ⟨rfl, fun h => absurd h (by simp)⟩
    · have fR := keyGate_fire c10Oracle sig "pkRoot" wR (by rw [gR _ (by decide) (by decide), nR]; exact hRt)
      have fH := keyGate_fire c10Oracle sig "pkRoot" wH (by rw [gH _ (by decide) (by decide) (by decide), nH]; exact hRt)
      rw [cons_some _ _ _ _ _ _ fR, cons_some _ _ _ _ _ _ fH, mR, mH]
      exact ⟨rfl, fun h => absurd h (by simp)⟩
  · have fR := keyGate_fire c10Oracle sig "pkSeed" wR (by rw [gR _ (by decide) (by decide), nR]; exact hS)
    have fH := keyGate_fire c10Oracle sig "pkSeed" wH (by rw [gH _ (by decide) (by decide) (by decide), nH]; exact hS)
    rw [cons_some _ _ _ _ _ _ fR, cons_some _ _ _ _ _ _ fH, mR, mH]
    exact ⟨rfl, fun h => absurd h (by simp)⟩

/-- **(O1) discharged.** -/
theorem hmsg_obl : HmsgObl := fun pkSeed pkRoot message sig =>
  hmsg_rel sig (vm0 pkSeed pkRoot message) (fun _ _ _ => rfl)

/-- **The end theorem with O1, O3, O4, O5 discharged.** FORS (O2) is an argument here only
    because its proof (`RelFors.fors_obl`) lives in a file that imports this one;
    `RelFors.head_verdict_eq_full` is the unconditional form. -/
theorem head_verdict_eq_of_fors (hf : ForsObl) (pkSeed pkRoot message : ByteVec 32)
    (sig : ByteVec Spec.SignatureLen) :
    execC10HeadAsm pkSeed pkRoot message sig = execC10Asm pkSeed pkRoot message sig :=
  head_verdict_eq_of hmsg_obl hf RelMid.mid_obl pkSeed pkRoot message sig

end SphincsCVerify.Interpreter.C10.RelHmsg
