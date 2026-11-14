/-
SphincsCVerify.Interpreter.EnvFrame — a generic *env-frame* for the Yul-subset
interpreter: a variable assigned nowhere in a statement / statement-list / loop
(recursively, including a loop's index var and loop/block/if bodies) is preserved
by execution.

Reusable across the refinement phases.  In particular it discharges the env-var
half of `wotsBody`-preservation for the hypertree layer (`HypertreePhase`): the
WOTS loops touch only `d` / `digitSum` / chain-scratch / `wotsPk`, never
`idxLeaf` / `layer` / `idxTree` / `sigBase` / `countOff` / `sigOff` / `N_MASK` /
`OUT` / `seed`, so `assignsVarList wotsBody x = false` is `decide`-able and the
frame lemma then yields `(execList … wotsBody vm).1.env x = vm.env x`.
-/
import SphincsCVerify.Interpreter.Yul

namespace SphincsCVerify.Interpreter

-- `assignsVar s x` / `assignsVarList l x`: does the statement / list assign `x`
-- (recursively: a loop's index var + loop / block / if bodies)?
mutual
def assignsVar : Stmt → String → Bool
  | .letv y _,          x => y == x
  | .setv y _,          x => y == x
  | .ifnz _ body,       x => assignsVarList body x
  | .forRange v _ body, x => (v == x) || assignsVarList body x
  | .block body,        x => assignsVarList body x
  | .mstore _ _,        _ => false
  | .sha256 _ _ _,      _ => false
  | .revert,            _ => false
  | .ret _,             _ => false
  -- batch-6 extension
  | .mstore8 _ _,       _ => false
  | .calldatacopy _ _ _, _ => false
  | .sha256h _ _ _,     _ => false
  | .forFrom v _ _ body, x => (v == x) || assignsVarList body x
def assignsVarList : List Stmt → String → Bool
  | [],        _ => false
  | s :: rest, x => assignsVar s x || assignsVarList rest x
end

mutual
theorem execStmt_env_frame {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (s : Stmt) (x : String) (vm : VM) (h : assignsVar s x = false) :
    (execStmt sha sig s vm).1.env x = vm.env x := by
  cases s with
  | letv y e =>
    have hyx : x ≠ y := fun he => by rw [assignsVar, he] at h; simp at h
    simp only [execStmt]; exact setVar_get_ne vm.env y x (eval sig vm e) hyx
  | setv y e =>
    have hyx : x ≠ y := fun he => by rw [assignsVar, he] at h; simp at h
    simp only [execStmt]; exact setVar_get_ne vm.env y x (eval sig vm e) hyx
  | mstore o val => simp only [execStmt]
  | sha256 a b c => simp only [execStmt]
  | revert => simp only [execStmt]
  | ret o => simp only [execStmt]
  | ifnz c body =>
    simp only [execStmt]
    split
    · exact execList_env_frame sha sig body x vm (by rw [assignsVar] at h; exact h)
    · rfl
  | forRange v cnt body =>
    have hvx : v ≠ x := fun he => by rw [assignsVar, he] at h; simp at h
    have hbody : assignsVarList body x = false := by
      rw [assignsVar] at h; exact (Bool.or_eq_false_iff.mp h).2
    simp only [execStmt]
    exact execFor_env_frame sha sig v body x hvx hbody (eval sig vm cnt) 0 vm
  | block body =>
    simp only [execStmt]
    exact execList_env_frame sha sig body x vm (by rw [assignsVar] at h; exact h)
  -- batch-6 extension: the three writes touch memory only; forFrom is forRange's case
  | mstore8 o val => simp only [execStmt]
  | calldatacopy a b c => simp only [execStmt]
  | sha256h a b c => simp only [execStmt]
  | forFrom v st cnt body =>
    have hvx : v ≠ x := fun he => by rw [assignsVar, he] at h; simp at h
    have hbody : assignsVarList body x = false := by
      rw [assignsVar] at h; exact (Bool.or_eq_false_iff.mp h).2
    simp only [execStmt]
    exact execFor_env_frame sha sig v body x hvx hbody _ _ vm
theorem execList_env_frame {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (stmts : List Stmt) (x : String) (vm : VM) (h : assignsVarList stmts x = false) :
    (execList sha sig stmts vm).1.env x = vm.env x := by
  cases stmts with
  | nil => simp only [execList]
  | cons s rest =>
    rw [assignsVarList] at h
    obtain ⟨hs, hr⟩ := Bool.or_eq_false_iff.mp h
    rw [execList]
    cases hex : execStmt sha sig s vm with
    | mk vm' o =>
      have hsf := execStmt_env_frame sha sig s x vm hs
      rw [hex] at hsf
      cases o with
      | none => simp only; rw [execList_env_frame sha sig rest x vm' hr]; exact hsf
      | some hh => simp only; exact hsf
theorem execFor_env_frame {n : Nat} (sha : List UInt8 → Spec.ByteVec 32) (sig : Spec.ByteVec n)
    (v : String) (body : List Stmt) (x : String) (hvx : v ≠ x)
    (hb : assignsVarList body x = false) : (rem cur : Nat) → (vm : VM) →
    (execFor sha sig v body rem cur vm).1.env x = vm.env x
  | 0, _, vm => by rw [execFor]
  | rem + 1, cur, vm => by
    rw [execFor]
    have hvm2x : ({ vm with env := setVar vm.env v cur } : VM).env x = vm.env x :=
      setVar_get_ne vm.env v x cur hvx.symm
    have hbf := execList_env_frame sha sig body x { vm with env := setVar vm.env v cur } hb
    cases hex : execList sha sig body { vm with env := setVar vm.env v cur } with
    | mk vm' o =>
      rw [hex] at hbf
      cases o with
      | none =>
        simp only
        rw [execFor_env_frame sha sig v body x hvx hb rem (cur + 1) vm', hbf, hvm2x]
      | some hh => simp only; rw [hbf, hvm2x]
end

end SphincsCVerify.Interpreter
