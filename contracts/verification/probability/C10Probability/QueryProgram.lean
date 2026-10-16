import C10Probability.Memo

/-! Finite adaptive query programs. The index bounds every continuation's
number of queries; it is not expected work. A continuation sees the reply,
not the oracle's private table. A PMF over programs supplies client randomness.
This is a small model of bounded clients, not a translation of the C10 signer. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

inductive QueryProgram (K α R : Type*) : ℕ → Type _
  | done {n : ℕ} (value : R) : QueryProgram K α R n
  | query {n : ℕ} (key : K) (next : α → QueryProgram K α R n) :
      QueryProgram K α R (n + 1)

variable {K α R : Type*} [DecidableEq K]

def evalProgram (p : PMF α) : {n : ℕ} → QueryProgram K α R n →
    Memo K α → PMF (R × Memo K α)
  | _, .done value, table => PMF.pure (value, table)
  | _, .query key next, table => (memoQuery p table key).bind fun out =>
      evalProgram p (next out.1) out.2

def randomizedProgram (p : PMF α) {n : ℕ}
    (client : PMF (QueryProgram K α R n)) (table : Memo K α) : PMF (R × Memo K α) :=
  client.bind fun program => evalProgram p program table

theorem evalProgram_done (p : PMF α) (n : ℕ) (value : R) (table : Memo K α) :
    evalProgram p (.done (n := n) value) table = PMF.pure (value, table) := by rfl

theorem evalProgram_cached (p : PMF α) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (table : Memo K α) (value : α)
    (h : table key = some value) :
    evalProgram p (.query key next) table = evalProgram p (next value) table := by
  simp [evalProgram, memoQuery_cached p table key value h]

theorem evalProgram_fresh (p : PMF α) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (table : Memo K α) (h : table key = none) :
    evalProgram p (.query key next) table =
      p.bind (fun value => evalProgram p (next value)
        (Function.update table key (some value))) := by
  rw [evalProgram, memoQuery_fresh p table key h, PMF.bind_map]
  rfl

theorem randomizedProgram_pure (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) :
    randomizedProgram p (PMF.pure program) table = evalProgram p program table := by
  simp [randomizedProgram]

theorem evalProgram_one (p : PMF α) (key : K) (table : Memo K α) :
    evalProgram p (.query key (fun value => .done (n := 0) value)) table =
      memoQuery p table key := by
  simp [evalProgram]

theorem evalProgram_zero (p : PMF α) (program : QueryProgram K α R 0)
    (table : Memo K α) : ∃ value, evalProgram p program table = PMF.pure (value, table) := by
  cases program with
  | done value => exact ⟨value, rfl⟩

theorem evalProgram_preserves (p : PMF α) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (key : K) (value : α) (h : table key = some value)
    (out : R × Memo K α) (ho : out ∈ (evalProgram p program table).support) :
    out.2 key = some value := by
  induction program generalizing table out with
  | done result =>
    have he : out = (result, table) := by simpa [evalProgram] using ho
    simpa [he] using h
  | query first next ih =>
    rw [evalProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    exact ih reply.1 reply.2 (memoQuery_preserves p table first key value h reply hr) out ho

theorem evalProgram_repeated (p : PMF α) (key : K) (table : Memo K α)
    (h : table key = none) :
    evalProgram p (.query key (fun first => .query key
      (fun second => .done (n := 0) (first, second)))) table =
        p.map (fun value => ((value, value), Function.update table key (some value))) := by
  rw [evalProgram_fresh p key _ table h]
  simp [evalProgram, memoQuery, PMF.map, Function.comp_def]

def adaptiveBool : QueryProgram Bool Bool (Bool × Bool) 2 :=
  .query false (fun first => .query first (fun second => .done (first, second)))

/- If the first reply is false, the second query repeats its input and cannot
return true. The second key is genuinely chosen from the first reply. -/
theorem adaptiveBool_cached_branch :
    ((evalProgram fairReply adaptiveBool (fun _ => none)).map Prod.fst)
      (false, true) = 0 := by
  simp [evalProgram, adaptiveBool, memoQuery, PMF.map_bind, PMF.bind_map,
    PMF.pure_map, PMF.bind_apply, fairReply, tsum_fintype]

end
end C10Probability
