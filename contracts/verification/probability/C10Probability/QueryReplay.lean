import C10Probability.ChainCollection

/-! A completed memoized execution can be replayed by lookup in its final
cache. Replay never samples, inserts a missing value, or assumes freshness.
The same witness survives every later cache extension. -/
namespace C10Probability
noncomputable section

variable {K α R T : Type*}

def MemoExtends (before after : Memo K α) : Prop :=
  ∀ key value, before key = some value → after key = some value

theorem memo_extends_refl (table : Memo K α) : MemoExtends table table := by
  intro key value h
  exact h

theorem memo_extends_trans {first second third : Memo K α}
    (left : MemoExtends first second) (right : MemoExtends second third) :
    MemoExtends first third := by
  intro key value h
  exact right key value (left key value h)

theorem memo_extends_empty (table : Memo K α) : MemoExtends (fun _ => none) table := by
  intro key value h
  cases h

theorem memo_query_extends [DecidableEq K] (p : PMF α) (table : Memo K α)
    (key : K) (out : α × Memo K α) (ho : out ∈ (memoQuery p table key).support) :
    MemoExtends table out.2 := by
  intro other value h
  exact memoQuery_preserves p table key other value h out ho

theorem eval_program_extends [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (out : R × Memo K α)
    (ho : out ∈ (evalProgram p program table).support) : MemoExtends table out.2 := by
  intro key value h
  exact evalProgram_preserves p program table key value h out ho

def replayProgram (table : Memo K α) : {n : ℕ} → QueryProgram K α R n → Option R
  | _, .done value => some value
  | _, .query key next => (table key).bind (fun reply => replayProgram table (next reply))

theorem replay_program_done (table : Memo K α) (n : ℕ) (value : R) :
    replayProgram table (.done (n := n) value) = some value := rfl

theorem replay_program_missing (table : Memo K α) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (missing : table key = none) :
    replayProgram table (.query key next) = none := by
  simp only [replayProgram, missing, Option.bind_none]

theorem replay_program_cached (table : Memo K α) {n : ℕ} (key : K)
    (next : α → QueryProgram K α R n) (reply : α) (cached : table key = some reply) :
    replayProgram table (.query key next) = replayProgram table (next reply) := by
  simp only [replayProgram, cached, Option.bind_some]

theorem replay_program_extends {n : ℕ} (program : QueryProgram K α R n)
    (before after : Memo K α) (value : R) (extension : MemoExtends before after)
    (recorded : replayProgram before program = some value) :
    replayProgram after program = some value := by
  induction program with
  | done result => exact recorded
  | query key next ih =>
    cases h : before key with
    | none =>
      simp only [replayProgram, h, Option.bind_none] at recorded
      cases recorded
    | some reply =>
      rw [replay_program_cached before key next reply h] at recorded
      rw [replay_program_cached after key next reply (extension key reply h)]
      exact ih reply recorded

theorem replay_program_unique {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) (first second : R)
    (hf : replayProgram table program = some first)
    (hs : replayProgram table program = some second) : first = second := by
  exact Option.some.inj (hf.symm.trans hs)

theorem eval_program_replay [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (out : R × Memo K α)
    (ho : out ∈ (evalProgram p program table).support) :
    replayProgram out.2 program = some out.1 := by
  induction program generalizing table out with
  | done value =>
    have he : out = (value, table) := by simpa only [evalProgram, PMF.mem_support_pure_iff] using ho
    simp only [he, replayProgram]
  | query key next ih =>
    rw [evalProgram, PMF.mem_support_bind_iff] at ho
    obtain ⟨reply, hr, ho⟩ := ho
    have stored := evalProgram_preserves p (next reply.1) reply.2 key reply.1
      (memoQuery_stores p table key reply hr) out ho
    rw [replay_program_cached out.2 key next reply.1 stored]
    exact ih reply.1 reply.2 out ho

theorem eval_program_replay_later [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (out : R × Memo K α)
    (ho : out ∈ (evalProgram p program table).support) (later : Memo K α)
    (extension : MemoExtends out.2 later) : replayProgram later program = some out.1 := by
  exact replay_program_extends program out.2 later out.1 extension
    (eval_program_replay p program table out ho)

theorem replay_program_eval [DecidableEq K] (p : PMF α) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) (value : R)
    (recorded : replayProgram table program = some value) :
    evalProgram p program table = PMF.pure (value, table) := by
  induction program with
  | done result =>
    have he : result = value := Option.some.inj recorded
    simp only [evalProgram, he]
  | query key next ih =>
    cases h : table key with
    | none =>
      simp only [replayProgram, h, Option.bind_none] at recorded
      cases recorded
    | some reply =>
      rw [replay_program_cached table key next reply h] at recorded
      rw [evalProgram_cached p key next table reply h]
      exact ih reply recorded

theorem replay_program_cast {n m : ℕ} (h : n = m) (program : QueryProgram K α R n)
    (table : Memo K α) : replayProgram table (castProgram h program) = replayProgram table program := by
  subst m
  rfl

theorem replay_program_reserve (extra : ℕ) {n : ℕ} (program : QueryProgram K α R n)
    (table : Memo K α) : replayProgram table (reserveProgram extra program) = replayProgram table program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [reserveProgram, replayProgram, ih]

theorem replay_program_bind {n m : ℕ} (program : QueryProgram K α R n)
    (after : R → QueryProgram K α T m) (table : Memo K α) :
    replayProgram table (bindProgram program after) =
      (replayProgram table program).bind (fun value => replayProgram table (after value)) := by
  induction program with
  | done value => simp only [bindProgram, replay_program_cast, replay_program_reserve,
      replayProgram, Option.bind_some]
  | query key next ih =>
    simp only [bindProgram, replayProgram, ih, Option.bind_assoc]

theorem replay_program_map_return (f : R → T) {n : ℕ}
    (program : QueryProgram K α R n) (table : Memo K α) :
    replayProgram table (mapReturnProgram f program) = (replayProgram table program).map f := by
  induction program with
  | done value => rfl
  | query key next ih =>
    cases h : table key <;> simp only [mapReturnProgram, replayProgram, h,
      Option.bind_none, Option.bind_some, Option.map_none, ih]

end
end C10Probability
