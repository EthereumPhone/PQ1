import C10Probability.ForsSplit
import C10Probability.QueryReplay

/-! Passive observation of fresh accepted replies at a selected input domain.
Cache hits reuse their stored reply and do not append another pool position. -/
namespace C10Probability
noncomputable section

structure HmsgPoolOutput (K R : Type*) where
  value : R
  cache : Memo K Digest
  entries : List (K × Digest)

def hmsgPoolPrepend {K R : Type*} (select : K → Bool) (key : K) (value : Digest)
    (out : HmsgPoolOutput K R) : HmsgPoolOutput K R :=
  if select key && forsAccept (forsOfDigest value) then
    { out with entries := (key, value) :: out.entries }
  else out

def hmsgPoolProgram {K R : Type*} [DecidableEq K] (select : K → Bool) :
    {n : ℕ} → QueryProgram K Digest R n → Memo K Digest → PMF (HmsgPoolOutput K R)
  | _, .done value, table => PMF.pure ⟨value, table, []⟩
  | _, .query key next, table =>
      match table key with
      | some value => hmsgPoolProgram select (next value) table
      | none => digestDraw.bind (fun value =>
          (hmsgPoolProgram select (next value)
            (Function.update table key (some value))).map (hmsgPoolPrepend select key value))

theorem hmsg_pool_prepend_erases {K R : Type*} (select : K → Bool) (key : K)
    (value : Digest) (out : HmsgPoolOutput K R) :
    ((hmsgPoolPrepend select key value out).value,
      (hmsgPoolPrepend select key value out).cache) = (out.value, out.cache) := by
  unfold hmsgPoolPrepend
  split <;> rfl

theorem hmsg_pool_prepend_selected {K R : Type*} (select : K → Bool) (key : K)
    (value : Digest) (out : HmsgPoolOutput K R)
    (selected : select key = true) (accepted : forsAccept (forsOfDigest value) = true) :
    (hmsgPoolPrepend select key value out).entries = (key, value) :: out.entries := by
  simp [hmsgPoolPrepend, selected, accepted]

theorem hmsg_pool_prepend_other {K R : Type*} (select : K → Bool) (key : K)
    (value : Digest) (out : HmsgPoolOutput K R)
    (other : select key = false ∨ forsAccept (forsOfDigest value) = false) :
    hmsgPoolPrepend select key value out = out := by
  rcases other with unselected | rejected <;> simp [hmsgPoolPrepend, *]

theorem hmsg_pool_program_cached {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (key : K) (next : Digest → QueryProgram K Digest R n)
    (table : Memo K Digest) (value : Digest) (cached : table key = some value) :
    hmsgPoolProgram select (.query key next) table = hmsgPoolProgram select (next value) table := by
  simp [hmsgPoolProgram, cached]

theorem hmsg_pool_program_fresh {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (key : K) (next : Digest → QueryProgram K Digest R n)
    (table : Memo K Digest) (fresh : table key = none) :
    hmsgPoolProgram select (.query key next) table =
      digestDraw.bind (fun value =>
        (hmsgPoolProgram select (next value)
          (Function.update table key (some value))).map (hmsgPoolPrepend select key value)) := by
  simp [hmsgPoolProgram, fresh]

theorem hmsg_pool_program_erases {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (table : Memo K Digest) :
    (hmsgPoolProgram select program table).map (fun out => (out.value, out.cache)) =
      evalProgram digestDraw program table := by
  induction program generalizing table with
  | done value => simp [hmsgPoolProgram, evalProgram, PMF.pure_map]
  | query key next ih =>
    cases cached : table key with
    | some value =>
      rw [hmsg_pool_program_cached select key next table value cached,
        evalProgram_cached digestDraw key next table value cached, ih]
    | none =>
      rw [hmsg_pool_program_fresh select key next table cached,
        evalProgram_fresh digestDraw key next table cached, PMF.map_bind]
      congr 1
      funext value
      simpa only [PMF.map_comp, Function.comp_def, hmsg_pool_prepend_erases] using
        ih value (Function.update table key (some value))

theorem hmsg_pool_program_support {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (table : Memo K Digest)
    (out : HmsgPoolOutput K R) (supported : out ∈ (hmsgPoolProgram select program table).support) :
    (out.value, out.cache) ∈ (evalProgram digestDraw program table).support := by
  rw [← hmsg_pool_program_erases select program table, PMF.mem_support_map_iff]
  exact ⟨out, supported, rfl⟩

theorem hmsg_pool_program_extends {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (table : Memo K Digest)
    (out : HmsgPoolOutput K R) (supported : out ∈ (hmsgPoolProgram select program table).support) :
    MemoExtends table out.cache := by
  exact eval_program_extends digestDraw program table (out.value, out.cache)
    (hmsg_pool_program_support select program table out supported)

end
end C10Probability
