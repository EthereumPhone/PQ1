import C10Probability.HmsgPool

/-! Fresh pool entries are unique input keys and remain in the final cache.
Completeness excludes entries already present before this execution. -/
namespace C10Probability
noncomputable section

def HmsgPoolValid {K R : Type*} (select : K → Bool) (initial : Memo K Digest)
    (out : HmsgPoolOutput K R) : Prop :=
  (∀ entry ∈ out.entries, select entry.1 = true ∧
    forsAccept (forsOfDigest entry.2) = true ∧ initial entry.1 = none ∧
    out.cache entry.1 = some entry.2) ∧ (out.entries.map Prod.fst).Nodup

theorem hmsg_pool_prepend_cache {K R : Type*} (select : K → Bool) (key : K)
    (value : Digest) (out : HmsgPoolOutput K R) :
    (hmsgPoolPrepend select key value out).cache = out.cache := by
  exact congrArg Prod.snd (hmsg_pool_prepend_erases select key value out)

theorem hmsg_pool_prepend_mem {K R : Type*} (select : K → Bool) (key : K)
    (value : Digest) (out : HmsgPoolOutput K R) (entry : K × Digest)
    (member : entry ∈ out.entries) :
    entry ∈ (hmsgPoolPrepend select key value out).entries := by
  unfold hmsgPoolPrepend
  split
  · exact List.mem_cons_of_mem _ member
  · exact member

theorem hmsg_pool_program_valid {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (table : Memo K Digest)
    (out : HmsgPoolOutput K R) (supported : out ∈ (hmsgPoolProgram select program table).support) :
    HmsgPoolValid select table out := by
  induction program generalizing table out with
  | done value =>
    have same : out = ⟨value, table, []⟩ := by simpa [hmsgPoolProgram] using supported
    simp [HmsgPoolValid, same]
  | query key next ih =>
    cases cached : table key with
    | some value =>
      rw [hmsg_pool_program_cached select key next table value cached] at supported
      exact ih value table out supported
    | none =>
      rw [hmsg_pool_program_fresh select key next table cached, PMF.mem_support_bind_iff] at supported
      obtain ⟨value, _, supported⟩ := supported
      rw [PMF.mem_support_map_iff] at supported
      obtain ⟨rest, hr, rfl⟩ := supported
      obtain ⟨valid, unique⟩ := ih value (Function.update table key (some value)) rest hr
      have inherited : ∀ entry ∈ rest.entries, select entry.1 = true ∧
          forsAccept (forsOfDigest entry.2) = true ∧ table entry.1 = none ∧
          rest.cache entry.1 = some entry.2 := by
        intro entry member
        obtain ⟨hs, ha, absent, stored⟩ := valid entry member
        have different : entry.1 ≠ key := by
          intro same
          rw [same, Function.update_self] at absent
          cases absent
        exact ⟨hs, ha, by simpa [Function.update_of_ne different] using absent, stored⟩
      have absentKey : key ∉ rest.entries.map Prod.fst := by
        intro member
        obtain ⟨entry, hm, same⟩ := List.mem_map.mp member
        have absent := (valid entry hm).2.2.1
        rw [same, Function.update_self] at absent
        cases absent
      by_cases selected : (select key && forsAccept (forsOfDigest value)) = true
      · have both : select key = true ∧ forsAccept (forsOfDigest value) = true := by
          simpa using selected
        have stored := hmsg_pool_program_extends select (next value)
          (Function.update table key (some value)) rest hr key value
          (by simp)
        simp only [HmsgPoolValid, hmsgPoolPrepend, if_pos selected]
        constructor
        · intro entry member
          rcases List.mem_cons.mp member with same | prior
          · subst entry
            exact ⟨both.1, both.2, cached, stored⟩
          · exact inherited entry prior
        · exact List.nodup_cons.mpr ⟨absentKey, unique⟩
      · simpa only [HmsgPoolValid, hmsgPoolPrepend, if_neg selected] using
          And.intro inherited unique

theorem hmsg_pool_program_complete {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (table : Memo K Digest)
    (out : HmsgPoolOutput K R) (supported : out ∈ (hmsgPoolProgram select program table).support)
    (key : K) (value : Digest) (fresh : table key = none) (selected : select key = true)
    (accepted : forsAccept (forsOfDigest value) = true) (stored : out.cache key = some value) :
    (key, value) ∈ out.entries := by
  induction program generalizing table out with
  | done result =>
    have same : out = ⟨result, table, []⟩ := by simpa [hmsgPoolProgram] using supported
    rw [same] at stored
    simp only at stored
    rw [fresh] at stored
    cases stored
  | query first next ih =>
    cases cached : table first with
    | some reply =>
      rw [hmsg_pool_program_cached select first next table reply cached] at supported
      exact ih reply table out supported fresh stored
    | none =>
      rw [hmsg_pool_program_fresh select first next table cached, PMF.mem_support_bind_iff] at supported
      obtain ⟨reply, _, supported⟩ := supported
      rw [PMF.mem_support_map_iff] at supported
      obtain ⟨rest, hr, rfl⟩ := supported
      rw [hmsg_pool_prepend_cache] at stored
      by_cases same : key = first
      · subst first
        have prior := hmsg_pool_program_extends select (next reply)
          (Function.update table key (some reply)) rest hr key reply
          (by simp)
        have equal : reply = value := Option.some.inj (prior.symm.trans stored)
        subst reply
        rw [hmsg_pool_prepend_selected select key value rest selected accepted]
        exact List.mem_cons_self
      · have stillFresh : Function.update table first (some reply) key = none := by
          simpa [Function.update_of_ne same] using fresh
        exact hmsg_pool_prepend_mem select first reply rest (key, value)
          (ih reply (Function.update table first (some reply)) rest hr stillFresh stored)

theorem hmsg_pool_empty_complete {K R : Type*} [DecidableEq K] (select : K → Bool)
    {n : ℕ} (program : QueryProgram K Digest R n) (out : HmsgPoolOutput K R)
    (supported : out ∈ (hmsgPoolProgram select program (fun _ => none)).support)
    (key : K) (value : Digest) (selected : select key = true)
    (accepted : forsAccept (forsOfDigest value) = true) (stored : out.cache key = some value) :
    (key, value) ∈ out.entries := by
  exact hmsg_pool_program_complete select program (fun _ => none) out supported key value
    rfl selected accepted stored

end
end C10Probability
