import C10Probability.ForestRecords

/-! The verifier's ordered forest recovery reproduces the signing forest's
actual public key, including its last transmitted root, separate last-leaf
hash and thirteen-position compression. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_forest_recovery_assemble (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (roots : Fin 12 → Randomizer)
    (indices : List (Fin 12)) (initial : List Randomizer)
    (recorded : ∀ i ∈ indices, replayProgram table (forsRecoverProgram encode seed ht i.val
      (forestIndex digest i.val) ((secrets[i.val]?).getD 0) ((auths[i.val]?).getD [])) = some (roots i)) :
    replayProgram table (forestRecoveryProgram encode seed ht digest secrets auths indices initial) =
      some (initial ++ indices.map roots) := by
  induction indices generalizing initial with
  | nil => simp only [forestRecoveryProgram, stateFoldProgram, replayProgram, List.map_nil, List.append_nil]
  | cons i rest ih =>
    have head := recorded i (List.mem_cons_self ..)
    have tail := ih (initial ++ [roots i])
      (fun j member => recorded j (List.mem_cons_of_mem i member))
    simp only [forestRecoveryProgram, stateFoldProgram, replay_program_cast,
      replay_program_bind, forestRecoveryStep, replay_program_map_return, head,
      Option.map_some, Option.bind_some] at tail ⊢
    rw [tail]
    simp only [List.map_cons, List.append_assoc, List.cons_append, List.nil_append]

theorem forest_roots_complete (roots : List Randomizer) (last : Randomizer)
    (length : roots.length = 13) :
    (forestTreeIndices.map (fun i => (roots[i.val]?).getD 0)) ++ [last] = roots.set 12 last := by
  apply List.ext_getElem
  · simp only [List.length_append, List.length_map, forest_tree_indices_length,
      List.length_cons, List.length_nil, List.length_set, length]
  · intro i leftBound rightBound
    have bound : i < 13 := by simpa only [List.length_set, length] using rightBound
    by_cases ordinary : i < 12
    · rw [List.getElem_append_left (by simpa only [List.length_map,
        forest_tree_indices_length] using ordinary)]
      simp only [List.getElem_map, forestTreeIndices, List.getElem_ofFn, id_eq,
        List.getElem?_eq_getElem (by omega : i < roots.length), Option.getD_some,
        List.getElem_set_ne (by omega : 12 ≠ i)]
    · have equal : i = 12 := by omega
      subst i
      rw [List.getElem_append_right (by simp [forest_tree_indices_length])]
      simp only [List.length_map, forest_tree_indices_length, Nat.sub_self,
        List.getElem_cons_zero, List.getElem_set_self]

theorem replay_forest_sign_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey) (out : ForestOutput)
    (recorded : replayProgram table (forestSignProgram encode seed ht digest shuffle) = some out) :
    replayProgram table (forestRecoverProgram (fun key => encode (.inl key))
      seed ht digest out.secrets out.auths) = some out.pk := by
  rw [forestSignProgram] at recorded
  obtain ⟨order, _, rest⟩ := replay_program_bind_witness table _ _ _ recorded
  obtain ⟨state, ordered, finish⟩ := replay_program_bind_witness table _ _ _ rest
  obtain ⟨shape, slots⟩ := replay_forest_ordered_records encode table seed ht digest order state ordered
  rw [forestFinishProgram] at finish
  obtain ⟨last, _, finish⟩ := replay_program_bind_witness table _ _ _ finish
  cases leaf : table (encode (.inl (forsLeafInput seed ht 12 0 last))) with
  | none => simp only [forestLastProgram, replayProgram, leaf, Option.bind_none] at finish; cases finish
  | some leafReply =>
    simp only [forestLastProgram, replayProgram, leaf, Option.bind_some] at finish
    cases compression : table (encode (.inl
        (forsPkInput seed ht (state.roots.set 12 (randomizerOfDigest leafReply))))) with
    | none => simp only [compression, Option.bind_none] at finish; cases finish
    | some reply =>
      simp only [compression, Option.bind_some, Option.some.injEq] at finish
      subst out
      have each : ∀ i : Fin 12, replayProgram table
          (forsRecoverProgram (fun key => encode (.inl key)) seed ht i.val
            (forestIndex digest i.val) (((state.secrets.set 12 last)[i.val]?).getD 0)
            ((state.auths[i.val]?).getD [])) = some ((state.roots[i.val]?).getD 0) := by
        intro i
        have different : 12 ≠ i.val := Nat.ne_of_gt i.isLt
        simpa only [List.getElem?_set_ne different] using
          recorded_forest_slot_recovery encode table seed ht digest state i (slots i)
      have recovered := replay_forest_recovery_assemble (fun key => encode (.inl key)) table
        seed ht digest (state.secrets.set 12 last) state.auths
        (fun i => (state.roots[i.val]?).getD 0) forestTreeIndices [] (fun i _ => each i)
      simp only [List.nil_append] at recovered
      rw [forestRecoverProgram, replay_program_bind, replay_program_cast, recovered, Option.bind_some]
      have lastStored : (state.secrets.set 12 last)[12]? = some last :=
        List.getElem?_set_self (by rw [shape.1]; decide)
      simp only [lastStored, Option.getD_some]
      rw [replay_program_cached table _ _ leafReply leaf,
        forest_roots_complete state.roots (randomizerOfDigest leafReply) shape.2.2.1,
        replay_program_cached table _ _ reply compression]
      rfl

theorem forest_sign_recovery_support [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (out : ForestOutput × Memo K Digest)
    (supported : out ∈ (forestSign encode table seed ht digest shuffle).support) :
    forestRecover (fun key => encode (.inl key)) out.2 seed ht digest out.1.secrets out.1.auths =
      PMF.pure (out.1.pk, out.2) := by
  rw [← forest_recover_eval]
  exact replay_program_eval digestDraw _ out.2 out.1.pk
    (replay_forest_sign_recovery encode out.2 seed ht digest shuffle out.1
      (eval_program_replay digestDraw _ table out (by rwa [forest_sign_eval])))

end
end C10Probability
