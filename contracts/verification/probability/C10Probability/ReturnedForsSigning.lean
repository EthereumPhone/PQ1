import C10Probability.ReturnedAuthRecovery

/-! The FORS signature's actual private value and actual returned path recover
the root produced by that same signing execution's tree builder. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

theorem replay_fors_sign_returned_recovery (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht tree target : ℕ) (signature : Randomizer × List Randomizer)
    (recorded : replayProgram table (forsSignProgram encode seed ht tree target) = some signature)
    (bound : target < 2048) :
    signature.2.length = 11 ∧ ∃ root,
      replayProgram table (forsTreeProgram encode seed ht tree target) = some (root, signature.2) ∧
      replayProgram table (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target signature.1 signature.2) = some root := by
  unfold forsSignProgram at recorded
  cases hs : table (encode (.inr (forsPrivateTail ht tree target))) with
  | none => simp only [replayProgram, hs, Option.bind_none] at recorded; cases recorded
  | some secret =>
    rw [replay_program_cached table _ _ secret hs, replay_program_map_return] at recorded
    cases ht' : replayProgram table (forsTreeProgram encode seed ht tree target) with
    | none => simp only [ht', Option.map_none] at recorded; cases recorded
    | some out =>
      simp only [ht', Option.map_some, Option.some.injEq] at recorded
      subst signature
      obtain ⟨length, secret', digest, hs', _, recover⟩ :=
        replay_fors_tree_recovery encode table seed ht tree target out ht' bound
      have equal : secret = secret' := Option.some.inj (hs.symm.trans hs')
      subst secret'
      exact ⟨length, out.1, rfl, recover⟩

theorem fors_sign_returned_recovery [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (ht tree target : ℕ)
    (out : (Randomizer × List Randomizer) × Memo K Digest)
    (supported : out ∈ (forsSign encode table seed ht tree target).support)
    (bound : target < 2048) :
    out.1.2.length = 11 ∧ ∃ root,
      replayProgram out.2 (forsTreeProgram encode seed ht tree target) = some (root, out.1.2) ∧
      replayProgram out.2 (forsRecoverProgram (fun key => encode (.inl key))
        seed ht tree target out.1.1 out.1.2) = some root := by
  exact replay_fors_sign_returned_recovery encode out.2 seed ht tree target out.1
    (eval_program_replay digestDraw _ table out (by rwa [fors_sign_eval])) bound

end
end C10Probability
