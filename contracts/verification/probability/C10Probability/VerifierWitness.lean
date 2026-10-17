import C10Probability.QueryReplay
import C10Probability.C10Verify

/-! A successful replay exposes the actual H_msg reply, forest output and
ordered hypertree reconstruction in one cache. No collision-freedom or
honest-signature correctness premise is hidden in these witnesses. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def VerificationWitness (encode : ByteKey → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) : Prop :=
  ∃ digest forest top,
    table (encode (hmsgRandomizerInput seed root message sig.randomizer)) = some digest ∧
    forsAccept (forsOfDigest digest) = true ∧
    replayProgram table (forestRecoverProgram encode seed (hypertreeIndex digest)
      digest sig.secrets sig.auths) = some forest ∧
    replayProgram table (hypertreeRecoverProgram encode seed sig.layers 2 0
      (hypertreeIndex digest) forest) = some top ∧ nodeBlock top = root

theorem verifier_replay_witness (encode : ByteKey → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature)
    (accepted : replayProgram table (c10VerifyProgram encode seed root message sig) = some true) :
    VerificationWitness encode table seed root message sig := by
  unfold c10VerifyProgram at accepted
  cases hd : table (encode (hmsgRandomizerInput seed root message sig.randomizer)) with
  | none =>
    simp only [replayProgram, hd, Option.bind_none] at accepted
    cases accepted
  | some digest =>
    rw [replay_program_cached table _ _ digest hd] at accepted
    cases ha : forsAccept (forsOfDigest digest)
    · simp only [c10VerifyAfterProgram, ha, Bool.false_eq_true, ↓reduceIte, replayProgram] at accepted
      cases accepted
    · simp only [c10VerifyAfterProgram, ha, ↓reduceIte, replay_program_bind,
        replay_program_map_return] at accepted
      cases hf : replayProgram table (forestRecoverProgram encode seed (hypertreeIndex digest)
          digest sig.secrets sig.auths) with
      | none =>
        simp only [hf, Option.bind_none] at accepted
        cases accepted
      | some forest =>
        simp only [hf, Option.bind_some] at accepted
        cases ht : replayProgram table (hypertreeRecoverProgram encode seed sig.layers 2 0
            (hypertreeIndex digest) forest) with
        | none =>
          simp only [ht, Option.map_none] at accepted
          cases accepted
        | some top =>
          simp only [ht, Option.map_some, Option.some.injEq, decide_eq_true_eq] at accepted
          exact ⟨digest, forest, top, hd, ha, hf, ht, accepted⟩

theorem verifier_witness_replay (encode : ByteKey → K) (table : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature)
    (witness : VerificationWitness encode table seed root message sig) :
    replayProgram table (c10VerifyProgram encode seed root message sig) = some true := by
  obtain ⟨digest, forest, top, hd, ha, hf, ht, he⟩ := witness
  simp only [c10VerifyProgram, replayProgram, hd, Option.bind_some,
    c10VerifyAfterProgram, ha, ↓reduceIte, replay_program_bind,
    replay_program_map_return, hf, ht, Option.map_some, he, decide_true]

theorem verification_witness_extends (encode : ByteKey → K) (before after : Memo K Digest)
    (seed root message : ByteKey) (sig : C10Signature) (extension : MemoExtends before after)
    (witness : VerificationWitness encode before seed root message sig) :
    VerificationWitness encode after seed root message sig := by
  exact verifier_replay_witness encode after seed root message sig
    (replay_program_extends _ before after true extension
      (verifier_witness_replay encode before seed root message sig witness))

theorem c10_verify_true_witness [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed root message : ByteKey) (sig : C10Signature)
    (out : Bool × Memo K Digest) (ho : out ∈ (c10Verify encode table seed root message sig).support)
    (win : out.1 = true) : VerificationWitness encode out.2 seed root message sig := by
  have hp : out ∈ (evalProgram digestDraw (c10VerifyProgram encode seed root message sig) table).support := by
    rw [c10_verify_eval]
    exact ho
  apply verifier_replay_witness
  simpa only [win] using eval_program_replay digestDraw _ table out hp

end
end C10Probability
