import C10Probability.WotsCutPrefix
import C10Probability.StagedOpeningComparison

/-! The staged opening setup is exactly the existing WOTS seed-chain
execution at the selected cut. Equality retains the full memo table and hence
also identifies cache-only replay, including failure on a missing entry. -/
namespace C10Probability
noncomputable section

theorem replay_program_of_eval_eq {K α R : Type*} [DecidableEq K] (p : PMF α) {n m : ℕ}
    (first : QueryProgram K α R n) (second : QueryProgram K α R m) (table : Memo K α)
    (equal : evalProgram p first table = evalProgram p second table) (value : R)
    (recorded : replayProgram table first = some value) :
    replayProgram table second = some value := by
  have pure : evalProgram p second table = PMF.pure (value, table) :=
    equal.symm.trans (replay_program_eval p first table value recorded)
  have supported : (value, table) ∈ (evalProgram p second table).support := by
    rw [pure]
    simp only [PMF.mem_support_pure_iff]
  exact eval_program_replay p second table (value, table) supported

theorem replay_program_eq_of_eval_eq {K α R : Type*} [DecidableEq K] (p : PMF α) {n m : ℕ}
    (first : QueryProgram K α R n) (second : QueryProgram K α R m) (table : Memo K α)
    (equal : evalProgram p first table = evalProgram p second table) :
    replayProgram table first = replayProgram table second := by
  cases left : replayProgram table first with
  | some value => exact (replay_program_of_eval_eq p first second table equal value left).symm
  | none =>
    cases right : replayProgram table second with
    | none => rfl
    | some value =>
      have impossible := replay_program_of_eval_eq p second first table equal.symm value right
      rw [left] at impossible
      cases impossible

def wotsCutSetup (seed : ByteKey) (target : WotsCutTarget) :
    QueryProgram WotsQuery Digest Randomizer (1 + target.2.val) :=
  openingTargetSetup (wotsBeforeCutProgram seed target.1 target.2.val)
    (wotsCutIncoming seed target) randomizerOfDigest

theorem wots_cut_setup_eval (seed : ByteKey) (target : WotsCutTarget)
    (table : Memo WotsQuery Digest) :
    evalProgram digestDraw (wotsCutSetup seed target) table =
      wotsSeedChain id table seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
        (wotsTargetKp target.1) target.1.2.val target.2.val := by
  rw [wotsCutSetup, opening_target_setup_eval]
  exact (wots_before_cut_snoc seed target table).symm

theorem wots_cut_setup_replay (seed : ByteKey) (target : WotsCutTarget)
    (table : Memo WotsQuery Digest) :
    replayProgram table (wotsCutSetup seed target) =
      replayProgram table (wotsSeedChainProgram id seed (wotsTargetLayer target.1)
        (wotsTargetTree target.1) (wotsTargetKp target.1) target.1.2.val target.2.val) := by
  apply replay_program_eq_of_eval_eq digestDraw
  rw [wots_cut_setup_eval, wots_seed_chain_eval]

theorem wots_cut_setup_event {R : Type*} (seed : ByteKey) (target : WotsCutTarget)
    (candidates : R → Finset Randomizer) (excluded : R → Memo WotsQuery Digest → Prop) :
    replayedOpeningEvent (wotsCutSetup seed target) candidates excluded =
      replayedOpeningEvent (wotsSeedChainProgram id seed (wotsTargetLayer target.1)
        (wotsTargetTree target.1) (wotsTargetKp target.1) target.1.2.val target.2.val)
          candidates excluded := by
  ext out
  simp only [replayedOpeningEvent, wots_cut_setup_replay]

end
end C10Probability
