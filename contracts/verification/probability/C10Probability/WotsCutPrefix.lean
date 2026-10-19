import C10Probability.WotsCutInputs
import C10Probability.OpeningSealed
import C10Probability.AdaptivePresample

/-! The predecessor prefix is an actual seed-chain program, including its
private query and earlier public calls. Its selected next input is absent when
this prefix starts from the empty cache. This is a precomputation fact, not a
freshness assumption about the later actual signing/adversary execution. -/
namespace C10Probability
noncomputable section

def wotsBeforeCutProgram (seed : ByteKey) (target : WotsTarget) :
    (cut : ℕ) → QueryProgram WotsQuery Digest Randomizer cut
  | 0 => .done 0
  | steps + 1 => wotsSeedChainProgram id seed (wotsTargetLayer target) (wotsTargetTree target)
      (wotsTargetKp target) target.2.val steps

theorem eval_program_sealed_lookup {K α R : Type*} [DecidableEq K]
    (p : PMF α) (target : K) {n : ℕ} (program : QueryProgram K α R n)
    (sealed : OpeningSealed target (liftOpening (P := Unit) (H := α) program))
    (table : Memo K α) (out : R × Memo K α)
    (supported : out ∈ (evalProgram p program table).support) : out.2 target = table target := by
  induction program generalizing table out with
  | done value =>
    have equal : out = (value, table) := by simpa only [evalProgram, PMF.mem_support_pure_iff] using supported
    simp only [equal]
  | query key next ih =>
    rw [evalProgram, PMF.mem_support_bind_iff] at supported
    obtain ⟨reply, hr, later⟩ := supported
    rw [ih reply.1 (sealed.2 reply.1) reply.2 out later]
    exact memoQuery_other p table key target (Ne.symm sealed.1) reply hr

theorem wots_chain_avoids_future (seed : ByteKey) (layer tree kp index start steps position : ℕ)
    (current future : Randomizer) (later : start + steps ≤ position) (bound : position < 2 ^ 32) :
    OpeningSealed (.inl (wotsChainInput seed layer tree kp index position future))
      (liftOpening (P := Unit) (H := Digest)
        (chainProgram (fun pos node => (.inl (wotsChainInput seed layer tree kp index pos node) : WotsQuery))
          randomizerOfDigest start steps current)) := by
  induction steps generalizing start current with
  | zero => trivial
  | succ steps ih =>
    refine ⟨?_, fun reply => ih (start + 1) (randomizerOfDigest reply) (by omega)⟩
    intro equal
    have positions := wots_chain_input_position_eq seed _ _ _ _ _ _ _ _ _ _ current future
      (by omega) bound (Sum.inl.inj equal)
    omega

theorem wots_before_cut_avoids (seed : ByteKey) (target : WotsCutTarget) (previous : Randomizer) :
    OpeningSealed (wotsCutIncoming seed target previous)
      (liftOpening (P := Unit) (H := Digest) (wotsBeforeCutProgram seed target.1 target.2.val)) := by
  cases cut : target.2.val with
  | zero => simp only [wotsBeforeCutProgram, liftOpening, OpeningSealed]
  | succ steps =>
    simp only [wotsCutIncoming, cut, Nat.succ_ne_zero, ↓reduceIte, Nat.add_sub_cancel,
      wotsBeforeCutProgram, wotsSeedChainProgram, liftOpening, OpeningSealed, id_eq]
    refine ⟨by simp, fun reply => ?_⟩
    exact wots_chain_avoids_future seed _ _ _ _ 0 steps steps (randomizerOfDigest reply)
      previous (by omega) (by have := target.2.isLt; omega)

theorem wots_before_cut_fresh (seed : ByteKey) (target : WotsCutTarget)
    (out : Randomizer × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw
      (wotsBeforeCutProgram seed target.1 target.2.val) (fun _ => none)).support) :
    out.2 (wotsCutIncoming seed target out.1) = none := by
  exact eval_program_sealed_lookup digestDraw _ _ (wots_before_cut_avoids seed target out.1)
    (fun _ => none) out supported

theorem wots_seed_chain_snoc (seed : ByteKey) (layer tree kp index steps : ℕ)
    (table : Memo WotsQuery Digest) :
    wotsSeedChain id table seed layer tree kp index (steps + 1) =
      (wotsSeedChain id table seed layer tree kp index steps).bind fun before =>
        (memoQuery digestDraw before.2 (.inl (wotsChainInput seed layer tree kp index steps before.1))).map
          (fun reply => (randomizerOfDigest reply.1, reply.2)) := by
  rw [wotsSeedChain, wotsSeedChain, PMF.bind_bind]
  congr 1
  funext reply
  rw [chainLoop_split digestDraw _ randomizerOfDigest 0 steps 1]
  simp only [Nat.zero_add, chainLoop, PMF.map, Function.comp_def, id_eq]

theorem wots_before_cut_snoc (seed : ByteKey) (target : WotsCutTarget)
    (table : Memo WotsQuery Digest) :
    wotsSeedChain id table seed (wotsTargetLayer target.1) (wotsTargetTree target.1)
      (wotsTargetKp target.1) target.1.2.val target.2.val =
        (evalProgram digestDraw (wotsBeforeCutProgram seed target.1 target.2.val) table).bind
          fun before => (memoQuery digestDraw before.2 (wotsCutIncoming seed target before.1)).map
            (fun reply => (randomizerOfDigest reply.1, reply.2)) := by
  cases cut : target.2.val with
  | zero =>
    simp only [cut, wotsBeforeCutProgram, evalProgram, PMF.pure_bind, wotsCutIncoming,
      ↓reduceIte, wotsSeedChain, chainLoop, wotsTargetKey, PMF.map, Function.comp_def, id_eq]
  | succ steps =>
    simp only [cut, wotsBeforeCutProgram, wots_seed_chain_eval, wotsCutIncoming,
      Nat.succ_ne_zero, ↓reduceIte, Nat.add_sub_cancel]
    exact wots_seed_chain_snoc seed _ _ _ _ steps table

end
end C10Probability
