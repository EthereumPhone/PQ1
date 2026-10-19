import C10Probability.WotsProbeEvents

/-! The concrete C10 game discharges every staged-opening obligation.
The excluded public incoming read is retained as a separately charged event;
it is not treated as a legitimate signing release. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem memo_extends_fresh_update {K α : Type*} [DecidableEq K] (table : Memo K α)
    (target : K) (value : α) (fresh : table target = none) :
    MemoExtends table (Function.update table target (some value)) := by
  intro key reply cached
  by_cases equal : key = target
  · subst key
    rw [fresh] at cached
    cases cached
  · simpa only [Function.update_of_ne equal] using cached

def wotsCutCharge (qr qs : ℕ) : ℝ≥0∞ :=
  ((155867 + 2 * qr + qs * 364076 : ℕ) : ℝ≥0∞) / 2 ^ 128

theorem wots_probed_staged_disclosure (target : WotsCutTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (before : Randomizer × Memo WotsQuery Digest)
    (beforeSupport : before ∈ (evalProgram digestDraw
      (wotsBeforeCutProgram (wotsGameSeed publicSeed) target.1 target.2.val) (fun _ => none)).support)
    (secret : Digest) (out : OpeningOutput WotsQuery Digest C10ProbedGame)
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target)
      randomizerOfDigest secret (wotsProbedGameOpening target before.1 cfg publicSeed adversary qr qs)
      (Function.update before.2 (wotsCutIncoming (wotsGameSeed publicSeed) target before.1)
        (some secret)) false).support) (opened : out.opened = true) :
    wotsProbedExcluded (wotsGameSeed publicSeed) target cfg out.value out.cache := by
  let initial := Function.update before.2 (wotsCutIncoming (wotsGameSeed publicSeed) target before.1)
    (some secret)
  have cached : initial (wotsCutIncoming (wotsGameSeed publicSeed) target before.1) = some secret := by
    simp only [initial, Function.update_self]
  rcases wots_probed_game_opened target before.1 secret cfg publicSeed adversary qr qs initial cached
    out supported opened with returned | queried
  · exact Or.inl returned
  · by_cases zero : target.2.val = 0
    · have ordinarySupport : (out.value, out.cache) ∈
          (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) initial).support := by
        rw [← wots_probed_game_refines target before.1 secret cfg publicSeed adversary qr qs initial false cached,
          PMF.mem_support_map_iff]
        exact ⟨out, supported, rfl⟩
      have onlyPublic := c10_probed_game_public cfg publicSeed adversary qr qs initial
        (out.value, out.cache) ordinarySupport
      rw [wots_cut_incoming_zero (wotsGameSeed publicSeed) target before.1 zero] at queried
      exact False.elim (onlyPublic _ queried)
    · have initialExtension : MemoExtends before.2 initial :=
        memo_extends_fresh_update before.2 _ secret
          (wots_before_cut_fresh (wotsGameSeed publicSeed) target before beforeSupport)
      have finalExtension : MemoExtends initial out.cache := by
        intro key value present
        exact eval_opening_preserves digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target)
          randomizerOfDigest secret _ initial false key value present out supported
      exact Or.inr ⟨by omega, before.1,
        eval_program_replay_later digestDraw _ (fun _ => none) before beforeSupport out.cache
          (memo_extends_trans initialExtension finalExtension), queried⟩

theorem wots_probed_unrevealed_bound (target : WotsCutTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) (fun _ => none)).toOuterMeasure
      (wotsProbedUnrevealedEvent (wotsGameSeed publicSeed) target cfg qr) ≤ wotsCutCharge qr qs := by
  let charge := target.2.val + (155135 + (qr + qs * 364076 + 361))
  have budget : SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (bindOpening
        (liftOpening (wotsBeforeCutProgram (wotsGameSeed publicSeed) target.1 target.2.val))
        (fun previous => wotsProbedGameOpening target previous cfg publicSeed adversary qr qs))) charge := by
    exact opening_selected_bind _ _ _ target.2.val (155135 + (qr + qs * 364076 + 361))
      (selectedBudget_total _ _) (fun previous => wots_probed_game_budget target previous cfg publicSeed adversary qr qs)
  have bound := wots_cut_candidate_bound (wotsGameSeed publicSeed) target
    (c10ProbedGameProgram cfg publicSeed adversary qr qs)
    (fun previous => wotsProbedGameOpening target previous cfg publicSeed adversary qr qs)
    (wotsProbeCandidates (qr + 361) target.1.2) (wotsProbedExcluded (wotsGameSeed publicSeed) target cfg)
    (fun previous secret => wots_probed_game_refines target previous secret cfg publicSeed adversary qr qs)
    (fun previous => wots_probed_game_avoids target previous cfg publicSeed adversary qr qs)
    (wots_probed_staged_disclosure target cfg publicSeed adversary qr qs)
    charge (qr + 361 + 2) budget (wots_probe_candidates_card (qr + 361) target.1.2)
  refine bound.trans ?_
  unfold wotsCutCharge
  gcongr 1
  exact (Nat.cast_le (α := ℝ≥0∞)).mpr (show charge + 2 + (qr + 361 + 2) ≤ 155867 + 2 * qr + qs * 364076 by
    have := target.2.isLt
    dsimp only [charge]
    omega)

end
end C10Probability
