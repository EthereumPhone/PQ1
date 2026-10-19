import C10Probability.SessionCharges
import C10Probability.CountMessageBinding
import C10Probability.WotsExact
import C10Probability.NodePathBinding

/-! Charges on the independent tagged cache. The fixed zero below is used
only to pull back the existing syntactic domain budget. No cache or execution
is mapped to a physical shared oracle, and tagged keys stay distinct. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

def nodeBudgetSelector : WotsQuery → Bool := nodeQuery ∘ privateKey prefixedPrivateInput 0

theorem node_budget_selector_public (key : ByteKey) :
    nodeBudgetSelector (.inl key) = nodeQuery key := rfl

theorem tagged_node_collision (table : Memo WotsQuery Digest)
    (collision : ¬ PublicNodeCollisionFree Sum.inl table) :
    ¬ CollisionFree randomizerOfDigest (selectedCache nodeBudgetSelector table) := by
  intro free
  apply collision
  intro key other value reply first second equal
  apply Sum.inl.inj
  exact free (.inl key) (.inl other) value reply
    (by simpa only [selectedCache, node_budget_selector_public] using first)
    (by simpa only [selectedCache, node_budget_selector_public] using second) equal

theorem tagged_public_zero (table : Memo WotsQuery Digest)
    (zero : PublicNodeZero (fun key => table (.inl key))) : ¬ NoTarget nodeZero table := by
  obtain ⟨key, value, cached, zero⟩ := zero
  intro free
  have absent := free (.inl key) value cached
  rw [zero] at absent
  contradiction

theorem tagged_accepted_collision (table : Memo WotsQuery Digest)
    (collision : AcceptedWotsCollision (fun key => table (.inl key))) :
    ¬ AcceptedCollisionFree wotsOfDigest wotsAccept table := by
  obtain ⟨key, other, value, reply, first, second, accepted, equal, distinct⟩ := collision
  intro free
  exact distinct (Sum.inl.inj (free (.inl key) (.inl other) value reply
    first second accepted equal))

theorem c10_independent_game_selected (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    SelectedBudget nodeBudgetSelector (c10GameProgram id cfg publicSeed adversary qr qs)
      (sessionGameSelected cfg qr qs) := by
  have budget := c10_game_selected 0 cfg publicSeed adversary qr qs
  have mapped := c10_game_map (privateKey prefixedPrivateInput 0) id cfg publicSeed adversary qr qs
  simp only [Function.comp_id] at mapped
  rw [← mapped, selectedBudget_map] at budget
  simpa only [nodeBudgetSelector, sessionGameSelected, Nat.add_assoc, Nat.add_comm,
    Nat.add_left_comm] using budget

theorem c10_independent_mixture_selected (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (program : QueryProgram WotsQuery Digest Bool ((361 + (qr + qs * sessionSignCost cfg)) + 177151))
    (member : program ∈ (c10GameMixtureProgram cfg sampler qr qs).support) :
    SelectedBudget nodeBudgetSelector program (sessionGameSelected cfg qr qs) := by
  rw [c10GameMixtureProgram, PMF.mem_support_map_iff] at member
  obtain ⟨input, _, rfl⟩ := member
  exact c10_independent_game_selected cfg input.1 input.2 qr qs

theorem tagged_program_node_collision_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram WotsQuery Digest R n)) (q : ℕ)
    (budget : ∀ program ∈ client.support, SelectedBudget nodeBudgetSelector program q) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | ¬ PublicNodeCollisionFree Sum.inl out.2} ≤
        (q.choose 2 : ℝ≥0∞) / 2 ^ 128 := by
  refine (MeasureTheory.OuterMeasure.mono _ (fun out hit => tagged_node_collision out.2 hit)).trans ?_
  simpa only [Fintype.card_fin, Nat.cast_pow, Nat.cast_ofNat] using
    randomizedProgram_selected_empty_bound digestDraw nodeBudgetSelector randomizerOfDigest
      randomizer_uniform client q budget

theorem tagged_program_zero_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram WotsQuery Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | PublicNodeZero (fun key => out.2 (.inl key))} ≤ (n : ℝ≥0∞) / 2 ^ 128 := by
  refine (MeasureTheory.OuterMeasure.mono _ (fun out hit => tagged_public_zero out.2 hit)).trans ?_
  simpa only [node_zero_mass, div_eq_mul_inv] using
    randomizedProgram_target_bound digestDraw nodeZero client (fun _ => none) (noTarget_empty nodeZero)

def acceptedWotsGameCharge (n : ℕ) : ℝ≥0∞ :=
  (n.choose 2 : ℝ≥0∞) * ((22169393903687611906220091621190388 : ℝ≥0∞) / 8 ^ 43) / 8 ^ 43

theorem tagged_program_accepted_bound {R : Type*} {n : ℕ}
    (client : PMF (QueryProgram WotsQuery Digest R n)) :
    (randomizedProgram digestDraw client (fun _ => none)).toOuterMeasure
      {out | AcceptedWotsCollision (fun key => out.2 (.inl key))} ≤ acceptedWotsGameCharge n := by
  refine (MeasureTheory.OuterMeasure.mono _ (fun out hit => tagged_accepted_collision out.2 hit)).trans ?_
  have bound := randomizedProgram_accepted_collision_bound digestDraw wotsOfDigest wotsAccept
    digest_uniform_wots client emptyView (emptyAcceptedView_valid wotsOfDigest wotsAccept) rfl
  have cardinality : Fintype.card WotsWord = 8 ^ 43 := by
    simp only [WotsWord, Fintype.card_fun, Fintype.card_fin]
  simpa only [acceptedWotsGameCharge, emptyView, Finset.card_empty, acceptedCollisionCharge,
    Nat.cast_zero, mul_zero, zero_add, digest_wots_acceptance_mass, cardinality,
    accepted_wots_card_exact, Nat.cast_pow, Nat.cast_ofNat] using bound

theorem accepted_wots_game_charge_ne_top (n : ℕ) : acceptedWotsGameCharge n ≠ ⊤ := by
  unfold acceptedWotsGameCharge
  finiteness

end
end C10Probability
