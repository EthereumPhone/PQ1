import C10Probability.RejectSchedule
import C10Probability.WotsProgram

/-! A finite cover of actual WOTS count inputs at a fixed public seed.
The layer/tree/keypair fields use all of their serialized widths. Together
with the 16-byte message they contain 256 variable bits. No logical-address
restriction or adversary-selected-message freshness premise is imposed. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

abbrev WotsCountContext :=
  (Fin 4 → Fin 256) × (Fin 8 → Fin 256) × (Fin 4 → Fin 256) × (Fin 16 → Fin 256)

def wotsContextStem (seed : ByteKey) (context : WotsCountContext) : ByteKey :=
  seed ++ (List.ofFn context.1 ++ List.ofFn context.2.1 ++ List.replicate 4 0 ++
    List.ofFn context.2.2.1 ++ List.replicate 4 0 ++ List.replicate 4 0 ++
    List.replicate 4 0) ++ List.ofFn context.2.2.2 ++ List.replicate 16 0

theorem wots_count_context_card : Fintype.card WotsCountContext = 2 ^ 256 := by
  simp only [WotsCountContext, Fintype.card_prod, Fintype.card_fun, Fintype.card_fin]
  norm_num

theorem wots_count_stem_covered (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (width : message.length = 16) :
    ∃ context : WotsCountContext,
      wotsCountStem seed layer tree kp message = wotsContextStem seed context := by
  let bytes (n value : ℕ) : Fin n → Fin 256 :=
    fun i => ⟨value / 256 ^ (n - 1 - i.val) % 256, Nat.mod_lt _ (by decide)⟩
  let msg : Fin 16 → Fin 256 := fun i => message.get ⟨i.val, by omega⟩
  have msg_eq : List.ofFn msg = message := by
    apply List.ext_get
    · simpa [msg] using width.symm
    · intro i hi hj
      simp only [List.get_eq_getElem, List.getElem_ofFn]
      rfl
  refine ⟨(bytes 4 layer, bytes 8 tree, bytes 4 kp, msg), ?_⟩
  simp only [wotsCountStem, wotsContextStem, c10Address, be_bytes_zero, msg_eq]
  rfl

def WotsDomainExhausted (seed : ByteKey) (trials : ℕ) (bounded : trials ≤ 2 ^ 32)
    (table : Memo ByteKey Digest) : Prop :=
  ∃ context : WotsCountContext,
    CompleteRejection (wotsAccept ∘ wotsOfDigest)
      (counterSchedule (wotsContextStem seed context) 0 trials (by simpa using bounded)).toFinset table

theorem wots_domain_exhausted_extends (seed : ByteKey) (trials : ℕ)
    (bounded : trials ≤ 2 ^ 32) (before after : Memo ByteKey Digest)
    (extension : MemoExtends before after)
    (exhausted : WotsDomainExhausted seed trials bounded before) :
    WotsDomainExhausted seed trials bounded after := by
  obtain ⟨context, complete⟩ := exhausted
  exact ⟨context, complete_rejection_extends _ _ before after extension complete⟩

theorem wots_count_exhaustion_in_domain (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (width : message.length = 16) (trials : ℕ)
    (bounded : trials ≤ 2 ^ 32) (table final : Memo ByteKey Digest)
    (exhausted : (none, final) ∈
      (wotsCountSearch table seed layer tree kp message 0 trials (by simpa using bounded)).support) :
    WotsDomainExhausted seed trials bounded final := by
  obtain ⟨context, same⟩ := wots_count_stem_covered seed layer tree kp message width
  refine ⟨context, ?_⟩
  rw [← same]
  exact memo_grind_exhaustion_rejects digestDraw (wotsAccept ∘ wotsOfDigest)
    _ 0 table final exhausted

def wotsDomainCharge (trials : ℕ) : ℝ≥0∞ :=
  2 ^ 256 * rejectMass digestDraw (wotsAccept ∘ wotsOfDigest) ^ trials

theorem randomized_wots_domain_bound {R : Type*} {budget : ℕ}
    (clients : PMF (QueryProgram ByteKey Digest R budget)) (seed : ByteKey)
    (trials : ℕ) (bounded : trials ≤ 2 ^ 32) :
    (randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
      {out | WotsDomainExhausted seed trials bounded out.2} ≤ wotsDomainCharge trials := by
  let events := fun context : WotsCountContext =>
    {out : R × Memo ByteKey Digest | CompleteRejection (wotsAccept ∘ wotsOfDigest)
      (counterSchedule (wotsContextStem seed context) 0 trials (by simpa using bounded)).toFinset out.2}
  calc
    _ ≤ (randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure (⋃ context, events context) := by
      apply MeasureTheory.OuterMeasure.mono
      intro out exhausted
      exact Set.mem_iUnion.mpr exhausted
    _ ≤ ∑ context, (randomizedProgram digestDraw clients (fun _ => none)).toOuterMeasure
        (events context) := MeasureTheory.measure_iUnion_fintype_le _ _
    _ ≤ ∑ _ : WotsCountContext,
        rejectMass digestDraw (wotsAccept ∘ wotsOfDigest) ^ trials := by
      apply Finset.sum_le_sum
      intro context _
      exact randomized_rejected_counter_bound clients (wotsContextStem seed context) 0 trials _
    _ = _ := by
      simp only [Finset.sum_const, Finset.card_univ, wots_count_context_card, nsmul_eq_mul,
        Nat.cast_pow, Nat.cast_ofNat, wotsDomainCharge]

end
end C10Probability
