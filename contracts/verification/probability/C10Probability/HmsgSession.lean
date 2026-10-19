import C10Probability.HmsgSigner
import C10Probability.ObservedProgram
import C10Probability.ObservedInitialized
import C10Probability.HmsgPoolBound

/-! The initialized observed independent-interface game has at most qr + qs + 1
accepted H_msg calls. This bound is independent of grinder and tree work. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

theorem c10_observed_session_hmsg_budget {R : Type*} (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger)
    (width : cfg.seed.length = 32) :
    ReplyBudget (hmsgReplyCharge hmsgQuery)
      (c10ObservedSessionProgram id cfg client qr qs ledger) (qr + qs) := by
  induction client generalizing qr qs ledger with
  | done value => simp only [c10ObservedSessionProgram, ReplyBudget]
  | hash key next ih =>
    cases qr with
    | zero => simpa only [c10ObservedSessionProgram] using ih 0 0 qs ledger
    | succ qr =>
      rw [c10ObservedSessionProgram, replyBudget_cast,
        show qr + 1 + qs = (qr + qs) + 1 by omega]
      apply replyBudget_query
      intro reply
      rw [replyBudget_mapReturn]
      exact ih reply qr qs ledger
  | sign req next ih =>
    cases qs with
    | zero => simpa only [c10ObservedSessionProgram] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [c10ObservedSessionProgram, admitted, Bool.false_eq_true, ↓reduceIte] using
          ih none qr (qs + 1) ledger
      · rw [c10ObservedSessionProgram, admitted, if_pos rfl, replyBudget_cast,
          show qr + (qs + 1) = 1 + (qr + qs) by omega]
        apply replyBudget_bind _ _ _ 1 (qr + qs)
          (c10_sign_hmsg_budget _ _ _ _ _ _ _ _ _ width
            ((session_admits_iff ledger req).mp admitted).2.2.2)
        intro reply
        rw [replyBudget_mapReturn]
        exact ih reply qr qs (sessionAfterSign ledger req.message reply)

theorem c10_observed_driver_hmsg_budget (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) (width : cfg.seed.length = 32) :
    ReplyBudget (hmsgReplyCharge hmsgQuery)
      (c10ObservedDriverProgram id cfg client qr qs) (qr + qs + 1) := by
  rw [c10ObservedDriverProgram]
  apply replyBudget_bind _ _ _ (qr + qs) 1
    (c10_observed_session_hmsg_budget cfg client qr qs emptySessionLedger width)
  intro observed
  rw [replyBudget_mapReturn]
  cases admitted : sessionFinalAdmits observed.session
  · simp only [c10FinalProgram, admitted, Bool.false_eq_true, ↓reduceIte, ReplyBudget]
  · rw [c10FinalProgram, admitted, if_pos rfl]
    exact c10_verify_hmsg_budget cfg.seed cfg.root observed.session.value.1 observed.session.value.2 width

theorem c10_observed_game_hmsg_budget (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    ReplyBudget (hmsgReplyCharge hmsgQuery)
      (c10ObservedGameProgram id cfg publicSeed adversary qr qs) (qr + qs + 1) := by
  rw [c10ObservedGameProgram]
  apply queryExclusion_reply_bind hmsgQuery
    (fun key => key.1.length = 32 ∧ key.2.length = 32)
  · simp only [c10KeygenProgram, subtreeRootProgram, queryExclusion_mapReturn,
      Function.comp_def, node_block_length, and_self]
    exact subtree_hmsg_excluded _ _ _ _ _ (node_block_length _)
  · intro key widths
    rw [replyBudget_mapReturn]
    exact c10_observed_driver_hmsg_budget (sessionConfigAt cfg key)
      (adversary key.1 key.2) qr qs widths.1

def c10ObservedPool (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    PMF (HmsgPoolOutput WotsQuery C10ObservedGame) :=
  sampler.bind (fun input => hmsgPoolProgram hmsgQuery
    (c10ObservedGameProgram id cfg input.1 input.2 qr qs) (fun _ => none))

theorem c10_observed_pool_erases (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedPool cfg sampler qr qs).map (fun out => (out.value, out.cache)) =
      c10ObservedInitializedIndependent cfg sampler qr qs := by
  simp only [c10ObservedPool, PMF.map_bind, hmsg_pool_program_erases,
    c10_observed_game_program_eval, c10ObservedInitializedIndependent]

theorem c10_observed_pool_length (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ)
    (out : HmsgPoolOutput WotsQuery C10ObservedGame)
    (supported : out ∈ (c10ObservedPool cfg sampler qr qs).support) :
    out.entries.length ≤ qr + qs + 1 := by
  rw [c10ObservedPool, PMF.mem_support_bind_iff] at supported
  obtain ⟨input, _, supported⟩ := supported
  exact hmsg_pool_length hmsgQuery _ (qr + qs + 1)
    (c10_observed_game_hmsg_budget cfg input.1 input.2 qr qs) _ out supported

theorem c10_observed_pool_coverage_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10Adversary fuel)) (qr qs : ℕ) :
    (c10ObservedPool cfg sampler qr qs).toOuterMeasure
      {out | ForsListCoverage (out.entries.map Prod.snd)} ≤ forsCoverageCharge (qr + qs + 1) := by
  have same : (c10ObservedPool cfg sampler qr qs).toOuterMeasure
      {out | ForsListCoverage (out.entries.map Prod.snd)} =
      (c10ObservedPool cfg sampler qr qs).toOuterMeasure
        {out | out.entries.length ≤ qr + qs + 1 ∧ ForsListCoverage (out.entries.map Prod.snd)} := by
    apply PMF.toOuterMeasure_apply_eq_of_inter_support_eq
    ext out
    constructor
    · rintro ⟨covered, supported⟩
      exact ⟨⟨c10_observed_pool_length cfg sampler qr qs out supported, covered⟩, supported⟩
    · rintro ⟨⟨_, covered⟩, supported⟩
      exact ⟨covered, supported⟩
  rw [same, c10ObservedPool, PMF.toOuterMeasure_bind_apply]
  calc
    _ ≤ ∑' input, sampler input * forsCoverageCharge (qr + qs + 1) := by
      apply pmf_weighted_bound
      intro input _
      exact hmsg_pool_coverage_bound hmsgQuery _ _ (qr + qs + 1)
    _ = _ := by rw [ENNReal.tsum_mul_right, PMF.tsum_coe, one_mul]

end
end C10Probability
