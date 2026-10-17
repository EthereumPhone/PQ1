import C10Probability.ObservedAccounting

/-! Every logged response is supported by the actual signer and remains
replayable in the final cache. Forwarded raw inputs also remain recorded there;
these properties neither assert fresh sampling nor reveal the cache to clients. -/
namespace C10Probability
noncomputable section

variable {K R : Type*}

def exposureProgram (encode : WotsQuery → K) (cfg : C10SessionConfig) (entry : C10Exposure) :
    QueryProgram K Digest (Option C10Signature) (sessionSignCost cfg) :=
  c10SignProgram encode entry.request.random entry.request.message cfg.seed cfg.root
    entry.request.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound

def ExposureSupported (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (table : Memo K Digest) (entry : C10Exposure) : Prop :=
  entry.request.message.length = 32 ∧
    (entry.request.random.length = 0 ∨ entry.request.random.length = 16) ∧
    entry.request.shuffle.length = 32 ∧ C10SignatureWellFormed entry.signature ∧
    replayProgram table (exposureProgram encode cfg entry) = some (some entry.signature)

theorem exposure_supported_extends (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (before after : Memo K Digest) (entry : C10Exposure)
    (extension : MemoExtends before after) (supported : ExposureSupported encode cfg before entry) :
    ExposureSupported encode cfg after entry := by
  obtain ⟨hm, hr, hs, hw, hp⟩ := supported
  exact ⟨hm, hr, hs, hw, replay_program_extends _ before after _ extension hp⟩

theorem c10_observed_exposure_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    ∀ entry ∈ out.1.exposures, ExposureSupported encode cfg out.2 entry := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have he : out = (⟨⟨value, ledger, qr, qs⟩, [], []⟩, table) := by
      simpa only [c10ObservedSession, PMF.mem_support_pure_iff] using ho
    simp only [he, List.not_mem_nil, false_implies, implies_true]
  | hash key next ih =>
    cases qr with
    | zero => exact ih 0 0 qs ledger table out ho
    | succ qr =>
      rw [c10ObservedSession, PMF.mem_support_bind_iff] at ho
      obtain ⟨reply, _, ho⟩ := ho
      rw [PMF.mem_support_map_iff] at ho
      obtain ⟨rest, hr, rfl⟩ := ho
      exact ih reply.1 qr qs ledger reply.2 rest hr
  | sign req next ih =>
    cases qs with
    | zero => exact ih none qr 0 ledger table out ho
    | succ qs =>
      cases ha : sessionAdmits ledger req
      · simp only [c10ObservedSession, ha, Bool.false_eq_true, ↓reduceIte] at ho
        exact ih none qr (qs + 1) ledger table out ho
      · simp only [c10ObservedSession, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
        obtain ⟨reply, hreply, ho⟩ := ho
        rw [PMF.mem_support_map_iff] at ho
        obtain ⟨rest, hr, rfl⟩ := ho
        have tail := ih reply.1 qr qs (sessionAfterSign ledger req.message reply.1) reply.2 rest hr
        cases hsig : reply.1 with
        | none => simpa only [hsig, observeSign] using tail
        | some sig =>
          simp only [observeSign, List.mem_cons]
          intro entry he
          rcases he with rfl | he
          · obtain ⟨_, hm, hrandom, hshuffle⟩ := (session_admits_iff ledger req).mp ha
            have hshape := c10_sign_signature_shape encode table req.random req.message
              cfg.seed cfg.root req.shuffle cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound
              reply hreply
            have hprogram : reply ∈ (evalProgram digestDraw
                (exposureProgram encode cfg ⟨req, sig⟩) table).support := by
              change reply ∈ (evalProgram digestDraw
                (c10SignProgram encode req.random req.message cfg.seed cfg.root req.shuffle
                  cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound) table).support
              rw [c10_sign_eval]
              exact hreply
            have extension := c10_observed_session_extends encode cfg (next reply.1) qr qs
              (sessionAfterSign ledger req.message reply.1) reply.2 rest hr
            have replay := eval_program_replay_later digestDraw
              (exposureProgram encode cfg ⟨req, sig⟩) table reply hprogram rest.2 extension
            refine ⟨hm, hrandom, hshuffle, ?_, ?_⟩
            · simpa only [hsig] using hshape
            · simpa only [hsig] using replay
          · exact tail entry he

theorem c10_observed_raw_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) (table : Memo K Digest)
    (out : C10ObservedSession R × Memo K Digest)
    (ho : out ∈ (c10ObservedSession encode cfg client qr qs ledger table).support) :
    ∀ key ∈ out.1.queries, ∃ reply, out.2 (encode (.inl key)) = some reply := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have he : out = (⟨⟨value, ledger, qr, qs⟩, [], []⟩, table) := by
      simpa only [c10ObservedSession, PMF.mem_support_pure_iff] using ho
    simp only [he, List.not_mem_nil, false_implies, implies_true]
  | hash key next ih =>
    cases qr with
    | zero => exact ih 0 0 qs ledger table out ho
    | succ qr =>
      rw [c10ObservedSession, PMF.mem_support_bind_iff] at ho
      obtain ⟨reply, hreply, ho⟩ := ho
      rw [PMF.mem_support_map_iff] at ho
      obtain ⟨rest, hr, rfl⟩ := ho
      have tail := ih reply.1 qr qs ledger reply.2 rest hr
      simp only [observeHash, List.mem_cons]
      intro other he
      rcases he with rfl | he
      · have extension := c10_observed_session_extends encode cfg (next reply.1) qr qs
          ledger reply.2 rest hr
        exact ⟨reply.1, extension (encode (.inl other)) reply.1
          (memoQuery_stores digestDraw table (encode (.inl other)) reply hreply)⟩
      · exact tail other he
  | sign req next ih =>
    cases qs with
    | zero => exact ih none qr 0 ledger table out ho
    | succ qs =>
      cases ha : sessionAdmits ledger req
      · simp only [c10ObservedSession, ha, Bool.false_eq_true, ↓reduceIte] at ho
        exact ih none qr (qs + 1) ledger table out ho
      · simp only [c10ObservedSession, ha, ↓reduceIte, PMF.mem_support_bind_iff] at ho
        obtain ⟨reply, _, ho⟩ := ho
        rw [PMF.mem_support_map_iff] at ho
        obtain ⟨rest, hr, rfl⟩ := ho
        have tail := ih reply.1 qr qs (sessionAfterSign ledger req.message reply.1) reply.2 rest hr
        cases hsig : reply.1 <;> simpa only [hsig, observeSign] using tail

end
end C10Probability
