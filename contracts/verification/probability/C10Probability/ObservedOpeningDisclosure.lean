import C10Probability.ObservedOpening

/-! Every marked opening in the actual observed game has a successful
exposure and a selected R/H_msg result replayable from the final cache. Failed,
absorbed and refused requests cannot manufacture such an exposure. -/
namespace C10Probability
noncomputable section
variable {R : Type*}

def ForsReturned (target : ForsTarget) (cfg : C10SessionConfig) (entries : List C10Exposure)
    (table : Memo WotsQuery Digest) : Prop :=
  ∃ entry ∈ entries, ∃ trial digest,
    replayProgram table (randomizerUnderProgram id entry.request.random entry.request.message
      cfg.seed cfg.root cfg.rTrials cfg.rBound) = some (some (trial, entry.signature.randomizer, digest)) ∧
    ForestSelected target (hypertreeIndex digest) digest

theorem fors_returned_extends (target : ForsTarget) (cfg : C10SessionConfig)
    (entries : List C10Exposure) (before after : Memo WotsQuery Digest)
    (extension : MemoExtends before after) (returned : ForsReturned target cfg entries before) :
    ForsReturned target cfg entries after := by
  obtain ⟨entry, member, trial, digest, recorded, selected⟩ := returned
  exact ⟨entry, member, trial, digest, replay_program_extends _ before after _ extension recorded, selected⟩

theorem c10_observed_session_opened (target : ForsTarget) (secret : Digest) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger)
    (table : Memo WotsQuery Digest) (out : OpeningOutput WotsQuery Digest (C10ObservedSession R))
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ObservedSessionOpening target cfg client qr qs ledger) table false).support)
    (opened : out.opened = true) : ForsReturned target cfg out.value.exposures out.cache := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have equal : out = ⟨⟨⟨value, ledger, qr, qs⟩, [], []⟩, table, false⟩ := by
      simpa only [c10ObservedSessionOpening, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | hash key next ih =>
    cases qr with
    | zero =>
      rw [c10ObservedSessionOpening] at supported
      exact ih 0 0 qs ledger table out supported opened
    | succ qr =>
      rw [c10ObservedSessionOpening, eval_opening_cast, evalOpening, PMF.mem_support_bind_iff] at supported
      obtain ⟨reply, _, supported⟩ := supported
      rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
      obtain ⟨rest, supported, rfl⟩ := supported
      exact ih reply.1 qr qs ledger reply.2 rest supported opened
  | sign req next ih =>
    cases qs with
    | zero =>
      rw [c10ObservedSessionOpening] at supported
      exact ih none qr 0 ledger table out supported opened
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · rw [c10ObservedSessionOpening, admitted, if_neg Bool.false_ne_true] at supported
        exact ih none qr (qs + 1) ledger table out supported opened
      · rw [c10ObservedSessionOpening, admitted, if_pos rfl, eval_opening_cast,
          eval_opening_bind, PMF.mem_support_bind_iff] at supported
        obtain ⟨signed, signSupport, supported⟩ := supported
        rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
        obtain ⟨rest, restSupport, rfl⟩ := supported
        cases signFlag : signed.opened
        · rw [signFlag] at restSupport
          obtain ⟨entry, member, trial, digest, recorded, selected⟩ :=
            ih signed.value qr qs (sessionAfterSign ledger req.message signed.value)
              signed.cache rest restSupport opened
          refine ⟨entry, ?_, trial, digest, recorded, selected⟩
          cases signed.value with
          | none => exact member
          | some sig => exact List.mem_cons_of_mem _ member
        · obtain ⟨trial, signature, digest, equal, recorded, selected⟩ :=
            c10_sign_opened target secret req.random req.message cfg.seed cfg.root req.shuffle
              cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound table signed signSupport signFlag
          have extension : MemoExtends signed.cache rest.cache := by
            intro key value cached
            exact eval_opening_preserves digestDraw nodeCommitEncode randomizerOfDigest secret
              (c10ObservedSessionOpening target cfg (next signed.value) qr qs
                (sessionAfterSign ledger req.message signed.value)) signed.cache signed.opened
              key value cached rest restSupport
          refine ⟨⟨req, signature⟩, ?_, trial, digest,
            replay_program_extends _ signed.cache rest.cache _ extension recorded, selected⟩
          simp only [equal, observe_sign_some, List.mem_cons_self]

theorem c10_observed_driver_opened (target : ForsTarget) (secret : Digest) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : OpeningOutput WotsQuery Digest C10ObservedDriver)
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ObservedDriverOpening target cfg client qr qs) table false).support)
    (opened : out.opened = true) : ForsReturned target cfg out.value.session.exposures out.cache := by
  rw [c10ObservedDriverOpening, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨session, sessionSupport, supported⟩ := supported
  rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨final, finalSupport, rfl⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at finalSupport
  obtain ⟨result, resultSupport, rfl⟩ := finalSupport
  have returned := c10_observed_session_opened target secret cfg client qr qs emptySessionLedger
    table session sessionSupport opened
  exact fors_returned_extends target cfg session.value.exposures session.cache result.2
    (fun key value cached => evalProgram_preserves digestDraw _ session.cache key value cached result resultSupport)
    returned

theorem c10_observed_game_opened (target : ForsTarget) (secret : Digest) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo WotsQuery Digest) (out : OpeningOutput WotsQuery Digest C10ObservedGame)
    (supported : out ∈ (evalOpening digestDraw nodeCommitEncode randomizerOfDigest secret
      (c10ObservedGameOpening target cfg publicSeed adversary qr qs) table false).support)
    (opened : out.opened = true) :
    ForsReturned target (sessionConfigAt cfg out.value.key) out.value.driver.session.exposures out.cache := by
  rw [c10ObservedGameOpening, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨key, keySupport, supported⟩ := supported
  rw [eval_opening_lift, PMF.mem_support_map_iff] at keySupport
  obtain ⟨keygen, _, rfl⟩ := keySupport
  rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨driver, driverSupport, rfl⟩ := supported
  exact c10_observed_driver_opened target secret (sessionConfigAt cfg keygen.1)
    (adversary keygen.1.1 keygen.1.2) qr qs keygen.2 driver driverSupport opened

end
end C10Probability
