import C10Probability.WotsSessionOpening

/-! Every session disclosure is either an actual successful exposure or a
forwarded raw query to the incoming key. Raw-query disclosure is kept explicit
for the preceding-cut probability charge. -/
namespace C10Probability
noncomputable section
variable {R : Type*}

theorem wots_observed_session_opened (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) (seedWidth : cfg.seed.length = 32)
    (rootWidth : cfg.root.length = 32) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo WotsQuery Digest)
    (cached : table (wotsCutIncoming cfg.seed target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest (C10ObservedSession R))
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
      (wotsObservedSessionOpening target previous cfg client qr qs ledger) table false).support)
    (opened : out.opened = true) :
    WotsReturned target cfg out.value.exposures out.cache ∨
      wotsCutIncoming cfg.seed target previous ∈ out.value.queries.map Sum.inl := by
  induction client generalizing qr qs ledger table out with
  | done value =>
    have equal : out = ⟨⟨⟨value, ledger, qr, qs⟩, [], []⟩, table, false⟩ := by
      simpa only [wotsObservedSessionOpening, evalOpening, PMF.mem_support_pure_iff] using supported
    simp only [equal, Bool.false_eq_true] at opened
  | hash key next ih =>
    cases qr with
    | zero =>
      rw [wotsObservedSessionOpening] at supported
      exact ih 0 0 qs ledger table cached out supported opened
    | succ qr =>
      rw [wotsObservedSessionOpening, eval_opening_cast] at supported
      by_cases matched : (.inl key : WotsQuery) = wotsCutIncoming cfg.seed target previous
      · rw [if_pos matched, evalOpening, eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
        obtain ⟨rest, _, rfl⟩ := supported
        right
        change wotsCutIncoming cfg.seed target previous ∈ (key :: rest.value.queries).map Sum.inl
        rw [List.map_cons, ← matched]
        exact List.mem_cons_self
      · rw [if_neg matched, evalOpening, PMF.mem_support_bind_iff] at supported
        obtain ⟨reply, replySupport, supported⟩ := supported
        rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
        obtain ⟨rest, restSupport, rfl⟩ := supported
        have stillCached := memoQuery_preserves digestDraw table (.inl key)
          (wotsCutIncoming cfg.seed target previous) secret cached reply replySupport
        rcases ih reply.1 qr qs ledger reply.2 stillCached rest restSupport opened with returned | queried
        · exact Or.inl returned
        · right
          simpa only [observeHash, List.map_cons] using List.mem_cons_of_mem (.inl key) queried
  | sign req next ih =>
    cases qs with
    | zero =>
      rw [wotsObservedSessionOpening] at supported
      exact ih none qr 0 ledger table cached out supported opened
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · rw [wotsObservedSessionOpening, admitted, if_neg Bool.false_ne_true] at supported
        exact ih none qr (qs + 1) ledger table cached out supported opened
      · rw [wotsObservedSessionOpening, admitted, if_pos rfl, eval_opening_cast,
          eval_opening_bind, PMF.mem_support_bind_iff] at supported
        obtain ⟨signed, signSupport, supported⟩ := supported
        rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
        obtain ⟨rest, restSupport, rfl⟩ := supported
        cases signFlag : signed.opened
        · have stillCached := eval_opening_preserves digestDraw (wotsCutCommit cfg.seed target)
            randomizerOfDigest secret _ table false (wotsCutIncoming cfg.seed target previous)
            secret cached signed signSupport
          rw [signFlag] at restSupport
          rcases ih signed.value qr qs (sessionAfterSign ledger req.message signed.value)
            signed.cache stillCached rest restSupport opened with returned | queried
          · left
            obtain ⟨entry, member, record, valid, exposed⟩ := returned
            refine ⟨entry, ?_, record, valid, exposed⟩
            cases signed.value with
            | none => exact member
            | some sig => exact List.mem_cons_of_mem _ member
          · right
            cases signed.value <;> exact queried
        · have widths := (session_admits_iff ledger req).mp admitted
          obtain ⟨signature, record, value, valid, exposed⟩ := wots_c10_opened cfg target previous req
            secret seedWidth rootWidth widths.2.1 widths.2.2.2 table cached signed signSupport signFlag
          have extension : MemoExtends signed.cache rest.cache := by
            intro key digest present
            exact eval_opening_preserves digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest secret
              (wotsObservedSessionOpening target previous cfg (next signed.value) qr qs
                (sessionAfterSign ledger req.message signed.value)) signed.cache signed.opened
              key digest present rest restSupport
          left
          refine ⟨⟨req, signature⟩, ?_, record,
            c10_signing_record_valid_extends id signed.cache rest.cache cfg _ record extension valid, exposed⟩
          simp only [value, observe_sign_some, List.mem_cons_self]

end
end C10Probability
