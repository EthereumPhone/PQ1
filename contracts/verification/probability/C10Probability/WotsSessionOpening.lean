import C10Probability.C10Probes
import C10Probability.ObservedOpening

/-! The actual observed session with an explicit WOTS cut. A raw query to
the incoming key reveals its cached full digest and still reaches the client.
Refused and absorbed calls keep their original behavior. -/
namespace C10Probability
noncomputable section
variable {R : Type*}

def wotsObservedSessionOpening (target : WotsCutTarget) (previous : Randomizer) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → (qr qs : ℕ) → C10SessionLedger →
      OpeningProgram WotsQuery Unit Digest Digest (C10ObservedSession R)
        (qr + qs * (sessionSignCost cfg + 1))
  | _, .done value, qr, qs, ledger => .done ⟨⟨value, ledger, qr, qs⟩, [], []⟩
  | _, .hash _ next, 0, qs, ledger => wotsObservedSessionOpening target previous cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castOpening (by omega)
        (if (.inl key : WotsQuery) = wotsCutIncoming cfg.seed target previous then
          .reveal (fun reply => mapOpeningReturn (observeHash key)
            (wotsObservedSessionOpening target previous cfg (next reply) qr qs ledger))
        else .query (.inl key) (fun reply => mapOpeningReturn (observeHash key)
          (wotsObservedSessionOpening target previous cfg (next reply) qr qs ledger)))
  | _, .sign _ next, qr, 0, ledger => wotsObservedSessionOpening target previous cfg (next none) qr 0 ledger
  | _, .sign req next, qr, qs + 1, ledger =>
      if sessionAdmits ledger req then
        castOpening (by simp only [Nat.add_mul, Nat.one_mul, sessionSignCost]; omega)
          (bindOpening (wotsC10Opening cfg.seed target previous req.random req.message cfg.root req.shuffle
            cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound) (fun reply =>
              mapOpeningReturn (observeSign req reply)
                (wotsObservedSessionOpening target previous cfg (next reply) qr qs
                  (sessionAfterSign ledger req.message reply))))
      else wotsObservedSessionOpening target previous cfg (next none) qr (qs + 1) ledger

attribute [irreducible] wotsObservedSessionOpening

theorem wots_observed_session_refines (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel)
    (qr qs : ℕ) (ledger : C10SessionLedger) :
    OpeningRefines digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
      (wotsCutIncoming cfg.seed target previous) secret id
      (wotsObservedSessionOpening target previous cfg client qr qs ledger)
      (c10ObservedSessionProgram id cfg client qr qs ledger) := by
  induction client generalizing qr qs ledger with
  | done value =>
    rw [wotsObservedSessionOpening, c10ObservedSessionProgram]
    exact opening_refines_done _ _ _ _ _ id _ _ _
  | hash key next ih =>
    cases qr with
    | zero => simpa only [wotsObservedSessionOpening, c10ObservedSessionProgram] using ih 0 0 qs ledger
    | succ qr =>
      rw [wotsObservedSessionOpening, c10ObservedSessionProgram]
      apply opening_refines_cast
      have later := fun reply => opening_refines_map digestDraw (wotsCutCommit cfg.seed target)
        randomizerOfDigest (wotsCutIncoming cfg.seed target previous) secret id id
        (observeHash key) (observeHash key) (fun _ => rfl) _ _ (ih reply qr qs ledger)
      by_cases matched : (.inl key : WotsQuery) = wotsCutIncoming cfg.seed target previous
      · rw [if_pos matched]
        rw [show id (.inl key) = wotsCutIncoming cfg.seed target previous from matched]
        exact opening_refines_reveal _ _ _ _ _ _ _ _ (later secret)
      · rw [if_neg matched]
        exact opening_refines_query _ _ _ _ _ _ _ _ _ later
  | sign req next ih =>
    cases qs with
    | zero => simpa only [wotsObservedSessionOpening, c10ObservedSessionProgram] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [wotsObservedSessionOpening, c10ObservedSessionProgram, admitted,
          Bool.false_eq_true, ↓reduceIte] using ih none qr (qs + 1) ledger
      · rw [wotsObservedSessionOpening, c10ObservedSessionProgram, admitted, if_pos rfl, if_pos rfl]
        apply opening_refines_cast
        apply opening_refines_bind digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
          (wotsCutIncoming cfg.seed target previous) secret id id _ _ _ _
          (wots_c10_opening_refines cfg.seed target previous _ _ _ _ _ _ _ _ secret)
        intro reply
        exact opening_refines_map digestDraw (wotsCutCommit cfg.seed target) randomizerOfDigest
          (wotsCutIncoming cfg.seed target previous) secret id id
          (observeSign req reply) (observeSign req reply) (fun _ => rfl) _ _
          (ih reply qr qs (sessionAfterSign ledger req.message reply))

theorem wots_observed_session_avoids (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) (seedWidth : cfg.seed.length = 32) (rootWidth : cfg.root.length = 32)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) :
    OpeningAvoids (wotsCutIncoming cfg.seed target previous)
      (wotsObservedSessionOpening target previous cfg client qr qs ledger) := by
  induction client generalizing qr qs ledger with
  | done value => rw [wotsObservedSessionOpening]; trivial
  | hash key next ih =>
    cases qr with
    | zero => simpa only [wotsObservedSessionOpening] using ih 0 0 qs ledger
    | succ qr =>
      rw [wotsObservedSessionOpening, opening_avoids_cast]
      by_cases matched : (.inl key : WotsQuery) = wotsCutIncoming cfg.seed target previous
      · rw [if_pos matched]
        intro reply
        rw [opening_avoids_map]
        exact ih reply qr qs ledger
      · rw [if_neg matched]
        refine ⟨matched, fun reply => ?_⟩
        rw [opening_avoids_map]
        exact ih reply qr qs ledger
  | sign req next ih =>
    cases qs with
    | zero => simpa only [wotsObservedSessionOpening] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [wotsObservedSessionOpening, admitted, Bool.false_eq_true, ↓reduceIte] using
          ih none qr (qs + 1) ledger
      · rw [wotsObservedSessionOpening, admitted, if_pos rfl, opening_avoids_cast]
        have widths := (session_admits_iff ledger req).mp admitted
        apply opening_avoids_bind _ _ _ (wots_c10_opening_avoids cfg.seed target previous
          _ _ _ _ _ _ _ _ seedWidth rootWidth widths.2.1 widths.2.2.2)
        intro reply
        rw [opening_avoids_map]
        exact ih reply qr qs (sessionAfterSign ledger req.message reply)

theorem wots_observed_session_budget (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsObservedSessionOpening target previous cfg client qr qs ledger))
      (qr + qs * 364076) := by
  induction client generalizing qr qs ledger with
  | done value => rw [wotsObservedSessionOpening]; trivial
  | hash key next ih =>
    cases qr with
    | zero => simpa only [wotsObservedSessionOpening] using ih 0 0 qs ledger
    | succ qr =>
      rw [wotsObservedSessionOpening, redact_opening_cast, selectedBudget_cast]
      by_cases matched : (.inl key : WotsQuery) = wotsCutIncoming cfg.seed target previous
      · rw [if_pos matched]
        trivial
      · rw [if_neg matched, show qr + 1 + qs * 364076 = (qr + qs * 364076) + 1 by omega]
        change SelectedBudget _ (.query _ _) ((qr + qs * 364076) + 1)
        apply selectedBudget_query
        intro reply
        rw [redact_opening_mapReturn, selectedBudget_mapReturn]
        exact ih reply qr qs ledger
  | sign req next ih =>
    cases qs with
    | zero => simpa only [wotsObservedSessionOpening] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [wotsObservedSessionOpening, admitted, Bool.false_eq_true, ↓reduceIte] using
          ih none qr (qs + 1) ledger
      · rw [wotsObservedSessionOpening, admitted, if_pos rfl, redact_opening_cast, selectedBudget_cast]
        rw [show qr + (qs + 1) * 364076 = 364076 + (qr + qs * 364076) by omega]
        apply opening_selected_bind _ _ _ 364076 (qr + qs * 364076)
          (wots_c10_opening_budget cfg.seed target previous _ _ _ _ _ _ _ _)
        intro reply
        rw [redact_opening_mapReturn, selectedBudget_mapReturn]
        exact ih reply qr qs (sessionAfterSign ledger req.message reply)

end
end C10Probability
