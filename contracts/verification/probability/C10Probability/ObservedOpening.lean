import C10Probability.C10SignOpening
import C10Probability.ObservedProgram

/-! The actual observed session, final verifier and key-generation game with
one deferred ordinary FORS target. Absorbed/refused calls, signing failures,
successful exposure order, final output and full memo state are preserved. -/
namespace C10Probability
noncomputable section
variable {R : Type*}

theorem opening_avoids_map {K P α H S T : Type*} [DecidableEq K] (target : K)
    (f : S → T) {n : ℕ} (program : OpeningProgram K P α H S n) :
    OpeningAvoids target (mapOpeningReturn f program) = OpeningAvoids target program := by
  induction program with
  | done value => rfl
  | query key next ih => simp only [mapOpeningReturn, OpeningAvoids, ih]
  | commit label next ih => simp only [mapOpeningReturn, OpeningAvoids, ih]
  | reveal next ih => simp only [mapOpeningReturn, OpeningAvoids, ih]

def c10ObservedSessionOpening (target : ForsTarget) (cfg : C10SessionConfig) :
    {fuel : ℕ} → C10Client R fuel → (qr qs : ℕ) → C10SessionLedger →
      OpeningProgram WotsQuery ByteKey Digest Digest (C10ObservedSession R)
        (qr + qs * (sessionSignCost cfg + 1))
  | _, .done value, qr, qs, ledger => .done ⟨⟨value, ledger, qr, qs⟩, [], []⟩
  | _, .hash _ next, 0, qs, ledger => c10ObservedSessionOpening target cfg (next 0) 0 qs ledger
  | _, .hash key next, qr + 1, qs, ledger =>
      castOpening (by omega) (.query (.inl key) (fun reply =>
        mapOpeningReturn (observeHash key)
          (c10ObservedSessionOpening target cfg (next reply) qr qs ledger)))
  | _, .sign _ next, qr, 0, ledger => c10ObservedSessionOpening target cfg (next none) qr 0 ledger
  | _, .sign req next, qr, qs + 1, ledger =>
      if sessionAdmits ledger req then
        castOpening (by simp only [Nat.add_mul, Nat.one_mul, sessionSignCost]; omega)
          (bindOpening (c10SignOpening target req.random req.message cfg.seed cfg.root req.shuffle
            cfg.rTrials cfg.wTrials cfg.rBound cfg.wBound) (fun reply =>
              mapOpeningReturn (observeSign req reply)
                (c10ObservedSessionOpening target cfg (next reply) qr qs
                  (sessionAfterSign ledger req.message reply))))
      else c10ObservedSessionOpening target cfg (next none) qr (qs + 1) ledger

attribute [irreducible] c10ObservedSessionOpening

def c10ObservedDriverOpening (target : ForsTarget) (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest C10ObservedDriver
      (361 + (qr + qs * (sessionSignCost cfg + 1))) :=
  bindOpening (c10ObservedSessionOpening target cfg client qr qs emptySessionLedger)
    (fun observed => mapOpeningReturn (fun accepted => ⟨observed, accepted⟩)
      (liftOpening (c10FinalProgram id cfg observed.session)))

def c10ObservedGameOpening (target : ForsTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningProgram WotsQuery ByteKey Digest Digest C10ObservedGame
      ((361 + (qr + qs * (sessionSignCost cfg + 1))) + 177151) :=
  bindOpening (liftOpening (c10KeygenProgram id publicSeed)) (fun key =>
    mapOpeningReturn (fun driver => ⟨key, driver⟩)
      (c10ObservedDriverOpening target (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs))

theorem c10_observed_session_opening_refines (target : ForsTarget) (secret : Digest)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ)
    (ledger : C10SessionLedger) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10ObservedSessionOpening target cfg client qr qs ledger)
      (c10ObservedSessionProgram id cfg client qr qs ledger) := by
  induction client generalizing qr qs ledger with
  | done value =>
    rw [c10ObservedSessionOpening, c10ObservedSessionProgram]
    exact opening_refines_done _ _ _ _ _ id _ _ _
  | hash key next ih =>
    cases qr with
    | zero => simpa only [c10ObservedSessionOpening, c10ObservedSessionProgram] using ih 0 0 qs ledger
    | succ qr =>
      rw [c10ObservedSessionOpening, c10ObservedSessionProgram]
      apply opening_refines_cast
      apply opening_refines_query
      intro reply
      exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
        secret id id (observeHash key) (observeHash key) (fun _ => rfl) _ _ (ih reply qr qs ledger)
  | sign req next ih =>
    cases qs with
    | zero => simpa only [c10ObservedSessionOpening, c10ObservedSessionProgram] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [c10ObservedSessionOpening, c10ObservedSessionProgram, admitted,
          Bool.false_eq_true, ↓reduceIte] using ih none qr (qs + 1) ledger
      · rw [c10ObservedSessionOpening, c10ObservedSessionProgram, admitted, if_pos rfl, if_pos rfl]
        apply opening_refines_cast
        apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
          secret id id _ _ _ _ (c10_sign_opening_refines target secret _ _ _ _ _ _ _ _ _)
        intro reply
        exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
          secret id id (observeSign req reply) (observeSign req reply) (fun _ => rfl) _ _
          (ih reply qr qs (sessionAfterSign ledger req.message reply))

theorem c10_observed_driver_opening_refines (target : ForsTarget) (secret : Digest)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10ObservedDriverOpening target cfg client qr qs) (c10ObservedDriverProgram id cfg client qr qs) := by
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id _ _ _ _ (c10_observed_session_opening_refines target secret cfg client qr qs emptySessionLedger)
  intro observed
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id (fun accepted => (⟨observed, accepted⟩ : C10ObservedDriver))
    (fun accepted => (⟨observed, accepted⟩ : C10ObservedDriver)) (fun _ => rfl) _ _
    (opening_refines_lift _ _ _ _ _ _)

theorem c10_observed_game_opening_refines (target : ForsTarget) (secret : Digest)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningRefines digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target) secret id
      (c10ObservedGameOpening target cfg publicSeed adversary qr qs)
      (c10ObservedGameProgram id cfg publicSeed adversary qr qs) := by
  apply opening_refines_bind digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id _ _ _ _ (opening_refines_lift _ _ _ _ _ _)
  intro key
  exact opening_refines_map digestDraw nodeCommitEncode randomizerOfDigest (forsTargetKey target)
    secret id id (fun driver => (⟨key, driver⟩ : C10ObservedGame))
    (fun driver => (⟨key, driver⟩ : C10ObservedGame)) (fun _ => rfl) _ _
    (c10_observed_driver_opening_refines target secret (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs)

theorem c10_observed_session_opening_avoids (target : ForsTarget) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) :
    OpeningAvoids (forsTargetKey target) (c10ObservedSessionOpening target cfg client qr qs ledger) := by
  induction client generalizing qr qs ledger with
  | done value => rw [c10ObservedSessionOpening]; trivial
  | hash key next ih =>
    cases qr with
    | zero => simpa only [c10ObservedSessionOpening] using ih 0 0 qs ledger
    | succ qr =>
      rw [c10ObservedSessionOpening, opening_avoids_cast]
      refine ⟨fors_target_not_public target key, fun reply => ?_⟩
      rw [opening_avoids_map]
      exact ih reply qr qs ledger
  | sign req next ih =>
    cases qs with
    | zero => simpa only [c10ObservedSessionOpening] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [c10ObservedSessionOpening, admitted, Bool.false_eq_true, ↓reduceIte] using
          ih none qr (qs + 1) ledger
      · rw [c10ObservedSessionOpening, admitted, if_pos rfl, opening_avoids_cast]
        apply opening_avoids_bind _ _ _ (c10_sign_opening_avoids target _ _ _ _ _ _ _ _ _)
        intro reply
        rw [opening_avoids_map]
        exact ih reply qr qs (sessionAfterSign ledger req.message reply)

theorem c10_final_opening_sealed (target : ForsTarget) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) :
    OpeningSealed (forsTargetKey target) (liftOpening (P := ByteKey) (H := Digest) (c10FinalProgram id cfg out)) := by
  cases admitted : sessionFinalAdmits out
  · simp only [c10FinalProgram, admitted, Bool.false_eq_true, ↓reduceIte, liftOpening, OpeningSealed]
  · rw [c10FinalProgram, admitted, if_pos rfl]
    have sealed := opening_sealed_lift_mapped (P := ByteKey) (H := Digest) (forsTargetKey target)
      Sum.inl (fors_target_not_public target) (c10VerifyProgram id cfg.seed cfg.root out.value.1 out.value.2)
    simpa only [c10_verify_map, Function.comp_id, Function.id_comp] using sealed

theorem c10_observed_driver_opening_avoids (target : ForsTarget) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    OpeningAvoids (forsTargetKey target) (c10ObservedDriverOpening target cfg client qr qs) := by
  apply opening_avoids_bind _ _ _
    (c10_observed_session_opening_avoids target cfg client qr qs emptySessionLedger)
  intro observed
  rw [opening_avoids_map]
  exact opening_sealed_avoids _ _ (c10_final_opening_sealed target cfg observed.session)

theorem c10_observed_game_opening_avoids (target : ForsTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningAvoids (forsTargetKey target) (c10ObservedGameOpening target cfg publicSeed adversary qr qs) := by
  apply opening_avoids_bind _ _ _
    (opening_sealed_avoids _ _ (query_exclusion_sealed _ _ (c10_keygen_fors_excluded target publicSeed)))
  intro key
  rw [opening_avoids_map]
  exact c10_observed_driver_opening_avoids target (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs

theorem c10_observed_session_opening_budget (target : ForsTarget) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (c10ObservedSessionOpening target cfg client qr qs ledger)) (qr + qs * 408408) := by
  induction client generalizing qr qs ledger with
  | done value => rw [c10ObservedSessionOpening]; trivial
  | hash key next ih =>
    cases qr with
    | zero => simpa only [c10ObservedSessionOpening] using ih 0 0 qs ledger
    | succ qr =>
      rw [c10ObservedSessionOpening, redact_opening_cast, selectedBudget_cast]
      rw [show qr + 1 + qs * 408408 = (qr + qs * 408408) + 1 by omega]
      change SelectedBudget _ (.query _ _) ((qr + qs * 408408) + 1)
      apply selectedBudget_query
      intro reply
      rw [redact_opening_mapReturn, selectedBudget_mapReturn]
      exact ih reply qr qs ledger
  | sign req next ih =>
    cases qs with
    | zero => simpa only [c10ObservedSessionOpening] using ih none qr 0 ledger
    | succ qs =>
      cases admitted : sessionAdmits ledger req
      · simpa only [c10ObservedSessionOpening, admitted, Bool.false_eq_true, ↓reduceIte] using
          ih none qr (qs + 1) ledger
      · rw [c10ObservedSessionOpening, admitted, if_pos rfl, redact_opening_cast, selectedBudget_cast]
        rw [show qr + (qs + 1) * 408408 = 408408 + (qr + qs * 408408) by omega]
        apply opening_selected_bind _ _ _ 408408 (qr + qs * 408408)
          (c10_sign_opening_budget target _ _ _ _ _ _ _ _ _)
        intro reply
        rw [redact_opening_mapReturn, selectedBudget_mapReturn]
        exact ih reply qr qs (sessionAfterSign ledger req.message reply)

theorem c10_observed_game_opening_budget (target : ForsTarget) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (c10ObservedGameOpening target cfg publicSeed adversary qr qs))
      (177151 + (qr + qs * 408408) + 361) := by
  rw [show 177151 + (qr + qs * 408408) + 361 = 177151 + ((qr + qs * 408408) + 361) by omega]
  apply opening_selected_bind _ _ _ 177151 ((qr + qs * 408408) + 361) (selectedBudget_total _ _)
  intro key
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  apply opening_selected_bind _ _ _ (qr + qs * 408408) 361
    (c10_observed_session_opening_budget target (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs emptySessionLedger)
  intro observed
  exact selectedBudget_total _ _

end
end C10Probability
