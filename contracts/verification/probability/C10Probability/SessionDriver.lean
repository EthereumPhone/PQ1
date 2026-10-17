import C10Probability.SessionBudget
import C10Probability.C10Verify

/-! Structured FullDriver: accept only a fresh32-byte message, a well-shaped
signature, and a session without admitted signing exhaustion. Typed nodes and
WOTS vectors already enforce their widths; the4008-byte codec is separate. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

abbrev C10Forgery := ByteKey × C10Signature

def sessionSignatureWidth (sig : C10Signature) : Bool :=
  decide (sig.secrets.length = 13) && decide (sig.auths.length = 12) &&
    sig.auths.all (fun auth => decide (auth.length = 11)) &&
    decide (sig.layers.length = 2) &&
    sig.layers.all (fun layer => decide (layer.count < 2 ^ 32 ∧ layer.auth.length = 9))

theorem session_signature_width_iff (sig : C10Signature) :
    sessionSignatureWidth sig = true ↔ C10SignatureWellFormed sig := by
  simp only [sessionSignatureWidth, Bool.and_eq_true, decide_eq_true_eq, List.all_eq_true,
    C10SignatureWellFormed, LayerSignatureWellFormed]
  tauto

def sessionFinalAdmits (out : C10SessionResult C10Forgery) : Bool :=
  !out.ledger.failed && decide (out.value.1.length = 32) &&
    sessionSignatureWidth out.value.2 && decide (out.value.1 ∉ out.ledger.signedMessages)

theorem session_final_admits_iff (out : C10SessionResult C10Forgery) :
    sessionFinalAdmits out = true ↔ out.ledger.failed = false ∧
      out.value.1.length = 32 ∧ C10SignatureWellFormed out.value.2 ∧
      out.value.1 ∉ out.ledger.signedMessages := by
  simp only [sessionFinalAdmits, Bool.and_eq_true, Bool.not_eq_true', decide_eq_true_eq,
    session_signature_width_iff]
  tauto

def c10FinalProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) : QueryProgram K Digest Bool 361 :=
  if sessionFinalAdmits out then
    c10VerifyProgram (encode ∘ Sum.inl) cfg.seed cfg.root out.value.1 out.value.2
  else .done false

def c10Final [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) (table : Memo K Digest) : PMF (Bool × Memo K Digest) :=
  if sessionFinalAdmits out then
    c10Verify (encode ∘ Sum.inl) table cfg.seed cfg.root out.value.1 out.value.2
  else PMF.pure (false, table)

theorem c10_final_eval [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) (table : Memo K Digest) :
    evalProgram digestDraw (c10FinalProgram encode cfg out) table = c10Final encode cfg out table := by
  cases h : sessionFinalAdmits out <;>
    simp only [c10FinalProgram, c10Final, h, Bool.false_eq_true, ↓reduceIte,
      c10_verify_eval, evalProgram]

theorem c10_final_map (encode : K → L) (labels : WotsQuery → K) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) :
    mapProgram encode (c10FinalProgram labels cfg out) = c10FinalProgram (encode ∘ labels) cfg out := by
  cases h : sessionFinalAdmits out <;>
    simp only [c10FinalProgram, h, Bool.false_eq_true, ↓reduceIte,
      c10_verify_map, mapProgram, Function.comp_assoc]

theorem c10_final_public (cfg : C10SessionConfig) (out : C10SessionResult C10Forgery) :
    PublicBudget (c10FinalProgram id cfg out) 361 := publicBudget_total _

theorem c10_final_selected (secret : Digest) (cfg : C10SessionConfig)
    (out : C10SessionResult C10Forgery) (hs : cfg.seed.length = 32) (hr : cfg.root.length = 32) :
    SelectedBudget nodeQuery (c10FinalProgram (privateKey prefixedPrivateInput secret) cfg out) 358 := by
  cases h : sessionFinalAdmits out
  · simp only [c10FinalProgram, h, Bool.false_eq_true, ↓reduceIte, SelectedBudget]
  · simp only [c10FinalProgram, h, ↓reduceIte]
    exact c10_verify_selected cfg.seed cfg.root out.value.1 out.value.2 hs hr
      ((session_final_admits_iff out).mp h).2.1

def c10DriverProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    QueryProgram K Digest Bool (361 + (qr + qs * sessionSignCost cfg)) :=
  bindProgram (c10SessionProgram encode cfg client qr qs emptySessionLedger)
    (c10FinalProgram encode cfg)

def c10Driver [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (Bool × Memo K Digest) :=
  (c10Session encode cfg client qr qs emptySessionLedger table).bind
    (fun out => c10Final encode cfg out.1 out.2)

theorem c10_driver_eval [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10DriverProgram encode cfg client qr qs) table =
      c10Driver encode cfg client qr qs table := by
  simp only [c10DriverProgram, evalProgram_bind, c10_session_eval, c10_final_eval, c10Driver]

theorem c10_driver_map (encode : K → L) (labels : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    mapProgram encode (c10DriverProgram labels cfg client qr qs) =
      c10DriverProgram (encode ∘ labels) cfg client qr qs := by
  simp only [c10DriverProgram, mapProgram_bind, c10_session_map, c10_final_map]

theorem c10_driver_public (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    PublicBudget (c10DriverProgram id cfg client qr qs) (qr + qs * sessionSignPublic cfg + 361) := by
  exact publicBudget_bind _ _ _ _ (c10_session_public _ _ _ _ _) (c10_final_public cfg)

theorem c10_driver_selected (secret : Digest) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ)
    (hs : cfg.seed.length = 32) (hr : cfg.root.length = 32) :
    SelectedBudget nodeQuery (c10DriverProgram (privateKey prefixedPrivateInput secret) cfg client qr qs)
      (qr + qs * sessionSignSelected cfg + 358) := by
  exact selectedBudget_bind _ _ _ _ _ (c10_session_selected _ _ _ _ _ _ hs hr)
    (fun out => c10_final_selected secret cfg out hs hr)

end
end C10Probability
