import C10Probability.SessionDriver
import C10Probability.C10Keygen

/-! Keygen and the adaptive structured game share one cache. The syntactic
width guard lets every compiler continuation carry its proved domain budget;
actual keygen support makes that guard redundant in the direct PMF game. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

abbrev C10Adversary (fuel : ℕ) := ByteKey → ByteKey → C10Client C10Forgery fuel

def sessionConfigAt (cfg : C10SessionConfig) (key : ByteKey × ByteKey) : C10SessionConfig :=
  { cfg with seed := key.1, root := key.2 }

theorem session_config_at_fields (cfg : C10SessionConfig) (key : ByteKey × ByteKey) :
    (sessionConfigAt cfg key).seed = key.1 ∧ (sessionConfigAt cfg key).root = key.2 ∧
      (sessionConfigAt cfg key).rTrials = cfg.rTrials ∧
      (sessionConfigAt cfg key).wTrials = cfg.wTrials := by
  exact ⟨rfl, rfl, rfl, rfl⟩

def c10GameAfterProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) (key : ByteKey × ByteKey) :
    QueryProgram K Digest Bool (361 + (qr + qs * sessionSignCost cfg)) :=
  if key.1.length = 32 ∧ key.2.length = 32 then
    c10DriverProgram encode (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs
  else .done false

theorem c10_game_after_eval [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) (key : ByteKey × ByteKey)
    (table : Memo K Digest) (hw : key.1.length = 32 ∧ key.2.length = 32) :
    evalProgram digestDraw (c10GameAfterProgram encode cfg adversary qr qs key) table =
      c10Driver encode (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs table := by
  rw [c10GameAfterProgram, if_pos hw]
  exact c10_driver_eval encode (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs table

theorem c10_game_after_map (encode : K → L) (labels : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) (key : ByteKey × ByteKey) :
    mapProgram encode (c10GameAfterProgram labels cfg adversary qr qs key) =
      c10GameAfterProgram (encode ∘ labels) cfg adversary qr qs key := by
  by_cases h : key.1.length = 32 ∧ key.2.length = 32
  · simp only [c10GameAfterProgram, if_pos h]
    exact c10_driver_map encode labels (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs
  · simp only [c10GameAfterProgram, if_neg h, mapProgram]

theorem c10_game_after_public (cfg : C10SessionConfig) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (key : ByteKey × ByteKey) :
    PublicBudget (c10GameAfterProgram id cfg adversary qr qs key)
      (qr + qs * sessionSignPublic cfg + 361) := by
  by_cases h : key.1.length = 32 ∧ key.2.length = 32
  · rw [c10GameAfterProgram, if_pos h]
    exact c10_driver_public _ _ _ _
  · simp only [c10GameAfterProgram, if_neg h, PublicBudget]

theorem c10_game_after_selected (secret : Digest) (cfg : C10SessionConfig) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (key : ByteKey × ByteKey) :
    SelectedBudget nodeQuery
      (c10GameAfterProgram (privateKey prefixedPrivateInput secret) cfg adversary qr qs key)
      (qr + qs * sessionSignSelected cfg + 358) := by
  by_cases h : key.1.length = 32 ∧ key.2.length = 32
  · rw [c10GameAfterProgram, if_pos h]
    exact c10_driver_selected _ _ _ _ _ h.1 h.2
  · simp only [c10GameAfterProgram, if_neg h, SelectedBudget]

def c10GameProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    QueryProgram K Digest Bool ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
  bindProgram (c10KeygenProgram encode publicSeed) (c10GameAfterProgram encode cfg adversary qr qs)

def c10Game [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo K Digest) : PMF (Bool × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    c10Driver encode (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2) qr qs key.2)

theorem c10_game_eval [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo K Digest) :
    evalProgram digestDraw (c10GameProgram encode cfg publicSeed adversary qr qs) table =
      c10Game encode cfg publicSeed adversary qr qs table := by
  simp only [c10GameProgram, evalProgram_bind, c10_keygen_eval, c10Game]
  apply pmf_bind_support_congr
  intro key hk
  exact c10_game_after_eval encode cfg adversary qr qs key.1 key.2
    (c10_keygen_widths encode table publicSeed key hk)

theorem c10_game_map (encode : K → L) (labels : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    mapProgram encode (c10GameProgram labels cfg publicSeed adversary qr qs) =
      c10GameProgram (encode ∘ labels) cfg publicSeed adversary qr qs := by
  simp only [c10GameProgram, mapProgram_bind, c10_keygen_map, c10_game_after_map]

theorem c10_game_public (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    PublicBudget (c10GameProgram id cfg publicSeed adversary qr qs)
      (155135 + (qr + qs * sessionSignPublic cfg + 361)) := by
  exact publicBudget_bind _ _ _ _ (c10_keygen_public publicSeed)
    (c10_game_after_public cfg adversary qr qs)

theorem c10_game_selected (secret : Digest) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    SelectedBudget nodeQuery
      (c10GameProgram (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs)
      (177151 + (qr + qs * sessionSignSelected cfg + 358)) := by
  exact selectedBudget_bind _ _ _ _ _ (selectedBudget_total _ _)
    (c10_game_after_selected secret cfg adversary qr qs)

end
end C10Probability
