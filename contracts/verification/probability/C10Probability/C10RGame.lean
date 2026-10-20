import C10Probability.C10RExhaustion
import C10Probability.SessionGame

/-! Actual keygen, the complete adaptive C10 session, and final verification
share one memo table. The observer retains the full session result and final
decision; erasing it gives the original direct game exactly. -/
namespace C10Probability
open scoped ENNReal
noncomputable section

variable {K L : Type*}

abbrev C10RGameOutput := Bool × C10RSessionResult C10Forgery

def c10RFailure (out : C10RGameOutput) : Bool := out.2.2

def c10RDriverProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    QueryProgram K Digest C10RGameOutput (361 + (qr + qs * sessionSignCost cfg)) :=
  bindProgram (c10RSessionProgram encode cfg client qr qs emptySessionLedger)
    (fun observed => mapReturnProgram (fun decision => (decision, observed))
      (c10FinalProgram encode cfg observed.1))

def c10RDriver [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (C10RGameOutput × Memo K Digest) :=
  (c10RSession encode cfg client qr qs emptySessionLedger table).bind (fun observed =>
    (c10Final encode cfg observed.1.1 observed.2).map
      (fun final => ((final.1, observed.1), final.2)))

theorem c10_r_driver_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10RDriverProgram encode cfg client qr qs) table =
      c10RDriver encode cfg client qr qs table := by
  simp only [c10RDriverProgram, evalProgram_bind, c10_r_session_eval,
    evalProgram_mapReturn, c10_final_eval, c10RDriver]

theorem c10_r_driver_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10RDriver encode cfg client qr qs table).map (fun out => (out.1.1, out.2)) =
      c10Driver encode cfg client qr qs table := by
  simp only [c10RDriver, PMF.map_bind, PMF.map_comp, Function.comp_def, Prod.mk.eta]
  have same : (fun observed : C10RSessionResult C10Forgery × Memo K Digest =>
      (c10Final encode cfg observed.1.1 observed.2).map (fun x => x)) =
      (fun observed => c10Final encode cfg observed.1.1 observed.2) := by
    funext observed
    exact PMF.map_id _
  rw [same, c10Driver, ← c10_r_session_erases encode cfg client qr qs emptySessionLedger table,
    PMF.bind_map]
  rfl

theorem c10_r_driver_map (encode : K → L) (labels : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    mapProgram encode (c10RDriverProgram labels cfg client qr qs) =
      c10RDriverProgram (encode ∘ labels) cfg client qr qs := by
  simp only [c10RDriverProgram, mapProgram_bind, c10_r_session_map,
    mapProgram_mapReturn, c10_final_map]

theorem c10_r_driver_public (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    PublicBudget (c10RDriverProgram id cfg client qr qs)
      (qr + qs * sessionSignPublic cfg + 361) := by
  apply publicBudget_bind _ _ _ _ (c10_r_session_public _ _ _ _ _)
  intro observed
  rw [publicBudget_mapReturn]
  exact c10_final_public cfg observed.1

theorem c10_r_driver_failure [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10RDriver encode cfg client qr qs table).map (fun out => c10RFailure out.1) =
      (c10RSession encode cfg client qr qs emptySessionLedger table).map (fun out => out.1.2) := by
  simp only [c10RDriver, PMF.map_bind, PMF.map_comp, Function.comp_def, c10RFailure]
  simp only [PMF.map, Function.comp_def, PMF.bind_const]

def c10RGameProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    QueryProgram K Digest C10RGameOutput ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
  bindProgram (c10KeygenProgram encode publicSeed) (fun key =>
    c10RDriverProgram encode (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs)

def c10RGame [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo K Digest) : PMF (C10RGameOutput × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    c10RDriver encode (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2) qr qs key.2)

theorem c10_r_game_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10RGameProgram encode cfg publicSeed adversary qr qs) table =
      c10RGame encode cfg publicSeed adversary qr qs table := by
  simp only [c10RGameProgram, evalProgram_bind, c10_keygen_eval, c10RGame]
  congr 1
  funext key
  exact c10_r_driver_eval encode (sessionConfigAt cfg key.1)
    (adversary key.1.1 key.1.2) qr qs key.2

theorem c10_r_game_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10RGame encode cfg publicSeed adversary qr qs table).map (fun out => (out.1.1, out.2)) =
      c10Game encode cfg publicSeed adversary qr qs table := by
  simp only [c10RGame, PMF.map_bind, c10_r_driver_erases, c10Game]

theorem c10_r_game_map (encode : K → L) (labels : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    mapProgram encode (c10RGameProgram labels cfg publicSeed adversary qr qs) =
      c10RGameProgram (encode ∘ labels) cfg publicSeed adversary qr qs := by
  simp only [c10RGameProgram, mapProgram_bind, c10_keygen_map]
  congr 1
  funext key
  exact c10_r_driver_map _ _ _ _ _ _

def c10RPublicCalls (cfg : C10SessionConfig) (qr qs : ℕ) : ℕ :=
  155135 + (qr + qs * sessionSignPublic cfg + 361)

def c10RHistoryCap (cfg : C10SessionConfig) (qr qs : ℕ) : ℕ :=
  155135 + qr + qs * sessionSignPublic cfg

theorem c10_r_game_public (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    PublicBudget (c10RGameProgram id cfg publicSeed adversary qr qs) (c10RPublicCalls cfg qr qs) := by
  exact publicBudget_bind _ _ _ _ (c10_keygen_public publicSeed)
    (fun _ => c10_r_driver_public _ _ _ _)

theorem c10_r_game_initialized_exhaustion (cfg : C10SessionConfig) (publicSeed : Digest)
    {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    ((c10RGame id cfg publicSeed adversary qr qs (fun _ => none)).map
      (fun out => c10RFailure out.1)) true ≤
        (qs : ℝ≥0∞) * rExhaustionCharge (c10RHistoryCap cfg qr qs) cfg.rTrials := by
  unfold c10RGame
  apply r_bind_flag_bound
  intro key supported
  rw [c10_r_driver_failure]
  exact c10_r_session_exhaustion (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2)
    qr qs ∅ emptySessionLedger 155135 (c10RHistoryCap cfg qr qs) key.2
    (c10_r_invariant_keygen (sessionConfigAt cfg key.1) publicSeed key supported) le_rfl

end
end C10Probability
