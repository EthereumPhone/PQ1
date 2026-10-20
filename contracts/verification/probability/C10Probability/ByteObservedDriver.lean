import C10Probability.ByteGame
import C10Probability.C10FailureGame

/-! Direct byte execution retaining the actual session result alongside final
verification. Erasure recovers the old byte driver. The structured R observer
agrees after forgetting only its auxiliary R-exhaustion flag. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

abbrev C10ByteGameOutput := Bool × C10SessionResult C10ByteForgery

def byteOutputToStructured (out : C10ByteGameOutput) : Bool × C10SessionResult C10Forgery :=
  (out.1, mapSessionValue byteForgeryToStructured out.2)

def c10ByteSigningFailure (out : C10ByteGameOutput) : Bool := out.2.ledger.failed

def c10ByteObservedDriver [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) : PMF (C10ByteGameOutput × Memo K Digest) :=
  (c10ByteSession encode cfg client qr qs emptySessionLedger table).bind (fun session =>
    (c10ByteFinal encode cfg session.1 session.2).map
      (fun final => ((final.1, session.1), final.2)))

theorem byte_output_to_structured_fields (out : C10ByteGameOutput) :
    (byteOutputToStructured out).1 = out.1 ∧
      (byteOutputToStructured out).2.value = byteForgeryToStructured out.2.value ∧
      (byteOutputToStructured out).2.ledger = out.2.ledger ∧
      (byteOutputToStructured out).2.rawRemaining = out.2.rawRemaining ∧
      (byteOutputToStructured out).2.signRemaining = out.2.signRemaining := by
  exact ⟨rfl, rfl, rfl, rfl, rfl⟩

theorem c10_byte_observed_driver_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10ByteObservedDriver encode cfg client qr qs table).map
      (fun out => (out.1.1, out.2)) = c10ByteDriver encode cfg client qr qs table := by
  simp only [c10ByteObservedDriver, PMF.map_bind, PMF.map_comp, Function.comp_def,
    Prod.mk.eta, c10ByteDriver]
  congr 1
  funext out
  exact PMF.map_id _

theorem c10_r_driver_session_observation [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10Client C10Forgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10RDriver encode cfg client qr qs table).map
      (fun out => ((out.1.1, out.1.2.1), out.2)) =
      (c10Session encode cfg client qr qs emptySessionLedger table).bind (fun session =>
        (c10Final encode cfg session.1 session.2).map
          (fun final => ((final.1, session.1), final.2))) := by
  rw [← c10_r_session_erases encode cfg client qr qs emptySessionLedger table, PMF.bind_map]
  simp only [c10RDriver, PMF.map_bind, PMF.map_comp, Function.comp_def]

theorem c10_byte_observed_driver_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10RDriver encode cfg (byteClientToStructured byteForgeryToStructured client)
      qr qs table).map (fun out => ((out.1.1, out.1.2.1), out.2)) =
      (c10ByteObservedDriver encode cfg client qr qs table).map
        (fun out => (byteOutputToStructured out.1, out.2)) := by
  rw [c10_r_driver_session_observation, c10_byte_session_refinement, PMF.bind_map]
  simp only [c10ByteObservedDriver, PMF.map_bind, PMF.map_comp, Function.comp_def,
    byteOutputToStructured]
  apply pmf_bind_support_congr
  intro session _
  rw [c10_byte_final_refinement]

theorem c10_byte_observed_driver_failure [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) {fuel : ℕ} (client : C10ByteClient C10ByteForgery fuel)
    (qr qs : ℕ) (table : Memo K Digest) :
    (c10ByteObservedDriver encode cfg client qr qs table).map
      (fun out => c10ByteSigningFailure out.1) =
      (c10ByteSession encode cfg client qr qs emptySessionLedger table).map
        (fun out => out.1.ledger.failed) := by
  simp only [c10ByteObservedDriver, PMF.map_bind, PMF.map_comp, Function.comp_def,
    c10ByteSigningFailure]
  simp only [PMF.map, Function.comp_def, PMF.bind_const]

end
end C10Probability
