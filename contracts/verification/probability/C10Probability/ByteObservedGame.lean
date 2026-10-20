import C10Probability.ByteObservedDriver

/-! Actual key generation precedes the directly observed byte session.
The original final verification and full physical cache are preserved. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def c10ByteObservedGame [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    PMF (C10ByteGameOutput × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    c10ByteObservedDriver encode (sessionConfigAt cfg key.1)
      (adversary key.1.1 key.1.2) qr qs key.2)

theorem c10_byte_observed_game_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10ByteObservedGame encode cfg publicSeed adversary qr qs table).map
      (fun out => (out.1.1, out.2)) = c10ByteGame encode cfg publicSeed adversary qr qs table := by
  simp only [c10ByteObservedGame, PMF.map_bind, c10_byte_observed_driver_erases, c10ByteGame]

theorem c10_byte_observed_game_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10RGame encode cfg publicSeed (byteAdversaryToStructured adversary) qr qs table).map
      (fun out => ((out.1.1, out.1.2.1), out.2)) =
      (c10ByteObservedGame encode cfg publicSeed adversary qr qs table).map
        (fun out => (byteOutputToStructured out.1, out.2)) := by
  simp only [c10RGame, c10ByteObservedGame, PMF.map_bind, byteAdversaryToStructured,
    c10_byte_observed_driver_refinement]

theorem c10_byte_observed_game_verdict [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10ByteObservedGame encode cfg publicSeed adversary qr qs table).map
      (fun out => out.1.1) =
      (c10ByteGame encode cfg publicSeed adversary qr qs table).map Prod.fst := by
  rw [← c10_byte_observed_game_erases, PMF.map_comp]
  rfl

theorem c10_byte_observed_game_failure [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10RGame encode cfg publicSeed (byteAdversaryToStructured adversary) qr qs table).map
      (fun out => c10SigningFailure out.1) =
      (c10ByteObservedGame encode cfg publicSeed adversary qr qs table).map
        (fun out => c10ByteSigningFailure out.1) := by
  have same := congrArg
    (fun p => p.map (fun out : (Bool × C10SessionResult C10Forgery) × Memo K Digest =>
      out.1.2.ledger.failed))
    (c10_byte_observed_game_refinement encode cfg publicSeed adversary qr qs table)
  simpa only [PMF.map_comp, Function.comp_def, byteOutputToStructured, mapSessionValue,
    c10SigningFailure, c10ByteSigningFailure] using same

end
end C10Probability
