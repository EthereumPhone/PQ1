import C10Probability.ByteDriver
import C10Probability.SessionCharges

/-! Key generation and initialization of the finite adaptive byte game.
The direct game retains its entire oracle table. A separately proved
translation reaches the existing compiled game, including its query budgets. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

abbrev C10ByteAdversary (fuel : ℕ) := ByteKey → ByteKey → C10ByteClient C10ByteForgery fuel

def byteAdversaryToStructured {fuel : ℕ} (adversary : C10ByteAdversary fuel) : C10Adversary fuel :=
  fun seed root => byteClientToStructured byteForgeryToStructured (adversary seed root)

def c10ByteGame [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10ByteAdversary fuel) (qr qs : ℕ)
    (table : Memo K Digest) : PMF (Bool × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    c10ByteDriver encode (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2) qr qs key.2)

theorem c10_byte_game_refinement [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    c10Game encode cfg publicSeed (byteAdversaryToStructured adversary) qr qs table =
      c10ByteGame encode cfg publicSeed adversary qr qs table := by
  simp only [c10Game, c10ByteGame, byteAdversaryToStructured, c10_byte_driver_refinement]

def c10ByteGameProgram (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10ByteAdversary fuel) (qr qs : ℕ) :
    QueryProgram K Digest Bool ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
  c10GameProgram encode cfg publicSeed (byteAdversaryToStructured adversary) qr qs

theorem c10_byte_game_eval [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    evalProgram digestDraw (c10ByteGameProgram encode cfg publicSeed adversary qr qs) table =
      c10ByteGame encode cfg publicSeed adversary qr qs table := by
  rw [c10ByteGameProgram, c10_game_eval, c10_byte_game_refinement]

theorem c10_byte_game_public (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10ByteAdversary fuel) (qr qs : ℕ) :
    PublicBudget (c10ByteGameProgram id cfg publicSeed adversary qr qs)
      (sessionGamePublic cfg qr qs) := by
  simpa only [c10ByteGameProgram, sessionGamePublic, Nat.add_assoc, Nat.add_left_comm,
    Nat.add_comm] using c10_game_public cfg publicSeed (byteAdversaryToStructured adversary) qr qs

theorem c10_byte_game_selected (secret : Digest) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10ByteAdversary fuel) (qr qs : ℕ) :
    SelectedBudget nodeQuery
      (c10ByteGameProgram (privateKey prefixedPrivateInput secret) cfg publicSeed adversary qr qs)
      (sessionGameSelected cfg qr qs) := by
  simpa only [c10ByteGameProgram, sessionGameSelected, Nat.add_assoc, Nat.add_left_comm,
    Nat.add_comm] using
    c10_game_selected secret cfg publicSeed (byteAdversaryToStructured adversary) qr qs

def structuredByteSampler {fuel : ℕ} (sampler : PMF (Digest × C10ByteAdversary fuel)) :
    PMF (Digest × C10Adversary fuel) :=
  sampler.map (fun input => (input.1, byteAdversaryToStructured input.2))

def c10ByteInitializedShared (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) : PMF Bool :=
  digestDraw.bind (fun secret => sampler.bind (fun input =>
    (c10ByteGame (privateKey prefixedPrivateInput secret) cfg input.1 input.2 qr qs
      (fun _ => none)).map Prod.fst))

def c10ByteInitializedIndependent (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) : PMF Bool :=
  sampler.bind (fun input =>
    (c10ByteGame id cfg input.1 input.2 qr qs (fun _ => none)).map Prod.fst)

theorem c10_byte_initialized_shared_eq (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    c10InitializedShared cfg (structuredByteSampler sampler) qr qs =
      c10ByteInitializedShared cfg sampler qr qs := by
  simp only [c10InitializedShared, structuredByteSampler, PMF.bind_map, Function.comp_def,
    c10_byte_game_refinement, c10ByteInitializedShared]

theorem c10_byte_initialized_independent_eq (cfg : C10SessionConfig) {fuel : ℕ}
    (sampler : PMF (Digest × C10ByteAdversary fuel)) (qr qs : ℕ) :
    c10InitializedIndependent cfg (structuredByteSampler sampler) qr qs =
      c10ByteInitializedIndependent cfg sampler qr qs := by
  simp only [c10InitializedIndependent, structuredByteSampler, PMF.bind_map, Function.comp_def,
    c10_byte_game_refinement, c10ByteInitializedIndependent]

end
end C10Probability
