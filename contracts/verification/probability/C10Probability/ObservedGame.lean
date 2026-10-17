import C10Probability.ObservedDriverSupport
import C10Probability.SessionGame

/-! Passive observations start with actual keygen and retain its public key.
Keygen, the adaptive session and final verification share one final cache. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

structure C10ObservedGame where
  key : ByteKey × ByteKey
  driver : C10ObservedDriver

def c10ObservedGame [DecidableEq K] (encode : WotsQuery → K) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo K Digest) : PMF (C10ObservedGame × Memo K Digest) :=
  (c10Keygen encode table publicSeed).bind (fun key =>
    (c10ObservedDriver encode (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2)
      qr qs key.2).map (fun out => (⟨key.1, out.1⟩, out.2)))

theorem c10_observed_game_erases [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest) :
    (c10ObservedGame encode cfg publicSeed adversary qr qs table).map
      (fun out => (out.1.driver.accepted, out.2)) =
      c10Game encode cfg publicSeed adversary qr qs table := by
  simp only [c10ObservedGame, c10Game, PMF.map_bind, PMF.map_comp,
    Function.comp_def, c10_observed_driver_erases]

theorem c10_observed_game_support [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support) :
    ∃ keyTable, (out.1.key, keyTable) ∈ (c10Keygen encode table publicSeed).support ∧
      (out.1.driver, out.2) ∈ (c10ObservedDriver encode (sessionConfigAt cfg out.1.key)
        (adversary out.1.key.1 out.1.key.2) qr qs keyTable).support := by
  rw [c10ObservedGame, PMF.mem_support_bind_iff] at ho
  obtain ⟨key, hk, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨driver, hd, rfl⟩ := ho
  exact ⟨key.2, hk, hd⟩

theorem c10_observed_game_keygen [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support) :
    out.1.key.1.length = 32 ∧ out.1.key.2.length = 32 ∧
      replayProgram out.2 (c10KeygenProgram encode publicSeed) = some out.1.key := by
  obtain ⟨keyTable, hk, hd⟩ := c10_observed_game_support encode cfg publicSeed adversary qr qs table out ho
  have widths := c10_keygen_widths encode table publicSeed (out.1.key, keyTable) hk
  have extension := c10_observed_driver_extends encode (sessionConfigAt cfg out.1.key)
    (adversary out.1.key.1 out.1.key.2) qr qs keyTable (out.1.driver, out.2) hd
  have hp : (out.1.key, keyTable) ∈ (evalProgram digestDraw
      (c10KeygenProgram encode publicSeed) table).support := by
    rw [c10_keygen_eval]
    exact hk
  exact ⟨widths.1, widths.2, eval_program_replay_later digestDraw _ table
    (out.1.key, keyTable) hp out.2 extension⟩

theorem c10_observed_game_extends [DecidableEq K] (encode : WotsQuery → K)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo K Digest)
    (out : C10ObservedGame × Memo K Digest)
    (ho : out ∈ (c10ObservedGame encode cfg publicSeed adversary qr qs table).support) :
    MemoExtends table out.2 := by
  apply eval_program_extends digestDraw (c10GameProgram encode cfg publicSeed adversary qr qs)
    table (out.1.driver.accepted, out.2)
  rw [c10_game_eval, ← c10_observed_game_erases encode cfg publicSeed adversary qr qs table,
    PMF.mem_support_map_iff]
  exact ⟨out, ho, rfl⟩

end
end C10Probability
