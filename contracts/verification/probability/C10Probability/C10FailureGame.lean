import C10Probability.C10FailureSession
import C10Probability.C10RGame

/-! Complete initialized game provenance for the returned signing ledger.
Actual keygen fixes the public-seed bytes. Final verification extends the same
cache and cannot remove an exhausted WOTS schedule. -/
namespace C10Probability
noncomputable section

def c10SigningFailure (out : C10RGameOutput) : Bool := out.2.1.ledger.failed

theorem c10_r_driver_failure_cases (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (cfg : C10SessionConfig)
    {fuel : ℕ} (client : C10Client C10Forgery fuel) (qr qs : ℕ)
    (table : Memo ByteKey Digest) (out : C10RGameOutput × Memo ByteKey Digest)
    (supported : out ∈ (c10RDriver encode cfg client qr qs table).support)
    (failed : c10SigningFailure out.1 = true) :
    c10RFailure out.1 = true ∨ WotsDomainExhausted cfg.seed cfg.wTrials cfg.wBound out.2 := by
  rw [c10RDriver, PMF.mem_support_bind_iff] at supported
  obtain ⟨session, ran, supported⟩ := supported
  rw [PMF.mem_support_map_iff] at supported
  obtain ⟨final, verified, rfl⟩ := supported
  rcases c10_r_initialized_session_failure_cases encode publicKeys cfg client qr qs
    table session ran failed with rfailure | wfailure
  · exact Or.inl rfailure
  · apply Or.inr
    apply wots_domain_exhausted_extends cfg.seed cfg.wTrials cfg.wBound session.2 final.2 _ wfailure
    rw [← c10_final_eval] at verified
    exact eval_program_extends digestDraw _ session.2 final verified

theorem c10_keygen_seed_fixed (encode : WotsQuery → ByteKey)
    (publicSeed : Digest) (table : Memo ByteKey Digest)
    (out : (ByteKey × ByteKey) × Memo ByteKey Digest)
    (supported : out ∈ (c10Keygen encode table publicSeed).support) :
    out.1.1 = nodeBlock (randomizerOfDigest publicSeed) := by
  rw [c10Keygen, PMF.mem_support_map_iff] at supported
  obtain ⟨root, _, rfl⟩ := supported
  rfl

theorem c10_r_game_failure_cases (encode : WotsQuery → ByteKey)
    (publicKeys : ∀ key, encode (.inl key) = key) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ)
    (table : Memo ByteKey Digest) (out : C10RGameOutput × Memo ByteKey Digest)
    (supported : out ∈ (c10RGame encode cfg publicSeed adversary qr qs table).support)
    (failed : c10SigningFailure out.1 = true) :
    c10RFailure out.1 = true ∨ WotsDomainExhausted (nodeBlock (randomizerOfDigest publicSeed))
      cfg.wTrials cfg.wBound out.2 := by
  rw [c10RGame, PMF.mem_support_bind_iff] at supported
  obtain ⟨key, generated, driven⟩ := supported
  have causes := c10_r_driver_failure_cases encode publicKeys (sessionConfigAt cfg key.1)
    (adversary key.1.1 key.1.2) qr qs key.2 out driven failed
  simpa only [sessionConfigAt, c10_keygen_seed_fixed encode publicSeed table key generated] using causes

theorem c10_r_session_failure_erases {K R : Type*} [DecidableEq K]
    (encode : WotsQuery → K) (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client R fuel) (qr qs : ℕ) (ledger : C10SessionLedger) (table : Memo K Digest) :
    (c10RSession encode cfg client qr qs ledger table).map (fun out => out.1.1.ledger.failed) =
      (c10Session encode cfg client qr qs ledger table).map (fun out => out.1.ledger.failed) := by
  rw [← c10_r_session_erases encode cfg client qr qs ledger table, PMF.map_comp]
  rfl

end
end C10Probability
