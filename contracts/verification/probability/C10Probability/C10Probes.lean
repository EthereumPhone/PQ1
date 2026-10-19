import C10Probability.ProbeProgram
import C10Probability.ObservedProgram

/-! The existing observed game plus a passive record of final-verifier
queries. Honest signing and key-generation inputs are not copied into this
probe list. Erasure preserves the existing complete observed output and cache. -/
namespace C10Probability
noncomputable section

abbrev C10ProbedDriver := C10ObservedDriver × List WotsQuery
abbrev C10ProbedGame := C10ObservedGame × List WotsQuery

def c10ProbedDriverProgram (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) :
    QueryProgram WotsQuery Digest C10ProbedDriver (361 + (qr + qs * sessionSignCost cfg)) :=
  bindProgram (c10ObservedSessionProgram id cfg client qr qs emptySessionLedger)
    (fun observed => mapReturnProgram (fun final => (⟨observed, final.1⟩, final.2))
      (probeProgram (c10FinalProgram id cfg observed.session)))

def c10ProbedGameProgram (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    QueryProgram WotsQuery Digest C10ProbedGame ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
  bindProgram (c10KeygenProgram id publicSeed) (fun key =>
    mapReturnProgram (fun driver => (⟨key, driver.1⟩, driver.2))
      (c10ProbedDriverProgram (sessionConfigAt cfg key) (adversary key.1 key.2) qr qs))

def c10ProbeQueries (out : C10ProbedGame) : List WotsQuery :=
  out.1.driver.session.queries.map Sum.inl ++ out.2

theorem c10_probed_driver_erases (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest) :
    (evalProgram digestDraw (c10ProbedDriverProgram cfg client qr qs) table).map
      (fun out => (out.1.1, out.2)) =
        evalProgram digestDraw (c10ObservedDriverProgram id cfg client qr qs) table := by
  simp only [c10ProbedDriverProgram, c10ObservedDriverProgram, evalProgram_bind,
    evalProgram_mapReturn, PMF.map_bind, PMF.map_comp, Function.comp_def]
  congr 1
  funext observed
  have erased := probe_program_erases digestDraw (c10FinalProgram id cfg observed.1.session) observed.2
  simpa only [PMF.map_comp, Function.comp_def] using
    congrArg (PMF.map (fun out : Bool × Memo WotsQuery Digest =>
      (C10ObservedDriver.mk observed.1 out.1, out.2))) erased

theorem c10_probed_game_erases (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest) :
    (evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) table).map
      (fun out => (out.1.1, out.2)) = c10ObservedGame id cfg publicSeed adversary qr qs table := by
  rw [← c10_observed_game_program_eval]
  simp only [c10ProbedGameProgram, c10ObservedGameProgram, evalProgram_bind,
    evalProgram_mapReturn, PMF.map_bind, PMF.map_comp, Function.comp_def]
  congr 1
  funext key
  have erased := c10_probed_driver_erases (sessionConfigAt cfg key.1)
    (adversary key.1.1 key.1.2) qr qs key.2
  simpa only [PMF.map_comp, Function.comp_def] using
    congrArg (PMF.map (fun out : C10ObservedDriver × Memo WotsQuery Digest =>
      (C10ObservedGame.mk key.1 out.1, out.2))) erased

theorem c10_probed_driver_query_bound (cfg : C10SessionConfig) {fuel : ℕ}
    (client : C10Client C10Forgery fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : C10ProbedDriver × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw (c10ProbedDriverProgram cfg client qr qs) table).support) :
    out.1.1.session.queries.length + out.1.2.length ≤ qr + 361 := by
  rw [c10ProbedDriverProgram, evalProgram_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨observed, observedSupport, supported⟩ := supported
  rw [evalProgram_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨final, finalSupport, rfl⟩ := supported
  rw [c10_observed_session_program_eval] at observedSupport
  have raw := c10_observed_query_count id cfg client qr qs emptySessionLedger table observed observedSupport
  have checked := probe_program_length digestDraw (c10FinalProgram id cfg observed.1.session)
    observed.2 final finalSupport
  dsimp only
  omega

theorem c10_probed_game_query_bound (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (out : C10ProbedGame × Memo WotsQuery Digest)
    (supported : out ∈ (evalProgram digestDraw
      (c10ProbedGameProgram cfg publicSeed adversary qr qs) table).support) :
    (c10ProbeQueries out.1).length ≤ qr + 361 := by
  rw [c10ProbedGameProgram, evalProgram_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨key, _, supported⟩ := supported
  rw [evalProgram_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨driver, driverSupport, rfl⟩ := supported
  simpa only [c10ProbeQueries, List.length_append, List.length_map] using
    c10_probed_driver_query_bound (sessionConfigAt cfg key.1) (adversary key.1.1 key.1.2)
      qr qs key.2 driver driverSupport

end
end C10Probability
