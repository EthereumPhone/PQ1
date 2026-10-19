import C10Probability.WotsDriverOpening

/-! The full observed game starts with the actual upper-tree key generation.
Its public seed is the original normalized node block. Every selected hidden
node in keygen is handled by the same proved tree refinement as signing. -/
namespace C10Probability
noncomputable section

def wotsGameSeed (publicSeed : Digest) : ByteKey := nodeBlock (randomizerOfDigest publicSeed)

def wotsProbedGameOpening (target : WotsCutTarget) (previous : Randomizer) (cfg : C10SessionConfig)
    (publicSeed : Digest) {fuel : ℕ} (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningProgram WotsQuery Unit Digest Digest C10ProbedGame
      ((361 + (qr + qs * (sessionSignCost cfg + 1))) + 177151) :=
  let seed := wotsGameSeed publicSeed
  bindOpening (wotsSubtreeRootOpening seed target previous (.inr 0)) (fun root =>
    mapOpeningReturn (fun driver => (⟨(seed, nodeBlock root), driver.1⟩, driver.2))
      (wotsProbedDriverOpening target previous (sessionConfigAt cfg (seed, nodeBlock root))
        (adversary seed (nodeBlock root)) qr qs))

theorem wots_probed_game_refines (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningRefines digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target) randomizerOfDigest
      (wotsCutIncoming (wotsGameSeed publicSeed) target previous) secret id
      (wotsProbedGameOpening target previous cfg publicSeed adversary qr qs)
      (c10ProbedGameProgram cfg publicSeed adversary qr qs) := by
  let seed := wotsGameSeed publicSeed
  let ordinary : QueryProgram WotsQuery Digest C10ProbedGame
      ((361 + (qr + qs * sessionSignCost cfg)) + 177151) :=
    bindProgram (subtreeRootProgram id seed 1 0) (fun root =>
    mapReturnProgram (fun driver : C10ProbedDriver =>
      ((⟨(seed, nodeBlock root), driver.1⟩ : C10ObservedGame), driver.2))
      (c10ProbedDriverProgram (sessionConfigAt cfg (seed, nodeBlock root))
        (adversary seed (nodeBlock root)) qr qs))
  have compared : OpeningRefines digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id
      (wotsProbedGameOpening target previous cfg publicSeed adversary qr qs) ordinary := by
    apply opening_refines_bind digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id id _ _ _ _
      (wots_subtree_root_opening_refines seed target previous (.inr 0) secret)
    intro root
    exact opening_refines_map digestDraw (wotsCutCommit seed target) randomizerOfDigest
      (wotsCutIncoming seed target previous) secret id id
      (fun driver : C10ProbedDriver => ((⟨(seed, nodeBlock root), driver.1⟩ : C10ObservedGame), driver.2))
      (fun driver : C10ProbedDriver => ((⟨(seed, nodeBlock root), driver.1⟩ : C10ObservedGame), driver.2))
      (fun _ => rfl) _ _ (wots_probed_driver_refines target previous secret
        (sessionConfigAt cfg (seed, nodeBlock root)) (adversary seed (nodeBlock root)) qr qs)
  intro table opened cached
  have equality : evalProgram digestDraw (c10ProbedGameProgram cfg publicSeed adversary qr qs) table =
      evalProgram digestDraw ordinary table := by
    simp only [c10ProbedGameProgram, c10KeygenProgram, ordinary, seed, wotsGameSeed,
      evalProgram_bind, evalProgram_mapReturn, PMF.bind_map, Function.comp_def]
  rw [equality]
  exact compared table opened cached

theorem wots_probed_game_avoids (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    OpeningAvoids (wotsCutIncoming (wotsGameSeed publicSeed) target previous)
      (wotsProbedGameOpening target previous cfg publicSeed adversary qr qs) := by
  apply opening_avoids_bind _ _ _ (opening_sealed_avoids _ _
    (wots_subtree_root_opening_sealed (wotsGameSeed publicSeed) target previous (.inr 0)))
  intro root
  rw [opening_avoids_map]
  exact wots_probed_driver_avoids target previous
    (sessionConfigAt cfg (wotsGameSeed publicSeed, nodeBlock root))
    (node_block_length _) (node_block_length _)
    (adversary (wotsGameSeed publicSeed) (nodeBlock root)) qr qs

theorem wots_probed_game_budget (target : WotsCutTarget) (previous : Randomizer)
    (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) :
    SelectedBudget (variableCandidate (publicDecode nodeQueryDecode) fixedNodeCandidates)
      (redactOpening (wotsProbedGameOpening target previous cfg publicSeed adversary qr qs))
      (155135 + (qr + qs * 364076 + 361)) := by
  apply opening_selected_bind _ _ _ 155135 (qr + qs * 364076 + 361)
    (wots_subtree_root_opening_budget (wotsGameSeed publicSeed) target previous (.inr 0))
  intro root
  rw [redact_opening_mapReturn, selectedBudget_mapReturn]
  exact wots_probed_driver_budget target previous
    (sessionConfigAt cfg (wotsGameSeed publicSeed, nodeBlock root))
    (adversary (wotsGameSeed publicSeed) (nodeBlock root)) qr qs

theorem wots_probed_game_opened (target : WotsCutTarget) (previous : Randomizer)
    (secret : Digest) (cfg : C10SessionConfig) (publicSeed : Digest) {fuel : ℕ}
    (adversary : C10Adversary fuel) (qr qs : ℕ) (table : Memo WotsQuery Digest)
    (cached : table (wotsCutIncoming (wotsGameSeed publicSeed) target previous) = some secret)
    (out : OpeningOutput WotsQuery Digest C10ProbedGame)
    (supported : out ∈ (evalOpening digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target)
      randomizerOfDigest secret (wotsProbedGameOpening target previous cfg publicSeed adversary qr qs)
      table false).support) (opened : out.opened = true) :
    WotsReturned target (sessionConfigAt cfg out.value.1.key) out.value.1.driver.session.exposures out.cache ∨
      wotsCutIncoming (wotsGameSeed publicSeed) target previous ∈ c10ProbeQueries out.value := by
  rw [wotsProbedGameOpening, eval_opening_bind, PMF.mem_support_bind_iff] at supported
  obtain ⟨root, rootSupport, supported⟩ := supported
  rw [eval_opening_mapReturn, PMF.mem_support_map_iff] at supported
  obtain ⟨driver, driverSupport, rfl⟩ := supported
  have flag := opening_sealed_flag digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target)
    randomizerOfDigest secret (wotsCutIncoming (wotsGameSeed publicSeed) target previous) _
    (wots_subtree_root_opening_sealed (wotsGameSeed publicSeed) target previous (.inr 0))
    table false root rootSupport
  have stillCached := eval_opening_preserves digestDraw (wotsCutCommit (wotsGameSeed publicSeed) target)
    randomizerOfDigest secret _ table false (wotsCutIncoming (wotsGameSeed publicSeed) target previous)
    secret cached root rootSupport
  rw [flag] at driverSupport
  exact wots_probed_driver_opened target previous secret
    (sessionConfigAt cfg (wotsGameSeed publicSeed, nodeBlock root.value))
    (node_block_length _) (node_block_length _)
    (adversary (wotsGameSeed publicSeed) (nodeBlock root.value)) qr qs
    root.cache stillCached driver driverSupport opened

end
end C10Probability
