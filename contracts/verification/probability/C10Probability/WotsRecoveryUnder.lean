import C10Probability.LayerInputs
import C10Probability.RecoveryRelabel

/-! WOTS recovery with public inputs embedded into a surrounding oracle. The
direct procedure retains the complete table through count, chains and final
compression, including rejection. Natural counters use all32 input bytes. -/
namespace C10Probability
noncomputable section

variable {K L : Type*}

def wotsRecoveryUnderProgram (encode : ByteKey → K) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma) (count : ℕ) :
    QueryProgram K Digest Randomizer 98 :=
  .query (encode (wotsRecoverCountInput seed layer tree kp message count))
    (fun digest => mapProgram encode (wotsRecoveryAfter seed layer tree kp sigma digest))

def wotsRecoveryUnder [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) : PMF (Randomizer × Memo K Digest) :=
  (memoQuery digestDraw table (encode (wotsRecoverCountInput seed layer tree kp message count))).bind
    (fun counted => if wotsAccept (wotsOfDigest counted.1) then
      (wotsRecoverChainsUnder encode counted.2 seed layer tree kp (wotsOfDigest counted.1) sigma).bind
        (fun chains => wotsCompressUnder encode chains.2 seed layer tree kp chains.1)
      else PMF.pure (0, counted.2))

theorem wots_recovery_after_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (sigma : WotsSigma) (digest : Digest) :
    evalProgram digestDraw
      (mapProgram encode (wotsRecoveryAfter seed layer tree kp sigma digest)) table =
      if wotsAccept (wotsOfDigest digest) then
        (wotsRecoverChainsUnder encode table seed layer tree kp (wotsOfDigest digest) sigma).bind
          (fun chains => wotsCompressUnder encode chains.2 seed layer tree kp chains.1)
      else PMF.pure (0, table) := by
  by_cases ha : wotsAccept (wotsOfDigest digest) = true
  · simp only [wotsRecoveryAfter, ha, ↓reduceDIte, ↓reduceIte, mapProgram_bind,
      evalProgram_bind, wots_accepted_chains_under_eval, wots_compress_under_eval]
  · simp only [wotsRecoveryAfter, ha, Bool.false_eq_true, ↓reduceDIte, ↓reduceIte,
      mapProgram, evalProgram]

theorem wots_recovery_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : WotsSigma) (count : ℕ) :
    evalProgram digestDraw
      (wotsRecoveryUnderProgram encode seed layer tree kp message sigma count) table =
      wotsRecoveryUnder encode table seed layer tree kp message sigma count := by
  simp only [wotsRecoveryUnderProgram, evalProgram, wots_recovery_after_under_eval,
    wotsRecoveryUnder]

theorem wots_recovery_under_map (encode : K → L) (labels : ByteKey → K)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma)
    (count : ℕ) :
    mapProgram encode (wotsRecoveryUnderProgram labels seed layer tree kp message sigma count) =
      wotsRecoveryUnderProgram (encode ∘ labels) seed layer tree kp message sigma count := by
  simp only [wotsRecoveryUnderProgram, mapProgram, mapProgram_comp, Function.comp_def]

theorem wots_recovery_under_identity (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (message : ByteKey) (sigma : WotsSigma) (count : Counter) :
    wotsRecoveryUnder id table seed layer tree kp message sigma count.val =
      wotsRecovery table seed layer tree kp message sigma count := by
  simp only [wotsRecoveryUnder, wots_recover_counter_input, id_eq,
    wots_recover_chains_under_id, wots_compress_under_id, wotsRecovery]

theorem wots_recovery_under_program_identity (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : WotsSigma) (count : Counter) :
    wotsRecoveryUnderProgram id seed layer tree kp message sigma count.val =
      wotsRecoveryProgram seed layer tree kp message sigma count := by
  simp only [wotsRecoveryUnderProgram, wots_recover_counter_input, id_eq,
    mapProgram_id, wotsRecoveryProgram]

theorem wots_recovery_under_selected (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : WotsSigma) (count : ℕ)
    (hs : seed.length = 32) (hm : message.length = 16) :
    SelectedBudget nodeQuery (wotsRecoveryUnderProgram id seed layer tree kp message sigma count)
      97 := by
  simp only [wotsRecoveryUnderProgram, id_eq, mapProgram_id, SelectedBudget,
    wots_recover_count_excluded _ _ _ _ _ _ hs hm, Bool.false_eq_true, ↓reduceIte]
  exact fun digest => wots_recovery_after_budget seed layer tree kp sigma digest

theorem wots_recovery_under_rejected_cached [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (message : ByteKey) (sigma : WotsSigma) (count : ℕ) (digest : Digest)
    (cached : table (encode (wotsRecoverCountInput seed layer tree kp message count)) = some digest)
    (reject : wotsAccept (wotsOfDigest digest) = false) :
    wotsRecoveryUnder encode table seed layer tree kp message sigma count =
      PMF.pure (0, table) := by
  rw [wotsRecoveryUnder, memoQuery_cached _ _ _ _ cached, PMF.pure_bind]
  simp only [reject, Bool.false_eq_true, ↓reduceIte]

end
end C10Probability
