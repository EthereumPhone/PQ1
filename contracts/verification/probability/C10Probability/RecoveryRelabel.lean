import C10Probability.WotsRecovery
import C10Probability.StateFold

/-! Relabel public WOTS recovery into the surrounding shared oracle without
erasing or restarting its cache. This leaves the original recovery unchanged. -/
namespace C10Probability
noncomputable section

variable {I K L α N : Type*}

theorem chain_program_map (encode : K → L) (input : ℕ → N → K) (project : α → N)
    (start steps : ℕ) (value : N) :
    mapProgram encode (chainProgram input project start steps value) =
      chainProgram (fun step node => encode (input step node)) project start steps value := by
  induction steps generalizing start value with
  | zero => rfl
  | succ steps ih => simp only [chainProgram, mapProgram, ih]

theorem chain_collection_program_map (encode : K → L) (input : I → ℕ → N → K)
    (project : α → N) (starts steps : I → ℕ) (values : I → N) (indices : List I) :
    mapProgram encode (chainCollectionProgram input project starts steps values indices) =
      chainCollectionProgram (fun i step node => encode (input i step node))
        project starts steps values indices := by
  induction indices with
  | nil => rfl
  | cons i rest ih =>
    simp only [chainCollectionProgram, mapProgram_cast, mapProgram_bind,
      chain_program_map, mapProgram_mapReturn, ih]

def wotsRecoverChainsUnder [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (sigma : Fin 43 → Randomizer) : PMF (List Randomizer × Memo K Digest) :=
  chainCollectionLoop digestDraw
    (fun i step node => encode (wotsChainInput seed layer tree kp i.val step node))
    randomizerOfDigest (fun i => (word i).val) (fun i => 7 - (word i).val) sigma wotsIndices table

theorem wots_recover_chains_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (sigma : Fin 43 → Randomizer) :
    evalProgram digestDraw
      (mapProgram encode (wotsRecoverChainsProgram seed layer tree kp word sigma)) table =
      wotsRecoverChainsUnder encode table seed layer tree kp word sigma := by
  have mapped := chain_collection_program_map encode
    (fun i : Fin 43 => wotsChainInput seed layer tree kp i.val) randomizerOfDigest
    (fun i => (word i).val) (fun i => 7 - (word i).val) sigma wotsIndices
  exact (congrArg (fun program => evalProgram digestDraw program table) mapped).trans
    (evalProgram_chainCollection digestDraw
      (fun i step node => encode (wotsChainInput seed layer tree kp i.val step node))
      randomizerOfDigest (fun i => (word i).val) (fun i => 7 - (word i).val)
      sigma wotsIndices table)

theorem wots_accepted_chains_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ)
    (word : WotsWord) (ha : wotsAccept word = true) (sigma : Fin 43 → Randomizer) :
    evalProgram digestDraw
      (mapProgram encode (wotsAcceptedChainsProgram seed layer tree kp word ha sigma)) table =
      wotsRecoverChainsUnder encode table seed layer tree kp word sigma := by
  rw [wotsAcceptedChainsProgram, mapProgram_cast, evalProgram_cast,
    wots_recover_chains_under_eval]

def wotsCompressUnder [DecidableEq K] (encode : ByteKey → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (values : List Randomizer) :
    PMF (Randomizer × Memo K Digest) :=
  (memoQuery digestDraw table (encode (wotsPkInput seed layer tree kp values))).map
    (fun out => (randomizerOfDigest out.1, out.2))

theorem wots_compress_under_eval [DecidableEq K] (encode : ByteKey → K)
    (table : Memo K Digest) (seed : ByteKey) (layer tree kp : ℕ) (values : List Randomizer) :
    evalProgram digestDraw (mapProgram encode (wotsCompressProgram seed layer tree kp values)) table =
      wotsCompressUnder encode table seed layer tree kp values := by rfl

theorem wots_recover_chains_under_id (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (word : WotsWord) (sigma : Fin 43 → Randomizer) :
    wotsRecoverChainsUnder id table seed layer tree kp word sigma =
      wotsRecoverChains table seed layer tree kp word sigma := by rfl

theorem wots_compress_under_id (table : Memo ByteKey Digest) (seed : ByteKey)
    (layer tree kp : ℕ) (values : List Randomizer) :
    wotsCompressUnder id table seed layer tree kp values =
      wotsCompress table seed layer tree kp values := by rfl

end
end C10Probability
