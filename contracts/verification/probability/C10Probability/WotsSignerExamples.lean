import C10Probability.WotsSigningCharges
import C10Probability.WotsRecoveryExamples

/-! Independent finite byte/order witnesses and complete cached executions.
Cached examples exercise the actual procedures, without freshness assumptions. -/
namespace C10Probability
noncomputable section

set_option maxRecDepth 4096

variable {K : Type*}

theorem state_fold_order :
    stateFoldLoop fairReply (fun _ : Bool => 1)
      (fun i (_ : Bool) => .query i (fun reply => .done reply))
      [false, true] false (fun key => some key) = PMF.pure (true, fun key => some key) := by
  simp only [stateFoldLoop, evalProgram, memoQuery, PMF.pure_bind]

theorem state_fold_accumulated_cache :
    stateFoldLoop (PMF.pure true) (fun _ : Bool => 1)
      (fun i (state : Bool) => .query i (fun reply => .done (state && reply)))
      [false, true] true (fun _ => none) =
      PMF.pure (true, Function.update (Function.update (fun _ => none) false (some true))
        true (some true)) := by
  simp [stateFoldLoop, evalProgram, memoQuery, PMF.pure_bind, PMF.pure_map]

theorem wots_fill_single_position :
    wotsFillLoop id [] 1 2 3 (fun _ => 0) [2] (fun _ => 0) (fun _ => some (2 ^ 128)) =
      PMF.pure (Function.update (fun _ => 0) 2 1, fun _ => some (2 ^ 128)) := by
  simp only [wotsFillLoop, wotsSeedChain, memoQuery, PMF.pure_bind, chainLoop]
  have hp : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
  rw [hp]

theorem wots_private_query_route :
    wotsSeedChain id (fun key => some (match key with
      | .inl _ => (2 ^ 129 : Digest) | .inr _ => 2 ^ 128)) [] 1 2 3 4 0 =
      PMF.pure (1, fun key => some (match key with
        | .inl _ => (2 ^ 129 : Digest) | .inr _ => 2 ^ 128)) := by
  simp only [wotsSeedChain, id_eq, memoQuery, PMF.pure_bind, chainLoop]
  have hp : randomizerOfDigest (2 ^ 128 : Digest) = 1 := by decide +kernel
  rw [hp]

theorem wots_seed_chain_cached [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree kp index steps : ℕ) (digest : Digest) :
    wotsSeedChain encode (fun _ => some digest) seed layer tree kp index steps =
      PMF.pure (randomizerOfDigest digest, fun _ => some digest) := by
  simp only [wotsSeedChain, memoQuery, PMF.pure_bind, chainLoop_constant_cached]

theorem wots_fill_cached [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (steps : Fin 43 → ℕ) (order : List (Fin 43))
    (sigma : WotsSigma) (digest : Digest) :
    wotsFillLoop encode seed layer tree kp steps order sigma (fun _ => some digest) =
      PMF.pure (order.foldl (fun state i => Function.update state i (randomizerOfDigest digest)) sigma,
        fun _ => some digest) := by
  induction order generalizing sigma with
  | nil => rfl
  | cons i rest ih =>
    simp only [wotsFillLoop, wots_seed_chain_cached, PMF.pure_bind, ih, List.foldl_cons]

theorem wots_constant_writes (order : List (Fin 43)) (sigma : WotsSigma)
    (value : Randomizer) (index : Fin 43) :
    (order.foldl (fun state i => Function.update state i value) sigma) index =
      if index ∈ order then value else sigma index := by
  induction order generalizing sigma with
  | nil => simp
  | cons i rest ih =>
    rw [List.foldl_cons, ih]
    by_cases hi : index = i <;> by_cases hr : index ∈ rest <;>
      simp [hi, hr, Function.update_apply]

theorem wots_fill_cached_complete [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (steps : Fin 43 → ℕ) (order : WotsOrder)
    (sigma : WotsSigma) (digest : Digest) :
    wotsFillLoop encode seed layer tree kp steps order.val sigma (fun _ => some digest) =
      PMF.pure ((fun _ => randomizerOfDigest digest), fun _ => some digest) := by
  rw [wots_fill_cached]
  congr 1
  apply Prod.ext
  · funext i
    dsimp only
    rw [wots_constant_writes, if_pos (wots_order_mem order i)]
  · rfl

theorem wots_leaf_cached [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (layer tree kp : ℕ) (digest : Digest) :
    wotsLeaf encode (fun _ => some digest) seed layer tree kp =
      PMF.pure (randomizerOfDigest digest, fun _ => some digest) := by
  have hf := wots_fill_cached_complete encode seed layer tree kp (fun _ => 7)
    wotsIdentityOrder wotsZeroSigma digest
  simp only [wotsIdentityOrder] at hf
  rw [wotsLeaf, hf]
  simp only [PMF.pure_bind, memoQuery, PMF.pure_map]

theorem wots_private_byte_vector :
    wotsPrivateTail 258 (2 ^ 40 + 3) 772 1286 =
      [119,111,116,115,0,0,1,2] ++ List.replicate 26 0 ++
        [1,0,0,0,0,3,0,0,3,4,0,0,5,6] := by
  set_option maxRecDepth 4096 in decide +kernel

theorem wots_private_prefix_vector :
    (prefixedPrivateInput (2 ^ 255) (wotsPrivateTail 1 2 3 4)).take 36 =
      [128] ++ List.replicate 31 0 ++ [119,111,116,115] := by
  set_option maxRecDepth 4096 in decide +kernel

theorem shuffle_block_counter_vector :
    (shuffleBlockInput (List.replicate 32 9) 258).drop 59 = [0,0,1,2] := by
  set_option maxRecDepth 4096 in decide +kernel

theorem shuffle_pair_little_endian : shuffleChoice [1,128] 0 42 = 21 := by decide +kernel

theorem shuffle_pair_high_byte : shuffleChoice [128,1] 0 42 = 0 := by decide +kernel

theorem shuffle_multiply_high_not_modulo : shuffleChoice [255,255] 0 42 = 42 := by decide +kernel

theorem shuffle_swap_positions : shuffleSwap [3,1,4,2] 1 3 = [3,2,4,1] := by decide +kernel

theorem shuffle_tag_ascii : fisherTag.map Fin.val =
    "sphincs-c10-fisher-yates-v1".toUTF8.toList.map UInt8.toNat := by decide +kernel

theorem shuffle_patterned_order :
    (shuffleLoop (List.ofFn (fun i : Fin 128 =>
      (⟨(37 * i.val + 11) % 256, Nat.mod_lt _ (by decide)⟩ : Fin 256)))
      42 0 wotsIndices).map Fin.val =
      [3,29,37,12,38,21,10,18,0,36,27,1,19,42,4,15,30,35,25,23,40,5,33,16,9,32,22,14,6,28,41,11,39,26,17,7,34,24,13,2,31,20,8] := by
  decide +kernel

theorem shuffle_zero_stream_order :
    (wotsShuffleOrder (List.replicate 128 0)).val.map Fin.val =
      ((List.range 42).map (fun i => i + 1)) ++ [0] := by
  set_option maxRecDepth 4096 in decide +kernel

theorem shuffle_max_stream_order :
    (wotsShuffleOrder (List.replicate 128 255)).val = wotsIndices := by
  set_option maxRecDepth 4096 in decide +kernel

theorem shuffle_blocks_cached_order [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (start n : ℕ) (digest : Digest) :
    shuffleBlocks encode seed start n (fun _ => some digest) =
      PMF.pure ((List.replicate n (secretBytes digest)).flatten, fun _ => some digest) := by
  induction n generalizing start with
  | zero => rfl
  | succ n ih =>
    simp only [shuffleBlocks, memoQuery, PMF.pure_bind, ih, PMF.pure_map,
      List.replicate_succ, List.flatten_cons]

theorem shuffle_nonzero_cached :
    wotsShuffle id [1] (fun _ => some 0) =
      PMF.pure (wotsShuffleOrder (List.replicate 128 0), fun _ => some 0) := by
  rw [wotsShuffle, if_neg (by decide), shuffle_blocks_cached_order]
  rw [PMF.pure_map]
  have stream : (List.replicate 4 (secretBytes 0)).flatten = List.replicate 128 0 := by
    set_option maxRecDepth 4096 in decide +kernel
  rw [stream]

theorem shuffle_query_order :
    (traceProgram digestDraw (wotsShuffleProgram id [1]) (fun _ => some 0)).map
      (fun out => out.queries) = PMF.pure
        [shuffleBlockInput [1] 0, shuffleBlockInput [1] 1,
          shuffleBlockInput [1] 2, shuffleBlockInput [1] 3] := by
  simp only [wotsShuffleProgram, show ([1] : ByteKey) ≠ List.replicate 32 0 by decide,
    ↓reduceIte, shuffleBlocksProgram, mapReturnProgram, traceProgram, id_eq,
    memoQuery, PMF.pure_bind, PMF.pure_map]

theorem shuffle_zero_query_trace :
    (traceProgram digestDraw (wotsShuffleProgram id (List.replicate 32 0))
      (fun _ => some 0)).map (fun out => out.queries) = PMF.pure [] := by
  simp only [wotsShuffleProgram, ↓reduceIte, traceProgram, PMF.pure_map]

theorem wots_sign_no_trials [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey) :
    wotsSign encode table seed layer tree kp message shuffle 0 (by decide) =
      PMF.pure (none, table) := by
  simp only [wotsSign, wotsCountUnder, counterSchedule, List.ofFn_zero, List.map_nil,
    memoGrind, PMF.pure_bind, wotsSignAfter]

theorem memoGrind_cached_reject [DecidableEq K] (keys : List K) (start : ℕ)
    (digest : Digest) (accept : Digest → Bool) (ha : accept digest = false) :
    memoGrind digestDraw accept (fun _ => some digest) start keys =
      PMF.pure (none, fun _ => some digest) := by
  induction keys generalizing start with
  | nil => rfl
  | cons key rest ih =>
    simp only [memoGrind, memoQuery, PMF.pure_bind, ha, Bool.false_eq_true, ↓reduceIte, ih]

theorem memoGrind_cached_accept [DecidableEq K] (keys : List K) (start : ℕ)
    (digest : Digest) (accept : Digest → Bool) (hne : keys ≠ []) (ha : accept digest = true) :
    memoGrind digestDraw accept (fun _ => some digest) start keys =
      PMF.pure (some (start, digest), fun _ => some digest) := by
  cases keys with
  | nil => exact False.elim (hne rfl)
  | cons key rest => simp only [memoGrind, memoQuery, PMF.pure_bind, ha, ↓reduceIte]

theorem wots_sign_one_rejected [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (message shuffle : ByteKey) :
    wotsSign encode (fun _ => some (2 ^ 128)) seed layer tree kp message shuffle 1 (by decide) =
      PMF.pure (none, fun _ => some (2 ^ 128)) := by
  rw [wotsSign, wotsCountUnder, memoGrind_cached_reject _ _ _ _ recovery_digest_rejected,
    PMF.pure_bind]
  rfl

theorem wots_sign_one_accepted_cached [DecidableEq K] (encode : WotsQuery → K)
    (seed : ByteKey) (layer tree kp : ℕ) (message : ByteKey) :
    wotsSign encode (fun _ => some recoveryAcceptedDigest) seed layer tree kp message
      (List.replicate 32 0) 1 (by decide) =
      PMF.pure (some ((fun _ => 2 ^ 72), 0), fun _ => some recoveryAcceptedDigest) := by
  have hn : ((counterSchedule (wotsCountStem seed layer tree kp message) 0 1
      (by decide)).map (fun key => encode (.inl key))) ≠ [] := by
    intro he
    have hl := congrArg List.length he
    simp only [List.length_map, counter_schedule_length, List.length_nil] at hl
    omega
  rw [wotsSign, wotsCountUnder, memoGrind_cached_accept _ _ _ _ hn recovery_digest_accepted,
    PMF.pure_bind, wotsSignAfter, wots_shuffle_zero, PMF.pure_bind]
  have hf := wots_fill_cached_complete encode seed layer tree kp
    (fun i => (wotsOfDigest recoveryAcceptedDigest i).val) wotsIdentityOrder wotsZeroSigma
    recoveryAcceptedDigest
  rw [hf, PMF.pure_map, recovery_digest_node]

theorem signing_budget_arithmetic :
    43 + 205 + 4 = 252 ∧ 205 + 4 = 209 ∧ Nat.choose 252 2 + 252 = 31878 := by
  set_option maxRecDepth 4096 in decide +kernel

end
end C10Probability
