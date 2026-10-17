import C10Probability.ForestSign
import C10Probability.ForestRecover

/-! Array sizes and inner authentication lengths persist through actual
computed-order calls and writes. The final compression has all thirteen roots.
Malformed external lists still retain the explicit recovery defaults. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def ForestShape (state : ForestState) : Prop :=
  state.secrets.length = 13 ∧ state.auths.length = 12 ∧ state.roots.length = 13 ∧
    ∀ auth ∈ state.auths, auth.length = 11

theorem empty_forest_shape : ForestShape emptyForestState := by
  simp [ForestShape, emptyForestState]

theorem forest_write_shape (state : ForestState) (tree : ℕ) (out : ForestTreeResult)
    (hs : ForestShape state) (ha : out.auth.length = 11) :
    ForestShape (forestWrite state tree out) := by
  rcases hs with ⟨hsecret, hauth, hroot, hrows⟩
  refine ⟨by simp [forestWrite, hsecret], by simp [forestWrite, hauth],
    by simp [forestWrite, hroot], ?_⟩
  intro auth hmem
  change auth ∈ state.auths.set tree out.auth at hmem
  rcases List.mem_or_eq_of_mem_set hmem with old | same
  · exact hrows auth old
  · simpa only [same] using ha

theorem forest_write_indices (state : ForestState) (tree : Fin 12) (hs : ForestShape state) :
    tree.val < state.secrets.length ∧ tree.val < state.auths.length ∧
      tree.val < state.roots.length := by
  have hi := tree.isLt
  rcases hs with ⟨hsecret, hauth, hroot, _⟩
  omega

theorem forest_fill_shape [DecidableEq K] (encode : WotsQuery → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (order : List (Fin 12))
    (state : ForestState) (table : Memo K Digest) (hs : ForestShape state)
    (out : ForestState × Memo K Digest)
    (ho : out ∈ (forestFillLoop encode seed ht digest order state table).support) :
    ForestShape out.1 := by
  induction order generalizing state table out with
  | nil =>
    have he : out = (state, table) := by simpa [forestFillLoop] using ho
    simpa [he] using hs
  | cons tree rest ih =>
    rw [forestFillLoop, PMF.mem_support_bind_iff] at ho
    obtain ⟨one, hone, ho⟩ := ho
    exact ih _ _ (forest_write_shape state tree.val one.1 hs
      (forest_one_auth_length encode table seed ht tree.val (forestIndex digest tree.val) one hone))
      out ho

theorem forest_sign_lengths [DecidableEq K] (encode : WotsQuery → K) (table : Memo K Digest)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (shuffle : ByteKey)
    (out : ForestOutput × Memo K Digest)
    (ho : out ∈ (forestSign encode table seed ht digest shuffle).support) :
    out.1.secrets.length = 13 ∧ out.1.auths.length = 12 ∧
      ∀ auth ∈ out.1.auths, auth.length = 11 := by
  rw [forestSign, PMF.mem_support_bind_iff] at ho
  obtain ⟨order, _, ho⟩ := ho
  rw [PMF.mem_support_bind_iff] at ho
  obtain ⟨filled, hf, ho⟩ := ho
  rcases forest_fill_shape encode seed ht digest order.1.val emptyForestState order.2
    empty_forest_shape filled hf with ⟨hsecret, hauth, _, hrows⟩
  rw [forestFinish, PMF.mem_support_bind_iff] at ho
  obtain ⟨last, _, ho⟩ := ho
  rw [forestLast, PMF.mem_support_bind_iff] at ho
  obtain ⟨leaf, _, ho⟩ := ho
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨reply, _, rfl⟩ := ho
  exact ⟨by simpa using hsecret, hauth, hrows⟩

theorem forest_finish_compression_width (seed : ByteKey) (ht : ℕ) (state : ForestState)
    (leaf : Randomizer) (hs : seed.length = 32) (hstate : ForestShape state) :
    (forsPkInput seed ht (state.roots.set 12 leaf)).length = 480 := by
  exact fors_pk_input_length seed ht _ hs (by simpa using hstate.2.2.1)

theorem forest_recovery_loop_length [DecidableEq K] (encode : ByteKey → K) (seed : ByteKey)
    (ht : ℕ) (digest : Digest) (secrets : List Randomizer) (auths : List (List Randomizer))
    (indices : List (Fin 12)) (roots : List Randomizer) (table : Memo K Digest)
    (out : List Randomizer × Memo K Digest)
    (ho : out ∈ (forestRecoveryLoop encode seed ht digest secrets auths indices roots table).support) :
    out.1.length = roots.length + indices.length := by
  induction indices generalizing roots table out with
  | nil =>
    have he : out = (roots, table) := by simpa [forestRecoveryLoop] using ho
    simp [he]
  | cons tree rest ih =>
    rw [forestRecoveryLoop, PMF.mem_support_bind_iff] at ho
    obtain ⟨one, _, ho⟩ := ho
    have h := ih (roots ++ [one.1]) one.2 out ho
    simpa only [List.length_append, List.length_cons, List.length_nil, Nat.add_zero, Nat.zero_add,
      Nat.add_assoc, Nat.add_comm, Nat.add_left_comm] using h

theorem forest_recovery_compression_width [DecidableEq K] (encode : ByteKey → K)
    (seed : ByteKey) (ht : ℕ) (digest : Digest) (secrets : List Randomizer)
    (auths : List (List Randomizer)) (table : Memo K Digest)
    (out : List Randomizer × Memo K Digest) (last : Randomizer) (hs : seed.length = 32)
    (ho : out ∈ (forestRecoveryLoop encode seed ht digest secrets auths
      forestTreeIndices [] table).support) :
    (forsPkInput seed ht (out.1 ++ [last])).length = 480 := by
  have h := forest_recovery_loop_length encode seed ht digest secrets auths
    forestTreeIndices [] table out ho
  apply fors_pk_input_length seed ht _ hs
  simp only [List.length_nil, forest_tree_indices_length, Nat.zero_add] at h
  simp [h]

end
end C10Probability
