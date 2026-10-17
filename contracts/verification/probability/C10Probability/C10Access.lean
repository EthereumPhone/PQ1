import C10Probability.C10Sign
import C10Probability.LayerAccess
import C10Probability.ForestAccess

/-! Output shape follows from executed bounded clients, for any starting cache.
The counter domain is proved on successful signatures; arbitrary externally
supplied structured values still require their own well-formedness premise. -/
namespace C10Probability
noncomputable section

variable {K : Type*}

def C10SignatureWellFormed (sig : C10Signature) : Prop :=
  sig.secrets.length = 13 ∧ sig.auths.length = 12 ∧
    (∀ auth ∈ sig.auths, auth.length = 11) ∧ sig.layers.length = 2 ∧
      ∀ layer ∈ sig.layers, LayerSignatureWellFormed layer

theorem hypertree_sign_shape [DecidableEq K] (encode : WotsQuery → K)
    (seed shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32) (steps layer index : ℕ)
    (current : Randomizer) (signatures : List LayerSignature) (table : Memo K Digest)
    (initial : ∀ sig ∈ signatures, LayerSignatureWellFormed sig)
    (out : HypertreeSigned × Memo K Digest)
    (ho : out ∈ (hypertreeSign encode seed shuffle n hn steps layer index current signatures table).support) :
    match out.1 with
    | none => True
    | some result => result.1.length = signatures.length + steps ∧
        ∀ sig ∈ result.1, LayerSignatureWellFormed sig := by
  induction steps generalizing layer index current signatures table out with
  | zero =>
    have he : out = (some (signatures, current), table) := by simpa [hypertreeSign] using ho
    simp only [he, Nat.add_zero]
    exact ⟨trivial, initial⟩
  | succ steps ih =>
    rw [hypertreeSign, PMF.mem_support_bind_iff] at ho
    obtain ⟨signed, hs, ho⟩ := ho
    have shape := layer_sign_signature_bound encode table seed layer
      (hypertreeParent index) (hypertreeLeaf index) current shuffle n hn signed hs
    cases hsig : signed.1 with
    | none =>
      have he : out = (none, signed.2) := by simpa [hsig] using ho
      simp [he]
    | some result =>
      simp only [hsig] at ho shape
      have next : ∀ sig ∈ signatures ++ [result.1], LayerSignatureWellFormed sig := by
        intro sig hmem
        rcases List.mem_append.mp hmem with old | last
        · exact initial sig old
        · simpa only [List.mem_singleton.mp last] using shape
      have bound := ih (layer + 1) (hypertreeParent index) result.2
        (signatures ++ [result.1]) signed.2 next out ho
      cases hout : out.1 with
      | none => trivial
      | some result =>
        simp only [hout, List.length_append, List.length_singleton] at bound ⊢
        exact ⟨by omega, bound.2⟩

theorem c10_finish_signature_shape [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (seed : ByteKey) (randomizer : Randomizer) (digest : Digest)
    (shuffle : ByteKey) (n : ℕ) (hn : n ≤ 2 ^ 32) (out : Option C10Signature × Memo K Digest)
    (ho : out ∈ (c10Finish encode table seed randomizer digest shuffle n hn).support) :
    match out.1 with | none => True | some sig => C10SignatureWellFormed sig := by
  rw [c10Finish, PMF.mem_support_bind_iff] at ho
  obtain ⟨forest, hf, ho⟩ := ho
  have fshape := forest_sign_lengths encode table seed (hypertreeIndex digest) digest shuffle forest hf
  rw [PMF.mem_support_map_iff] at ho
  obtain ⟨signed, hs, rfl⟩ := ho
  have lshape := hypertree_sign_shape encode seed shuffle n hn 2 0 (hypertreeIndex digest)
    forest.1.pk [] forest.2 (by simp) signed hs
  cases hsig : signed.1 with
  | none => simp [c10FinishOutput]
  | some result =>
    simp only [hsig, List.length_nil, Nat.zero_add] at lshape
    simp only [c10FinishOutput, Option.map_some, C10SignatureWellFormed]
    exact ⟨fshape.1, fshape.2.1, fshape.2.2, lshape.1, lshape.2⟩

theorem c10_sign_signature_shape [DecidableEq K] (encode : WotsQuery → K)
    (table : Memo K Digest) (random message seed root shuffle : ByteKey)
    (m n : ℕ) (hm : m ≤ 2 ^ 32) (hn : n ≤ 2 ^ 32) (out : Option C10Signature × Memo K Digest)
    (ho : out ∈ (c10Sign encode table random message seed root shuffle m n hm hn).support) :
    match out.1 with | none => True | some sig => C10SignatureWellFormed sig := by
  rw [c10Sign, PMF.mem_support_bind_iff] at ho
  obtain ⟨found, _, ho⟩ := ho
  cases hfound : found.1 with
  | none =>
    have he : out = (none, found.2) := by simpa [c10SignAfter, hfound] using ho
    simp [he]
  | some result =>
    rw [hfound, c10SignAfter] at ho
    exact c10_finish_signature_shape _ _ _ _ _ _ _ _ out ho

theorem c10_signature_layer_access (sig : C10Signature) (hs : C10SignatureWellFormed sig)
    (layer : ℕ) (hl : layer < 2) :
    layer < sig.layers.length ∧
      LayerSignatureWellFormed ((sig.layers[layer]?).getD emptyLayerSignature) := by
  have hbound : layer < sig.layers.length := by rw [hs.2.2.2.1]; exact hl
  refine ⟨hbound, ?_⟩
  rw [List.getElem?_eq_getElem hbound]
  exact hs.2.2.2.2 _ (List.getElem_mem hbound)

theorem c10_signature_secret_access (sig : C10Signature) (hs : C10SignatureWellFormed sig) :
    12 < sig.secrets.length ∧ ∀ tree : Fin 12, tree.val < sig.auths.length := by
  constructor
  · rw [hs.1]; omega
  · intro tree; rw [hs.2.1]; exact tree.isLt

end
end C10Probability
