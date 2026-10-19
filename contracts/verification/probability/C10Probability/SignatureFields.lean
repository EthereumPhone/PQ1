import C10Probability.ByteCodecBlocks
import C10Probability.C10Access

/-! Fixed-size signature fields retain all u32 counters and every node value.
Their correspondence with the existing structured model requires exactly its
existing well-formedness predicate, with no acceptance or freshness premise. -/
namespace C10Probability
noncomputable section

def codecListFields {α : Type*} {n : ℕ} (values : List α) (width : values.length = n) :
    Fin n → α := fun i => values.get ⟨i.val, by omega⟩

theorem codec_list_fields_mem {α : Type*} {n : ℕ} (values : List α)
    (width : values.length = n) (i : Fin n) : codecListFields values width i ∈ values := by
  exact List.get_mem _ _

theorem codec_list_fields_roundtrip {α : Type*} {n : ℕ} (values : List α)
    (width : values.length = n) : List.ofFn (codecListFields values width) = values := by
  apply List.ext_getElem
  · simp only [List.length_ofFn, width]
  intro i hi hj
  simp only [List.getElem_ofFn, codecListFields, List.get_eq_getElem]

theorem codec_list_fields_ofFn {α : Type*} {n : ℕ} (values : Fin n → α)
    (width : (List.ofFn values).length = n) :
    codecListFields (List.ofFn values) width = values := by
  funext i
  simp only [codecListFields, List.get_eq_getElem, List.getElem_ofFn]

abbrev WireLayer := WotsSigma × Counter × (Fin 9 → Randomizer)
abbrev WireSignature := Randomizer × (Fin 13 → Randomizer) ×
  (Fin 12 → Fin 11 → Randomizer) × (Fin 2 → WireLayer)

def wireLayerToStructured (fields : WireLayer) : LayerSignature :=
  ⟨fields.1, fields.2.1.val, List.ofFn fields.2.2⟩

theorem wire_layer_shape (fields : WireLayer) :
    LayerSignatureWellFormed (wireLayerToStructured fields) := by
  exact ⟨fields.2.1.isLt, List.length_ofFn⟩

def wireLayerFromStructured (sig : LayerSignature) (shape : LayerSignatureWellFormed sig) :
    WireLayer := (sig.sigma, ⟨sig.count, shape.1⟩, codecListFields sig.auth shape.2)

theorem wire_layer_structured_roundtrip (sig : LayerSignature)
    (shape : LayerSignatureWellFormed sig) :
    wireLayerToStructured (wireLayerFromStructured sig shape) = sig := by
  simp only [wireLayerFromStructured, wireLayerToStructured, codec_list_fields_roundtrip]

theorem wire_layer_fields_roundtrip (fields : WireLayer)
    (shape : LayerSignatureWellFormed (wireLayerToStructured fields)) :
    wireLayerFromStructured (wireLayerToStructured fields) shape = fields := by
  rcases fields with ⟨sigma, count, auth⟩
  simp only [wireLayerFromStructured, wireLayerToStructured, codec_list_fields_ofFn]

def wireSignatureToStructured (fields : WireSignature) : C10Signature :=
  ⟨fields.1, List.ofFn fields.2.1, List.ofFn (fun t => List.ofFn (fields.2.2.1 t)),
    List.ofFn (fun l => wireLayerToStructured (fields.2.2.2 l))⟩

theorem wire_signature_shape (fields : WireSignature) :
    C10SignatureWellFormed (wireSignatureToStructured fields) := by
  simp [wireSignatureToStructured, C10SignatureWellFormed, wire_layer_shape]

def wireSignatureFromStructured (sig : C10Signature) (shape : C10SignatureWellFormed sig) :
    WireSignature :=
  (sig.randomizer, codecListFields sig.secrets shape.1,
    fun t => codecListFields (codecListFields sig.auths shape.2.1 t)
      (shape.2.2.1 _ (codec_list_fields_mem _ _ t)),
    fun l => wireLayerFromStructured (codecListFields sig.layers shape.2.2.2.1 l)
      (shape.2.2.2.2 _ (codec_list_fields_mem _ _ l)))

theorem wire_signature_structured_roundtrip (sig : C10Signature)
    (shape : C10SignatureWellFormed sig) :
    wireSignatureToStructured (wireSignatureFromStructured sig shape) = sig := by
  simp only [wireSignatureFromStructured, wireSignatureToStructured,
    codec_list_fields_roundtrip, wire_layer_structured_roundtrip]

theorem wire_signature_fields_roundtrip (fields : WireSignature)
    (shape : C10SignatureWellFormed (wireSignatureToStructured fields)) :
    wireSignatureFromStructured (wireSignatureToStructured fields) shape = fields := by
  simp only [wireSignatureFromStructured, wireSignatureToStructured,
    codec_list_fields_ofFn, wire_layer_fields_roundtrip]
  refine Prod.ext rfl (Prod.ext rfl (Prod.ext ?_ rfl))
  funext t
  apply List.ofFn_injective
  rw [codec_list_fields_roundtrip]
  exact congrFun (codec_list_fields_ofFn _ _) t

end
end C10Probability
