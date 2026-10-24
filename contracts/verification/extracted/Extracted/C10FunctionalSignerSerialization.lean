/- Compose the actual nonce, forest and two layer writes into common words.
   All source bytes are covered; no cryptographic-validity premise is needed. -/
import Extracted.C10FunctionalSignatureBytes
import Extracted.C10FunctionalForest
import Extracted.SignHeaderSpec

open Aeneas Aeneas.Std Result
open Extracted.C10HashInputBridge Extracted.C10RepresentationBridge C10Representation
open Extracted.C10FunctionalForest Extracted.C10FunctionalSignatureBytes
set_option maxRecDepth 8192
set_option maxHeartbeats 1000000

namespace Extracted.C10FunctionalSignerSerialization
open Equiv

theorem prefix_node (a b : C10Signature) (n : Nat)
    (h : ∀ j : Fin 4008, j.val < n → a.val[j.val]! = b.val[j.val]!)
    (off : Fin 3993) (hb : off.val+16 ≤ n) :
    signatureNode a off = signatureNode b off := by
  apply signatureNode_eq
  intro i
  rw [signatureNode_get b off i]
  exact h ⟨off.val+i.val, by have := off.isLt; have := i.isLt; omega⟩
    (by change off.val+i.val < n; have := i.isLt; omega)

theorem prefix_forest (a b : C10Signature)
    (h : ∀ j : Fin 4008, j.val < 2336 → a.val[j.val]! = b.val[j.val]!) :
    verifierRandomizer a = verifierRandomizer b ∧
      parsedForsSecrets a = parsedForsSecrets b ∧ parsedForsAuth a = parsedForsAuth b := by
  refine ⟨prefix_node a b 2336 h ⟨0,by decide⟩ (by decide), ?_, ?_⟩
  · apply fixedArray_ext
    intro q
    rw [parsedForsSecrets_get, parsedForsSecrets_get]
    apply prefix_node a b 2336 h
    have hq : q.val < 13 := q.isLt
    simp only [forsSecretBytes]
    omega
  · apply fixedArray_ext
    intro q
    apply fixedArray_ext
    intro j
    rw [parsedForsAuth_get, parsedForsAuth_get]
    apply prefix_node a b 2336 h
    have hq : q.val < 12 := q.isLt
    have hj : j.val < 11 := j.isLt
    simp only [forsAuthBytes]
    omega

theorem prefix_first_layer (a b : C10Signature)
    (h : ∀ j : Fin 4008, j.val < 3172 → a.val[j.val]! = b.val[j.val]!) :
    parsedLayerWords a ⟨0,by decide⟩ = parsedLayerWords b ⟨0,by decide⟩ := by
  have hc : parsedLayerChains a ⟨0,by decide⟩ = parsedLayerChains b ⟨0,by decide⟩ := by
    apply fixedArray_ext
    intro j
    rw [parsedLayerChains_get, parsedLayerChains_get]
    apply prefix_node a b 3172 h
    have hj : j.val < 43 := j.isLt
    simp only [layerChainBytes]
    omega
  have hp : parsedLayerAuth a ⟨0,by decide⟩ = parsedLayerAuth b ⟨0,by decide⟩ := by
    apply fixedArray_ext
    intro j
    rw [parsedLayerAuth_get, parsedLayerAuth_get]
    apply prefix_node a b 3172 h
    have hj : j.val < 9 := j.isLt
    simp only [layerAuthBytes]
    omega
  have hn : parsedLayerCount a ⟨0,by decide⟩ = parsedLayerCount b ⟨0,by decide⟩ := by
    apply UScalar.eq_of_val_eq
    rw [parsedLayerCount_val, parsedLayerCount_val]
    simp only [Nat.mul_zero, Nat.add_zero]
    rw [h ⟨3024,by decide⟩ (by decide), h ⟨3025,by decide⟩ (by decide),
      h ⟨3026,by decide⟩ (by decide), h ⟨3027,by decide⟩ (by decide)]
  simp only [parsedLayerWords, hc, hp, hn]

theorem serialized_layer_words (sig : C10Signature) (layer : Fin 2)
    (chains : WotsChains) (count : Std.U32) (path : XmssAuth) :
    parsedLayerWords (serializedLayer sig (2336+836*layer.val) chains count path) layer =
      (nodeWords chains,Int.ofNat count.val,nodeWords path) := by
  have h := serializedLayer_fields sig layer chains count path
  simp only [parsedLayerWords, h.1, h.2.1, h.2.2]
  rfl

def serializedFull (r : Std.Array Std.U8 16#usize) (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (chains0 : WotsChains) (count0 : Std.U32) (auth0 : XmssAuth)
    (chains1 : WotsChains) (count1 : Std.U32) (auth1 : XmssAuth) : C10Signature :=
  serializedLayer (serializedLayer (serializedForest (serializedNonce r) secrets paths)
    2336 chains0 count0 auth0) 3172 chains1 count1 auth1

theorem serialized_full_words (r : Std.Array Std.U8 16#usize) (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (chains0 : WotsChains) (count0 : Std.U32) (auth0 : XmssAuth)
    (chains1 : WotsChains) (count1 : Std.U32) (auth1 : XmssAuth) :
    parsedSignatureWords (serializedFull r secrets paths chains0 count0 auth0 chains1 count1 auth1) =
      (byteInts r.val,nodeWords secrets,pathWords paths,
        [(nodeWords chains0,Int.ofNat count0.val,nodeWords auth0),
         (nodeWords chains1,Int.ofNat count1.val,nodeWords auth1)]) := by
  let forest := serializedForest (serializedNonce r) secrets paths
  let first := serializedLayer forest 2336 chains0 count0 auth0
  let out := serializedLayer first 3172 chains1 count1 auth1
  have hp (j : Fin 4008) (hj : j.val < 3172) : out.val[j.val]! = first.val[j.val]! :=
    serializedLayer_preserves first 3172 chains1 count1 auth1 j (Or.inl hj)
  have hf (j : Fin 4008) (hj : j.val < 2336) : out.val[j.val]! = forest.val[j.val]! := by
    rw [hp j (by omega)]
    exact serializedLayer_preserves forest 2336 chains0 count0 auth0 j (Or.inl hj)
  have hforest := prefix_forest out forest hf
  have hn : verifierRandomizer forest = r := by
    have he := prefix_node forest (serializedNonce r) 16
      (fun j hj => serializedForest_preserves (serializedNonce r) secrets paths j (Or.inl hj))
      ⟨0,by decide⟩ (by decide)
    exact he.trans (serialized_nonce_decodes r)
  have hs := serializedForest_fields (serializedNonce r) secrets paths
  change parsedForsSecrets forest = secrets ∧ parsedForsAuth forest = paths at hs
  have hfirst := (prefix_first_layer out first hp).trans
    (serialized_layer_words forest ⟨0,by decide⟩ chains0 count0 auth0)
  have hsecond := serialized_layer_words first ⟨1,by decide⟩ chains1 count1 auth1
  change parsedLayerWords out ⟨1,by decide⟩ = _ at hsecond
  change parsedSignatureWords out = _
  have layers : List.ofFn (parsedLayerWords out) =
      [parsedLayerWords out ⟨0,by decide⟩,parsedLayerWords out ⟨1,by decide⟩] := rfl
  simp only [parsedSignatureWords, layers, hfirst, hsecond,
    hforest.1, hn, hforest.2.1, hforest.2.2, hs.1, hs.2]
  rfl

theorem serialized_full_bytes (r : Std.Array Std.U8 16#usize) (secrets : ForsSecrets) (paths : ForsAuthPaths)
    (chains0 : WotsChains) (count0 : Std.U32) (auth0 : XmssAuth)
    (chains1 : WotsChains) (count1 : Std.U32) (auth1 : XmssAuth) :
    signatureBytes (serializedFull r secrets paths chains0 count0 auth0 chains1 count1 auth1) =
      signature_bytes (byteInts r.val) (nodeWords secrets) (pathWords paths)
        (nodeWords chains0) (Int.ofNat count0.val) (nodeWords auth0)
        (nodeWords chains1) (Int.ofNat count1.val) (nodeWords auth1) := by
  rw [← parsed_bytes, serialized_full_words]
  rfl

end Extracted.C10FunctionalSignerSerialization
