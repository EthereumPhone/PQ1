/- Execute the actual extracted serializers against independently concatenated
   Rust byte vectors. These cases are correspondence evidence, not a proof of
   the compiler/backend or the complete signer/session. -/
import Extracted.SignForestSerialize
import Extracted.SignLayerSerialize
import Extracted.SignSerializationDiffVectors
namespace SignSerializationDiff
open Aeneas Aeneas.Std Extracted.Equiv

def byte (pattern domain i : Nat) : Std.U8 :=
  ⟨BitVec.ofNat 8 (17*i+29*(i/16)+43*pattern+61*domain)⟩

def initial (pattern : Nat) : C10Signature :=
  ⟨List.ofFn (fun i : Fin 4008 => byte pattern 0 i.val), by rw [List.length_ofFn]; rfl⟩

def node (pattern domain row : Nat) : Std.Array Std.U8 16#usize :=
  ⟨List.ofFn (fun i : Fin 16 => byte pattern domain (16*row+i.val)), by rw [List.length_ofFn]; rfl⟩

def rows (n : Std.Usize) (pattern domain : Nat) : Std.Array (Std.Array Std.U8 16#usize) n :=
  ⟨List.ofFn (fun i : Fin n.val => node pattern domain i.val), by rw [List.length_ofFn]⟩

def paths (pattern : Nat) : ForsAuthPaths :=
  ⟨List.ofFn (fun t : Fin 12 =>
    (⟨List.ofFn (fun h : Fin 11 => node pattern 2 (11*t.val+h.val)), by
      rw [List.length_ofFn]; rfl⟩ : Std.Array (Std.Array Std.U8 16#usize) 11#usize)),
    by rw [List.length_ofFn]; rfl⟩

def hex (sig : C10Signature) : String :=
  String.ofList (sig.val.flatMap (fun b =>
    ["0123456789abcdef".toList[b.val/16]!, "0123456789abcdef".toList[b.val%16]!]))

structure Output where
  forest : String
  forestOffset : Nat
  layer : String
  layerOffset : Nat

def run (v : Vector) : Option Output :=
  if v.pattern > 255 || v.offset+836 > 4008 || v.count ≥ 2^32 then none
  else do
    let sig := initial v.pattern
    let (forest,fo) ← match signerSerializeForest sig (rows 13#usize v.pattern 1) (paths v.pattern) with
      | .ok out => some out
      | _ => none
    let (layer,lo) ← match signerSerializeLayer sig ⟨BitVec.ofNat _ v.offset⟩
        (rows 43#usize v.pattern 3) ⟨BitVec.ofNat 32 v.count⟩ (rows 9#usize v.pattern 4) with
      | .ok out => some out
      | _ => none
    some ⟨hex forest,fo.val,hex layer,lo.val⟩

def agrees (got : Output) (v : Vector) : Bool :=
  got.forest == v.forest && got.layer == v.layer &&
    got.forestOffset == 2336 && got.layerOffset == v.offset+836

def check : IO Unit := do
  unless vectors.length == 8 && (vectors.map (·.count)) ==
      [0,255,256,65535,65536,305419896,2147483648,4294967295] do
    throw (IO.userError "serialization corpus count inventory changed")
  unless (vectors.map (·.offset)) == [0,1,2336,3172,7,2336,3172,3172] do
    throw (IO.userError "serialization corpus offset inventory changed")
  for v in vectors do
    unless v.forest.length == 8016 && v.layer.length == 8016 do
      throw (IO.userError "serialization expected byte width changed")
    let some got := run v | throw (IO.userError "actual serialization failed")
    unless agrees got v do throw (IO.userError s!"serialization mismatch {v.pattern}")
    for altered in [{v with count := v.count ^^^ 16777216}, {v with pattern := v.pattern+1}] do
      let some changed := run altered | throw (IO.userError "valid changed-input serialization failed")
      if agrees changed v then throw (IO.userError "changed high counter byte or fields were ignored")
    for changed in [{v with forest := ""}, {v with layer := ""},
        {v with forest := "0" ++ v.forest}, {v with layer := v.layer ++ "0"}] do
      if agrees got changed then throw (IO.userError "wrong expected layout accepted")
    for malformed in [{v with count := 2^32}, {v with offset := 3173}, {v with pattern := 256}] do
      unless (run malformed).isNone do throw (IO.userError "out-of-domain corpus input accepted")
  let sig := initial 0
  let block := node 0 7 0
  match sphincs_c10.hypertree.write16 sig 3992#usize block with
  | .ok out =>
    unless (signatureNode out ⟨3992,by decide⟩).val == block.val do
      throw (IO.userError "last complete sixteen-byte window mismatch")
  | _ => throw (IO.userError "last complete sixteen-byte write failed")
  match sphincs_c10.hypertree.write16 sig 3993#usize block with
  | .fail _ => pure ()
  | _ => throw (IO.userError "overrunning sixteen-byte write did not fail")
  IO.println "OK: eight full-byte forest/layer serializer cases; four-byte counter and frame boundaries; changed inputs and malformed cases rejected"

#eval check
end SignSerializationDiff
