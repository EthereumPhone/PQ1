/- Semantic census of freshly compiled Verity modules. No source-token inference. -/
import Lean
import VerityCensusReplay
open Lean

deriving instance BEq for QuotKind, QuotVal, InductiveVal

def declarationOrigin (env : Environment) (name : Name) : String :=
  match env.getModuleIdxFor? name with
  | some i => env.header.moduleNames[i.toNat]!.toString
  | none => "<current>"

def declarationFields (env : Environment) (name : Name) (info : ConstantInfo) :=
  [("name", toJson name.toString), ("module", toJson (declarationOrigin env name)),
   ("type", toJson (repr info.type).pretty),
   ("levels", toJson (info.levelParams.map Name.toString)),
   ("unsafe", toJson info.isUnsafe), ("partial", toJson info.isPartial)]

-- Compare every kernel-relevant field when a candidate shares a stdlib name.
-- Never let a project override masquerade as a trusted imported declaration.
def sameConstant : ConstantInfo → ConstantInfo → Bool
  | .axiomInfo a, .axiomInfo b => a == b
  | .defnInfo a, .defnInfo b => a == b
  | .thmInfo a, .thmInfo b => a == b
  | .opaqueInfo a, .opaqueInfo b => a == b
  | .quotInfo a, .quotInfo b => a == b
  | .inductInfo a, .inductInfo b => a == b
  | .ctorInfo a, .ctorInfo b => a == b
  | .recInfo a, .recInfo b => a == b
  | _, _ => false

def main (args : List String) : IO Unit := do
  initSearchPath (← findSysroot)
  let trusted ← importModules #[{ module := `Lean }] {} 0 (loadExts := false)
  let env ← importModules (args.toArray.map fun s => { module := s.toName }) {} 0 (loadExts := false)
  -- finalizeImport retains each module's original private ModuleData even
  -- though its combined name map can subsume an axiom with a sibling theorem.
  -- Census this union first: no cross-module duplicate or stdlib redeclaration
  -- may disappear into the aggregate environment used for kernel replay.
  let mut own : Std.HashMap Name ConstantInfo := {}
  let mut origins : Std.HashMap Name String := {}
  for module in args do
    let some idx := env.getModuleIdx? module.toName |
      throw <| IO.userError s!"Missing census module {module}"
    let data := env.header.moduleData[idx.toNat]!
    unless data.constNames.size == data.constants.size do
      throw <| IO.userError s!"Malformed module declaration arrays: {module}"
    for name in data.constNames, info in data.constants do
      unless name == info.name do
        throw <| IO.userError s!"Mismatched module declaration name: {module}"
      if origins.contains name then
        throw <| IO.userError s!"Duplicate project declaration {name} in {origins[name]!} and {module}"
      if trusted.contains name then
        throw <| IO.userError s!"Project redeclares trusted declaration {name} in {module}"
      own := own.insert name info
      origins := origins.insert name module
  let mut candidate : Std.HashMap Name ConstantInfo := {}
  for (name, info) in env.constants.toList do
    if let some original := trusted.find? name then
      unless sameConstant original info do
        throw <| IO.userError s!"Candidate changed trusted declaration {name}"
    else
      candidate := candidate.insert name info
  unless own.size == candidate.size do
    throw <| IO.userError "Per-module and aggregate declaration coverage differ"
  for (name, info) in own.toList do
    unless candidate[name]?.any (sameConstant info) do
      throw <| IO.userError s!"Aggregate changed or lost module declaration {name}"
  -- Replay uses Kernel.Environment.addDeclCore, which always checks. Imports
  -- alone do not recheck serialized declarations or undo skipKernelTC.
  discard <| trusted.replay' candidate
  let mut rechecked := 0
  for (_, info) in candidate.toList do
    if !info.isUnsafe && !info.isPartial then rechecked := rechecked + 1
  let mut axioms : Array Json := #[]
  let mut declarations : Array Json := #[]
  for (name, info) in env.constants.toList do
    let fields := (declarationFields env name info).map fun (key, value) =>
      if key == "module" && origins.contains name then (key, toJson origins[name]!) else (key, value)
    if info matches .axiomInfo _ then
      axioms := axioms.push (Json.mkObj fields)
    if candidate.contains name then
      let (_, state) := ((CollectAxioms.collect name).run env).run {}
      declarations := declarations.push (Json.mkObj (fields ++ [
        ("value", toJson (if state.axioms.contains ``sorryAx then
          info.value? (allowOpaque := true) |>.map fun e => (repr e).pretty else none)),
        ("axioms", toJson (state.axioms.map Name.toString))]))
  IO.println (Json.mkObj [("schema_version", toJson (1 : Nat)),
    ("modules", toJson args), ("axioms", Json.arr axioms),
    ("kernel_rechecked_declarations", toJson rechecked),
    ("declarations", Json.arr declarations)]).compress
