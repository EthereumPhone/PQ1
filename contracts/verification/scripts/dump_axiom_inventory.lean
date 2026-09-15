/- Enumerate declarations, not theorem dependency closures. Shared by both pinned Lean versions. -/
import Lean
open Lean

def main (args : List String) : IO Unit := do
  initSearchPath (← findSysroot)
  let env ← importModules (args.toArray.map fun s => { module := s.toName }) {} 0
  let mut rows : Array Json := #[]
  for (name, info) in env.constants.toList do
    if let .axiomInfo value := info then
      let origin := match env.getModuleIdxFor? name with
        | some i => env.header.moduleNames[i.toNat]!.toString
        | none => "<current>"
      rows := rows.push <| Json.mkObj [
        ("name", toJson name.toString), ("module", toJson origin),
        ("type", toJson (repr value.type).pretty),
        ("levels", toJson (value.levelParams.map Name.toString)),
        ("unsafe", toJson value.isUnsafe)]
  IO.println (Json.arr rows).compress
