/- §33 axiom-collapse umbrella — the five sphincs-c10 tweakable-hash
   primitives, each proven against its REAL extracted Rust body, with the
   vendored FIPS 180-4 `sha256_pure` as the only hash inside (computable,
   CAVP-pinned, zero axioms). Import this wherever the former handwritten
   `@[step]` hash specs were assumed. -/
import Extracted.HashSpecs.Truncate
import Extracted.HashSpecs.Th
import Extracted.HashSpecs.ThPair
import Extracted.HashSpecs.WotsDigest
import Extracted.HashSpecs.ThMulti
import Extracted.HashSpecs.ChainHash
import Extracted.HashSpecs.HMsg
