import Lake
open Lake DSL

-- Verity formal-verification port of the PQSigner smart-wallet contracts.
--
-- Pinned to Verity v0.1.0 (Lean 4.22.0). The dependency line points at
-- the upstream tag rather than a fork — we do not modify Verity itself.
require verity from git
  "https://github.com/lfglabs-dev/verity.git" @ "v0.1.0"

package «pqsigner-verity» where
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩
  ]

-- Part B — Pure-Lean reference implementation of the SPHINCS+C10
-- verifier. This is the buildable, machine-checked deliverable from
-- 2026-05-11. No dependency on the Verity EDSL — uses only Lean stdlib
-- types (Nat, Array UInt8, UInt32, UInt64). The Verity dependency
-- above is kept for future use when Verity v0.2.x lands the Phase-0
-- primitives (precompile.sha256, calldata.read, bitfield ops,
-- memory.scratch) that the on-chain Yul verifier needs. See
-- `docs/handoff-verity-c10-verifier.md` §4 Phase 0 and
-- `docs/verity-v0.1.0-primitive-map.md`.
@[default_target]
lean_lib «Verifier» where
  roots := #[
    `PQSigner.Verifier.Params,
    `PQSigner.Verifier.Address,
    `PQSigner.Verifier.Hash,
    `PQSigner.Verifier.Wots,
    `PQSigner.Verifier.Merkle,
    `PQSigner.Verifier.Fors,
    `PQSigner.Verifier.Hypertree,
    `PQSigner.Verifier.Top
  ]

-- Part A — Aspirational Lean port of the smart-wallet contracts
-- (PQMultiOwnable, PQSmartWalletFactory, PQSmartWallet dispatch).
-- DOES NOT BUILD on Verity v0.1.0: the file series imports modules
-- (`Verity.Prelude`, `Verity.Hash.Sha256`, `Verity.External.Call`,
-- `Verity.Storage.Namespaced`, `Verity.UserOp.V06`, `Verity.Tactic`)
-- that the upstream Verity v0.1.0 does not provide. The files remain
-- in-tree as the spec for what we want Verity v0.2.x+ to support; the
-- 13 theorem statements are the obligations for that future port. See
-- `README.md` §"Part A status".
--
-- Re-enable as a root once Verity v0.2.x ships the primitives.
lean_lib «PartA» where
  srcDir := "PQSigner"
  -- intentionally no roots — keeps files un-built but discoverable.
  globs := #[]
