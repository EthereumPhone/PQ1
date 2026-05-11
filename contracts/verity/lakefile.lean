import Lake
open Lake DSL

-- Verity formal-verification port of the PQSigner smart-wallet contracts.
--
-- Pinned to Verity v0.1.0 (Lean 4.22.0). The dependency line points at
-- the upstream tag rather than a fork — we do not modify Verity itself.
-- If a v0.2.x lands with the prerequisites P1/P2/P3 from
-- `/home/markus/.claude/plans/ok-implement-the-smart-cached-matsumoto.md`,
-- bump this line and re-run `lake build`.
require verity from git
  "https://github.com/lfglabs-dev/verity.git" @ "v0.1.0"

package «pqsigner-verity» where
  -- Verify-on-build: every theorem must be `0 sorry, 0 axioms` outside
  -- the documented trust-boundary axiom block. `make verify-stats`
  -- (Makefile) reproduces Verity's own VERIFICATION_STATUS.md format
  -- and is the single CI gate.
  leanOptions := #[
    ⟨`autoImplicit, false⟩,
    ⟨`relaxedAutoImplicit, false⟩
  ]

@[default_target]
lean_lib «PQSigner» where
  roots := #[
    `PQSigner.Common,
    `PQSigner.PQMultiOwnable,
    `PQSigner.PQSmartWalletFactory,
    `PQSigner.PQSmartWallet,
    `PQSigner.Theorems
  ]
