/-
SphincsCVerify — top-level module that pulls in every sub-namespace so a
plain `import SphincsCVerify` exposes the whole verification project.

The decomposition mirrors §4.1 of `how_to_math_proof_secureness.md`:

  Stratum A: SPHINCS+C10 verifier core
  Stratum B: ERC-4337 / Coinbase wallet scaffolding
  Stratum C: Lean reference ↔ Solidity refinement (partial)

Plus the cryptographic-axiom block (Crypto/) and shared utilities (Util/).
-/

-- Stratum A: pure declarative SPHINCS+C10 spec
import SphincsCVerify.Spec.Params
import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Adrs
import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Wots
import SphincsCVerify.Spec.Fors
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Signer
import SphincsCVerify.Spec.Theorems

-- Stratum A (refined): the offset-indexed verifier the Solidity asm
-- module implements, and the equivalence theorem connecting it to Spec.
import SphincsCVerify.Verifier.Refined
import SphincsCVerify.Verifier.Equivalence

-- Stratum B: ERC-4337 / Coinbase wallet scaffolding
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.Factory
import SphincsCVerify.Wallet.Invariants

-- Cryptographic axioms (Stratum A continued)
import SphincsCVerify.Crypto.Assumptions
import SphincsCVerify.Crypto.EUFCMA

-- Stratum C: bridge to the Solidity verifier
import SphincsCVerify.Bridge.SolidityVerifier
import SphincsCVerify.Bridge.Refinement

-- Utilities
import SphincsCVerify.Util.Bits
import SphincsCVerify.Util.ByteVec
