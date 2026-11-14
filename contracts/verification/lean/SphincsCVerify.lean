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
import SphincsCVerify.Spec.Sha256Impl
import SphincsCVerify.Spec.Hash
import SphincsCVerify.Spec.Wots
import SphincsCVerify.Spec.Fors
import SphincsCVerify.Spec.Hypertree
import SphincsCVerify.Spec.Signature
import SphincsCVerify.Spec.Signer
import SphincsCVerify.Spec.Treehash
import SphincsCVerify.Spec.Theorems
import SphincsCVerify.Spec.SignerPost

-- Stratum A (refined): the offset-indexed verifier the Solidity asm
-- module implements, and the equivalence theorem connecting it to Spec.
import SphincsCVerify.Verifier.Refined
import SphincsCVerify.Verifier.Equivalence
import SphincsCVerify.Verifier.MerkleRoundtrip
import SphincsCVerify.Verifier.WotsRoundtrip
import SphincsCVerify.Verifier.ForsRoundtrip
import SphincsCVerify.Verifier.HypertreeRoundtrip
import SphincsCVerify.Verifier.HonestConsistent

-- Stratum B: ERC-4337 / Coinbase wallet scaffolding
import SphincsCVerify.Wallet.Storage
import SphincsCVerify.Wallet.MultiOwnable
import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Wallet.IsValidSignature
import SphincsCVerify.Wallet.Factory
import SphincsCVerify.Wallet.SphincsDigestSpec
import SphincsCVerify.Wallet.StorageLayout
import SphincsCVerify.Wallet.Execute
import SphincsCVerify.Wallet.Invariants
import SphincsCVerify.Wallet.UpgradeSafety
import SphincsCVerify.Wallet.OffchainBinding
import SphincsCVerify.Wallet.TxFlow

-- Cryptographic axioms (Stratum A continued)
import SphincsCVerify.Crypto.Assumptions
import SphincsCVerify.Crypto.EUFCMA
import SphincsCVerify.Crypto.Quantitative
import SphincsCVerify.Crypto.SplitSecrecy

-- Stratum C: bridge to the Solidity verifier and EntryPoint v0.6
import SphincsCVerify.Bridge.SolidityVerifier
import SphincsCVerify.Bridge.Refinement
import SphincsCVerify.Bridge.EntryPoint

-- Utilities
import SphincsCVerify.Util.Bits
import SphincsCVerify.Util.ByteVec

-- A3.1 deductive-closure track: byte-addressed memory for the C10 interpreter
-- (residual R2) + one fully-characterized hash-pair climb step. See
-- docs/A3_1_CLOSURE_PATH.md.
import SphincsCVerify.Interpreter.Memory
import SphincsCVerify.Interpreter.Climb
import SphincsCVerify.Interpreter.ClimbLoop
import SphincsCVerify.Interpreter.Sha256Bridge
import SphincsCVerify.Interpreter.Yul
import SphincsCVerify.Interpreter.EnvFrame
import SphincsCVerify.Interpreter.C10Program
import SphincsCVerify.Interpreter.Phases
import SphincsCVerify.Interpreter.HypertreePhase
import SphincsCVerify.Interpreter.C10Refine

-- A3.1 R1a in-kernel parser leg (2026-07-04): a Lean Yul-subset parser
-- (YulParse), the pinned byte-exact .sol assembly interior + faithful parse
-- target (C10Source), and the kernel theorems `parse_c10` + elision bridge +
-- `execC10Asm_eq_parsed_source` (C10Parse). Needs the lakefile's
-- `--tstack=32768`. See docs/A3_1_CLOSURE_PATH.md §8.
import SphincsCVerify.Interpreter.YulParse
import SphincsCVerify.Interpreter.C10Source
import SphincsCVerify.Interpreter.C10Parse
import SphincsCVerify.Interpreter.C10HeadSource
import SphincsCVerify.Interpreter.C10HeadProgram
import SphincsCVerify.Interpreter.C10HeadParse
import SphincsCVerify.Interpreter.RelE1
import SphincsCVerify.Interpreter.RelChain
import SphincsCVerify.Interpreter.RelChainControls
import SphincsCVerify.Interpreter.RelWots
import SphincsCVerify.Interpreter.RelMerkle
import SphincsCVerify.Interpreter.RelWotsEntry
import SphincsCVerify.Interpreter.RelSkeleton
import SphincsCVerify.Interpreter.RelMid
import SphincsCVerify.Interpreter.RelHmsg
import SphincsCVerify.Interpreter.RelFors
import SphincsCVerify.Platform.MemoryMap
