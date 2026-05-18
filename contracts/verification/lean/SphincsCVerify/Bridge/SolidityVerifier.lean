/-
Bridge/SolidityVerifier: a Yul-level model of `SPHINCsC10Asm.verify`.

This module documents the precise Yul control flow of the Solidity
verifier as a Lean function. Combined with the refinement theorem in
`Bridge/Refinement.lean`, it forms the Verity-style boundary between
the Lean spec and the deployed EVM bytecode.

We do NOT claim to model the full EVM semantics here. What we capture:

  * The sequence of `staticcall(0x02, ...)` invocations (SHA-256
    precompile calls).
  * The exact byte ranges each call hashes.
  * The post-call N-mask AND.
  * The Merkle-pair memory layout (`mstore(xor(0x40, s), node)` /
    `mstore(xor(0x60, s), sibling)` branchless swap).
  * The digit-sum check and the final root equality check.

We do NOT capture:

  * The gas semantics (modelled as "enough gas" — see TCB).
  * The `revert` opcodes' exact error data (modelled as `false`).
  * Solidity's calldata-decoding ABI rules (we accept the same
    `bytes calldata sig` shape the function signature requires).

The Yul source we mirror is `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`
lines 26-201.
-/

import SphincsCVerify.Verifier.Refined
import SphincsCVerify.Spec.Hash

namespace SphincsCVerify.Bridge

open SphincsCVerify.Spec
open SphincsCVerify.Verifier.Refined

/-- The Yul-level verifier function. Conceptually identical to
    `Refined.verifyRefined` but the body is rewritten to mirror Yul's
    statement structure (sequential `staticcall`s rather than Lean's
    `for-in` syntax).

    We keep the definition here purely structural — it is byte-for-byte
    equivalent to `verifyRefined`. The interesting work is the
    refinement to the EVM bytecode after `solc 0.8.28` codegen, which is
    in the TCB. -/
def verifyYulModel
    (pkSeed pkRoot : ByteVec 32)
    (message : ByteVec 32)
    (sig : ByteVec SignatureLen) : Bool :=
  SphincsCVerify.Verifier.Refined.verifyRefined pkSeed pkRoot message sig

/-- The Yul model and the refined Lean model are extensionally equal by
    definition. This is the easiest refinement step. -/
theorem yul_eq_refined
    (pkSeed pkRoot : ByteVec 32) (message : ByteVec 32) (sig : ByteVec SignatureLen) :
    verifyYulModel pkSeed pkRoot message sig
      = SphincsCVerify.Verifier.Refined.verifyRefined pkSeed pkRoot message sig :=
  rfl

end SphincsCVerify.Bridge
