# SPHINCS+C10 Verifier — Formal Verification (Lean 4)

This directory mechanises the verification of
`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`, the
SPHINCS+C10 cryptographic verifier contract. The playbook is at
[`../../docs/how_to_math_proof_secureness.md`](../../docs/how_to_math_proof_secureness.md);
the phased plan is at
[`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md).

**Scope.** Verifier only. The wallet contracts and the hardware-wallet
firmware are out of scope; see [`../README.md`](../README.md).

## Layout

```
SphincsCVerify/
├── Spec/              -- Pure declarative model of SPHINCS+C10 + SHA-256 + ADRS
│   ├── Params.lean    -- C10 parameters (n=16, h=18, d=2, a=11, k=13, w=8, l=43, T=205)
│   ├── Bytes.lean     -- ByteVec, byte-array helpers
│   ├── Hash.lean      -- sha256 (opaque pre-Phase 2; def post) + tweakable hashes
│   ├── Adrs.lean      -- 32-byte ADRS construction (matches Rust + Yul)
│   ├── Wots.lean      -- WOTS+C sign/verify spec
│   ├── Fors.lean      -- FORS+C with forced-zero last index
│   ├── Hypertree.lean -- D=2 hypertree
│   ├── Signature.lean -- Top-level verify + 4008-byte layout
│   ├── Signer.lean    -- Reference signer (placeholder pre-Phase 3; full post)
│   └── Theorems.lean  -- Functional-correctness theorems
├── Verifier/
│   ├── Refined.lean        -- Offset-indexed verifier (Yul shape)
│   └── Equivalence.lean    -- Refined ≡ Spec (closed in Phase 6)
├── Bridge/
│   ├── SolidityVerifier.lean -- Yul-level model of SPHINCsC10Asm
│   └── Refinement.lean       -- Lean ↔ Solidity ↔ EVM bridge (3 TCB axioms)
├── Crypto/
│   ├── Assumptions.lean   -- SHA-256 SM-TCR / ITSR / ROM axioms
│   └── EUFCMA.lean        -- EUF-CMA axiom (cited)
├── Util/
│   ├── Bits.lean          -- read_bits_le, base-w decoding, target-sum
│   └── ByteVec.lean       -- ByteVec lemmas
└── Wallet/                -- LEGACY, OUT OF SCOPE. May be removed.
```

## How to build

```bash
elan toolchain install $(cat lean-toolchain)
lake update
lake build
```

This type-checks every module. A clean build means every theorem the
project claims to prove is checked by the Lean kernel.

```bash
lake env lean --run scripts/check_no_sorry.lean   # Audit `sorry`s
lake env lean --run scripts/dump_axioms.lean      # Audit `axiom`s
```

`sorry` is permitted only in the locations enumerated in
[`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md);
the audit script fails on any uncovered occurrence.

## What this gives you (after the phased plan completes)

After all seven phases in
[`../docs/OPEN_PROOF_OBLIGATIONS.md`](../docs/OPEN_PROOF_OBLIGATIONS.md):

1. The reference verifier accepts every signature produced by the
   reference signer (`Spec/Theorems.lean::verify_signs`).
2. The reference verifier rejects every signature with wrong length,
   nonzero last FORS index, or WOTS+C target-sum violation
   (`Spec/Theorems.lean::verify_rejects_*`).
3. The offset-indexed verifier (Yul shape) is extensionally equal to
   the structured spec verifier
   (`Verifier/Equivalence.lean::verifyRefined_eq_spec`).
4. The Yul model is byte-identical to the offset-indexed verifier
   (`Bridge/SolidityVerifier.lean::yul_eq_refined`, already closed).
5. Modulo the three named TCB axioms, the deployed EVM bytecode
   refines the Lean spec
   (`Bridge/Refinement.lean::deployed_verifier_refines_spec`).
6. Modulo the four cited cryptographic axioms, accepting an
   unknown-provenance signature implies SPHINCS+C10 EUF-CMA forgery
   (`Crypto/EUFCMA.lean`).

What this does **NOT** give you, by design:

- **SPHINCS+C10 EUF-CMA security**: assumed under SHA-256 SM-TCR +
  ROM. To remove, extend the Barbosa et al. EasyCrypt development.
- **`solc 0.8.28` codegen correctness**: in the TCB. To remove,
  Verity-style rewrite of `SPHINCsC10Asm` in a verified EDSL.
- **EVM consensus / SHA-256 precompile (`0x02`) implementation**: in
  the TCB.
- **Gas behaviour and DoS resistance**: covered by Foundry
  differential testing.
- **Wallet-contract invariants** (cap monotonicity, non-bypass,
  CREATE2 determinism, squat-defence): out of scope. A separate
  engagement would add `SphincsCVerify/Wallet/` proofs on top of the
  proven verifier.

See [`../docs/TRUST_ASSUMPTIONS.md`](../docs/TRUST_ASSUMPTIONS.md) for
the complete trust report and [`../docs/AXIOMS.md`](../docs/AXIOMS.md)
for the explicit `axiom` inventory.
