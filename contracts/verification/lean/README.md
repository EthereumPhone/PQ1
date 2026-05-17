# SPHINCS+C10 / PQSmartWallet — Formal Verification (Lean 4)

This directory mechanises the verification playbook described in
[`../../docs/how_to_math_proof_secureness.md`](../../docs/how_to_math_proof_secureness.md).
It is structured into three strata, matching §4.1 of that playbook:

| Stratum | Lean module | Verification target |
|---|---|---|
| **A** | `SphincsCVerify/Spec`, `SphincsCVerify/Verifier` | SPHINCS+C10 verifier — functional correctness; cryptographic security as axioms |
| **B** | `SphincsCVerify/Wallet` | `PQSmartWallet` + `PQMultiOwnable` + `PQSmartWalletFactory` — non-bypass, replay, cap monotonicity |
| **C** | `SphincsCVerify/Bridge` | Lean reference ↔ Solidity refinement (Verity-style; partial) |

## Layout

```
SphincsCVerify/
├── Spec/              -- Pure declarative model of SPHINCS+C10 + SHA-256 + ADRS
│   ├── Params.lean    -- C10 parameter set (n=16, h=18, d=2, a=11, k=13, w=8, l=43, T=205)
│   ├── Bytes.lean     -- ByteVec, byte-array helpers
│   ├── Hash.lean      -- Opaque sha256 + tweakable hash primitives (th, th_pair, th_multi, h_msg)
│   ├── Adrs.lean      -- 32-byte ADRS construction (matches Rust + Yul)
│   ├── Wots.lean      -- WOTS+C signing/verification spec
│   ├── Fors.lean      -- FORS+C with forced-zero last index
│   ├── Hypertree.lean -- D=2 hypertree sign/verify
│   └── Signature.lean -- Top-level verify/sign + 4008-byte layout
├── Verifier/
│   ├── Refined.lean   -- Verifier as the Solidity verifier sees it (offset arithmetic)
│   └── Equivalence.lean -- Refined ≡ Spec (refinement lemma)
├── Wallet/
│   ├── Storage.lean   -- ERC-7201 PQMultiOwnableStorage model
│   ├── MultiOwnable.lean -- owner add/remove + cap bumps
│   ├── ValidateUserOp.lean -- the validation routine
│   ├── Factory.lean   -- CREATE2 + squat-defence sig check
│   └── Invariants.lean -- Non-bypass, replay, cap-monotonicity theorems
├── Bridge/
│   ├── SolidityVerifier.lean -- Yul-level model of SPHINCsC10Asm
│   └── Refinement.lean -- Yul model refines the Lean spec
├── Crypto/
│   ├── Assumptions.lean -- SHA-256 SM-TCR / interleaved target-subset-resilience axioms
│   └── EUFCMA.lean    -- EUF-CMA theorem (axiomatised, with citations to Barbosa et al.)
└── Util/
    ├── Bits.lean      -- read_bits_le, base-w decoding, target-sum check
    └── ByteVec.lean   -- ByteVec lemmas
```

## How to build

```bash
elan toolchain install $(cat lean-toolchain)
lake update
lake build
```

This type-checks every module. A clean build means **every theorem the
project claims to prove is checked by the Lean kernel**. The project
ships with **zero `sorry` placeholders in the functional-correctness
chain** (see `lake env lean --run scripts/check_no_sorry.lean`).

`sorry` is only permitted in two clearly-scoped places:

1. `Crypto/EUFCMA.lean` — the cryptographic-security theorem, stated as
   an axiom citing Barbosa et al. ASIACRYPT 2024 + Hülsing PQC2022 (this
   would require extending the Barbosa et al. EasyCrypt development to
   SPHINCS+C, which is out of scope for this engagement; see §3.2 of the
   playbook).
2. `Bridge/Refinement.lean` — bytecode-level refinement of the Solidity
   verifier; this is the Verity-style obligation that requires the
   verified-compilation work described in §1 of the playbook.

Both are tagged with `@[axiomatised_assumption]` and listed in
[`AXIOMS.md`](../docs/AXIOMS.md).

## What this gives you

After `lake build` succeeds you have a Lean-kernel-checked proof that:

1. The reference verifier accepts every signature produced by the
   reference signer.
2. The reference verifier rejects every signature with wrong length,
   indices out of range, target-sum violation, or last-FORS-index ≠ 0.
3. `PQSmartWallet.validateUserOp` returns `SIG_VALIDATION_SUCCESS` only if
   the wrapped C10 signature passes the reference verifier (non-bypass).
4. `bootstrapUses` and `slotUses[i] + offchainSigCount[i]` are monotonic
   and bounded above by their constants — no path resets them.
5. The bootstrap key cannot be removed; only `addOwnerBytes` can be
   reached with `ownerIndex == 0`, and it is callable only by `this`.
6. `isValidSignature` (EIP-1271) rejects `ownerIndex == 0`.
7. The factory's CREATE2 salt is deterministic in `(masterPkSeed, masterPkRoot)`
   alone and the bootstrap sig is required before slot-0 install.

What it does **NOT** give you, by design:

- SPHINCS+C10 EUF-CMA security: assumed under SHA-256 SM-TCR + ROM. To
  remove this assumption, extend the Barbosa et al. EasyCrypt
  development.
- `solc 0.8.28` codegen correctness: in the TCB.
- EVM consensus / SHA-256 precompile (`0x02`) implementation: in the TCB.
- Gas behaviour and DoS resistance: covered by Foundry differential
  testing, not by these proofs.
- Solidity → Yul → bytecode equivalence with the Lean spec: the bridge
  module is partial; full refinement requires Verity-style work.

See [`../docs/TRUST_ASSUMPTIONS.md`](../docs/TRUST_ASSUMPTIONS.md) for
the complete trust report and [`../docs/AXIOMS.md`](../docs/AXIOMS.md)
for the explicit list of `axiom` declarations.
