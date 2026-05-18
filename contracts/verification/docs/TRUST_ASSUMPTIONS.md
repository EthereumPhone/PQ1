# Trust Assumptions — SPHINCS+C10 Verifier Formal Verification

This document is the **single, authoritative inventory** of everything
that lives in the TCB of the SphincsCVerify formal-verification stack
under the current verifier-only scope.

Mirrors the structure of Verity's
[`TRUST_ASSUMPTIONS.md`](https://github.com/lfglabs-dev/verity/blob/main/TRUST_ASSUMPTIONS.md):
every item is a named, scoped assumption that someone reading the
proofs needs to accept (or independently discharge) for the end-to-end
guarantee to hold on a deployed Ethereum chain.

Mirrors and elaborates the playbook in
[`../../docs/how_to_math_proof_secureness.md`](../../docs/how_to_math_proof_secureness.md)
§§ 1.2, 2.4, 4.8, 5.4.

**Scope.** Verifier only (`contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol`).
The wallet contracts (`PQSmartWallet`, `PQMultiOwnable`,
`PQSmartWalletFactory`) and the hardware-wallet firmware are not in
scope and are intentionally absent from this report. A future
engagement that re-includes them would inherit every verifier-level
trust assumption plus wallet-specific ones — see
[`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md).

---

## TCB Layer 1: Lean Kernel & Compiler Toolchain

| Item | Scope | Mitigation |
|---|---|---|
| **Lean 4 kernel** (version pinned in `lean-toolchain`) | Universal: every theorem is checked by it. | Small, well-trusted, kernel-only-checking implementation; same trust class as every Lean 4 verification project. |
| **mathlib** (revision pinned in `lakefile.toml`) | Used for `decide`, `Vector`, basic arithmetic lemmas. | Open-source, peer-reviewed, used by hundreds of formalisations. |

We do not currently rely on any unverified Lean tactic or
metaprogramming macro that could silently desynchronise the spec from
what is proven — the project models the Solidity verifier, it does not
author the Solidity in Lean (no `verity_contract`-style macro
elaborator surface).

## TCB Layer 2: Smart-Contract Compilation

| Item | Scope | Mitigation |
|---|---|---|
| **solc 0.8.28** | Translates `verifiers/SPHINCsC10Asm.sol` → Yul → EVM bytecode. | (1) Foundry pins `solc 0.8.28` via `foundry.toml`; CI checks the pin. (2) The `solidityVerifier_compiles_correctly` axiom in `Bridge/Refinement.lean` records the assumption explicitly. (3) Future engagement: Verity-style verified EDSL→Yul→bytecode pipeline. |
| **Foundry forge** | Test runner and broadcast tool — used only at test time and deployment time; not on the hot path of any deployed proxy. | Out-of-band: only its output (the deployed bytecode at the verifier address) matters; that bytecode is then trusted via `solidityVerifier_compiles_correctly`. |
| **Yul→bytecode pass** | The final step of solc. Not separately modelled. | Same as solc trust assumption. |

## TCB Layer 3: EVM and Consensus Client

| Item | Scope | Mitigation |
|---|---|---|
| **EVM semantics** (Cancun for Eth-mainnet target) | The mathematical specification of every opcode the verifier uses. Encoded in `evm_bytecode_executes_correctly`. | We do not formally model the EVM — that is the KEVM / Dafny-EVM / EVMYulLean territory. Cross-check via Foundry tests and on-chain replay. |
| **SHA-256 precompile (`0x02`) — FIPS 180-4 compliance** | The verifier issues thousands of `staticcall(0x02, ...)` per signature verification. Correct execution = SHA-256 per FIPS 180-4. | `precompile_0x02_is_FIPS_180_4` axiom records the assumption. Geth/reth/erigon test vectors validate this empirically. |
| **Gas semantics** | Not modelled; the proofs say nothing about gas use. | The verifier's high gas cost (≥ 4008-byte calldata signature, ~1000 SHA-256 precompile calls) is a separate engineering concern. Foundry differential tests bound it empirically. |

## TCB Layer 4: SPHINCS+C10 Cryptographic Assumptions

| Item | Scope | Mitigation |
|---|---|---|
| **SHA-256 SM-DT-TCR** | Tweakable hash `F(seed, ADRS, x) = sha256(seed ‖ ADRS ‖ x)[0..16]` is single-function multi-target distinct-tweak target-collision-resistant. | `Crypto/Assumptions.lean::SM_DT_TCR_F`. Best-current-knowledge cryptanalysis: no attack below `2^128 / Q` queries. |
| **SHA-256 ITSR** | Interleaved Target Subset Resilience on FORS roots compression. Central to the tight Barbosa et al. bound. | `Crypto/Assumptions.lean::ITSR_F`. Cited from Barbosa et al. ASIACRYPT 2024. |
| **SHA-256 as random oracle on `H_msg`** | The message hash `H_msg(seed, root, R, m)` is modelled as a random oracle. | `Crypto/Assumptions.lean::hMsg_random_oracle`. Standard assumption; underlies the tight SPHINCS+ bound. |
| **EUF-CMA bound for SPHINCS+C10** | The composed bound `Adv ≤ ε(A) + Q · 2^-128` for any PPT adversary `A` making at most `Q` signing queries. | Axiomatised via `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC`. To eliminate: extend Barbosa et al.'s EasyCrypt to SPHINCS+C (multi-person-year). |

## TCB Layer 5: Out-of-Scope (explicitly *not* in TCB)

Things this verifier-only project deliberately does not address, listed
so they don't get silently inherited:

* **The wallet contracts** (`PQSmartWallet`, `PQMultiOwnable`,
  `PQSmartWalletFactory`). Not verified. Would need separate Lean
  models + non-bypass / cap-monotonicity / squat-defence proofs.
  Builds on top of the proven verifier as a black-box hypothesis.
* **The hardware-wallet firmware** (`secure/`, `nonsecure/`, workspace
  crates under `sphincs-c10/`, `domain/`, …). Out of scope entirely.
* **`PqsignerProto` constant generation** (used by the wallet, not the
  verifier). Out of scope.
* **EntryPoint v0.6 binding**. Out of scope (wallet-level concern).
* **Gas / DoS resistance**. Covered by Foundry differential testing,
  not by these proofs.
* **Front-end and key management**. Lives in firmware; not in this
  verification.
* **MEV / bundler griefing**. Outside non-bypass scope.
* **Side-channel attacks against firmware signing**. Outside this
  project.

---

## Summary

The end-to-end statement of trust at full completion of the phased plan
in [`OPEN_PROOF_OBLIGATIONS.md`](OPEN_PROOF_OBLIGATIONS.md):

> *Given* a Lean kernel that checks proofs correctly, `solc 0.8.28`
> that compiles correctly, an EVM consensus client that executes per
> spec, a SHA-256 precompile that implements FIPS 180-4, and the cited
> Barbosa/Hülsing line of SPHINCS+ cryptographic assumptions,
>
> **then** the deployed `SPHINCsC10Asm.verify(pkSeed, pkRoot, message,
> signature)` is functionally correct (theorem `verify_signs` in
> `Spec/Theorems.lean`), is extensionally equivalent to the structured
> Lean spec (theorem `verifyRefined_eq_spec` in
> `Verifier/Equivalence.lean`), rejects every malformed input (`verify_rejects_*`
> theorems), and accepting an unknown-provenance signature implies
> SPHINCS+C10 EUF-CMA forgery.

The unprovable parts (EUF-CMA, deployed bytecode equivalence, gas) are
named axioms with explicit citations and a clear elimination path. See
[`AXIOMS.md`](AXIOMS.md).
