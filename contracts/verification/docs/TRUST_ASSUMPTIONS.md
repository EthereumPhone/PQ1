# Trust Assumptions — SPHINCS+C10 PQSmartWallet Formal Verification

This document is the **single, authoritative inventory** of everything
that lives in the TCB of the SphincsCVerify formal-verification stack.
It follows the same structure as Verity's
[`TRUST_ASSUMPTIONS.md`](https://github.com/lfglabs-dev/verity/blob/main/TRUST_ASSUMPTIONS.md):
every item is a named, scoped assumption that someone reading the
proofs needs to accept (or independently discharge) for the end-to-end
guarantee to hold on a deployed Ethereum chain.

Mirrors and elaborates `docs/how_to_math_proof_secureness.md` §§ 1.2,
2.4, 4.8, 5.4.

---

## TCB Layer 1: Lean Kernel & Compiler Toolchain

| Item | Scope | Mitigation |
|---|---|---|
| **Lean 4 kernel** (version pinned in `lean-toolchain`) | Universal: every theorem in this project is checked by it. | Small, well-trusted, kernel-only-checking implementation; same trust class as every Lean 4 verification project. |
| **mathlib** (specific revision pinned in `lakefile.toml`) | Library used for `decide`, `Vector`, basic arithmetic lemmas. | Open-source, peer-reviewed, used by hundreds of formalisations. |

We do not currently rely on any unverified Lean tactic or
`metaprogramming` macro that could silently desynchronise the spec
from what is proven (compare with Verity's `verity_contract` macro
elaborator — we have no analogue here because we *do not* author the
Solidity contract in Lean; we model it).

## TCB Layer 2: Smart-Contract Compilation

| Item | Scope | Mitigation |
|---|---|---|
| **solc 0.8.28** | Translates `*.sol` → Yul → EVM bytecode for the deployed contracts (`PQSmartWallet`, `PQMultiOwnable`, `PQSmartWalletFactory`, `SPHINCsC10Asm`). | (1) Foundry pins `solc 0.8.28` via `foundry.toml`; CI checks this. (2) The `solidityVerifier_compiles_correctly` axiom in `Bridge/Refinement.lean` records the assumption explicitly. (3) Future engagement: Verity-style verified EDSL→Yul→bytecode pipeline. |
| **Foundry forge** | Test runner and broadcast tool — used only at *test time* and *deployment time*; not on the hot path of any deployed proxy. | Out-of-band: only its output (the deployed bytecode at the impl address) matters; that bytecode is then trusted via `solidityVerifier_compiles_correctly`. |
| **Yul→bytecode pass** | The final step of solc. Not separately modelled in this project. | Same as solc trust assumption. |

## TCB Layer 3: EVM and Consensus Client

| Item | Scope | Mitigation |
|---|---|---|
| **EVM semantics** (Cancun for Eth-mainnet target) | The mathematical specification of every opcode. Encoded in `evm_bytecode_executes_correctly`. | We do not formally model the EVM in this project — that is the KEVM / Dafny-EVM / EVMYulLean territory. Cross-check via Foundry tests and on-chain replay. |
| **SHA-256 precompile (`0x02`) — FIPS 180-4 compliance** | The verifier issues thousands of `staticcall(0x02, ...)` per signature verification. Correct execution = SHA-256 per FIPS 180-4. | `precompile_0x02_is_FIPS_180_4` axiom records the assumption. Geth/reth/erigon test vectors validate this empirically. |
| **`keccak256` precompile** | Used by `keccak256(initCode)` in CREATE2 address computation and by Solidity's `bytes4` selector / `bytes32` slot computations. | Same trust class as SHA-256 precompile. |
| **Gas semantics** | Not modelled; the proofs say nothing about gas use. | The contract's high gas cost (≥ 4008-byte calldata signature, 1000s of SHA-256 precompile calls) is a separate engineering concern. Foundry differential tests bound it empirically. See `docs/how_to_math_proof_secureness.md` § 4.6. |

## TCB Layer 4: SPHINCS+C10 Cryptographic Assumptions

| Item | Scope | Mitigation |
|---|---|---|
| **SHA-256 SM-DT-TCR** | Tweakable hash `F(seed, ADRS, x) = sha256(seed ‖ ADRS ‖ x)[0..16]` is single-function multi-target distinct-tweak target-collision-resistant. | Best-current-knowledge cryptanalysis: no attack below `2^128 / Q` queries. `Crypto/Assumptions.lean::SM_DT_TCR_F`. |
| **SHA-256 ITSR** | Interleaved Target Subset Resilience on FORS roots compression. Central to the tight Barbosa et al. bound. | `Crypto/Assumptions.lean::ITSR_F`. Cited from Barbosa et al. ASIACRYPT 2024. |
| **SHA-256 as random oracle on `H_msg`** | The message hash `H_msg(seed, root, R, m)` is modelled as a random oracle. | `Crypto/Assumptions.lean::hMsg_random_oracle`. Standard assumption; underlies the tight SPHINCS+ bound. |
| **EUF-CMA bound for SPHINCS+C10** | The composed bound `Adv ≤ ε(A) + Q · 2^-128` for any PPT adversary `A` making at most `Q` signing queries. | Axiomatised via `Crypto/EUFCMA.lean::EUF_CMA_SPHINCSplusC`. To eliminate: extend Barbosa et al.'s EasyCrypt to SPHINCS+C (multi-person-year). |
| **SHA-256 collision resistance** | Used by `factorySig` digest (which is SHA-256 of `(DOMAIN, chainId, slot0PkSeed, slot0PkRoot)`) and by `keccak256`-derived storage-slot anti-collision. | Standard 256-bit collision-resistance; well-cryptanalysed. |

## TCB Layer 5: Wallet-Specific Trust

| Item | Scope | Mitigation |
|---|---|---|
| **`PqsignerProto` constants** | The auto-generated constants (`C10_SIG_LEN`, `OWNER_BYTES_LEN`, `MAX_BOOTSTRAP_USES`, `MAX_SLOT_USES`, `FACTORY_ADD_SLOT_DOMAIN`) are sourced from `proto/src/lib.rs` via `cargo run -p pqsigner-xtask -- gen-solidity-constants`. | CI diff-checks the generated `PqsignerProto.sol` against the canonical Rust constants on every PR. |
| **EntryPoint v0.6** | The contract is permanently bound to `0x5FF137D4b0FDCD49DcA30c7CF57E578a026d2789` on every chain (CLAUDE.md non-negotiable: no v0.7/v0.8 migration). | Compile-time immutable in `PQSmartWallet`'s constructor. Drift would change the CREATE2 init-code hash and break cross-chain address stability. |
| **`PQSmartWalletFactory` address per chain** | The factory is expected to live at the same address on every target chain via a singleton-deployer pattern (Safe-style). | Out-of-band: confirmed via `getAddress` on each chain after deployment. |
| **Coinbase Smart Wallet ancestry** | We forked `CoinbaseSmartWallet.sol` and stripped non-PQ paths. Anything we did NOT modify inherits Coinbase's audit history. | The diff is reviewed by Coinbase Smart Wallet auditors as part of any production deployment. |
| **ERC-7201 storage slot** | `PQMultiOwnable` uses `keccak256(...)` to derive a non-colliding storage slot. | Derived by `keccak256(abi.encode(uint256(keccak256("pqsigner.storage.PQMultiOwnable")) - 1)) & ~bytes32(uint256(0xff))`. Compile-time constant. |
| **Solady ERC1271** | Inherited base for EIP-1271 + EIP-712 nested wrapping + ERC-6492 unwrap. | Solady is widely audited; we override only `_domainNameAndVersion`, `_erc1271Signer`, `_erc1271IsValidSignatureNowCalldata`. |

## TCB Layer 6: Out-of-Scope (explicitly *not* in TCB)

Things the project deliberately does not address, listed so they don't
get silently inherited:

* **Front-end and key management**: The user's mnemonic / PIN / SE
  binding lives in the hardware wallet firmware (`secure/`), not in
  this verification. Compromised UX or seed-loss is outside scope.
* **MEV / bundler griefing**: A malicious bundler can withhold a UserOp
  but cannot forge one. Outside the scope of "non-bypass."
* **Censorship**: If a chain censors a UserOp, the wallet's invariants
  still hold; the user simply cannot transact on that chain.
* **Phantom proxies on other chains**: Anyone can pre-fund the CREATE2
  address on chain X. Our `createAccount` squat-defence prevents an
  attacker from deploying *the* proxy at that address with attacker
  control — pre-funding is fine.
* **State-rent / future EIP-7702-style account abstraction migration**:
  EntryPoint v0.6 is the frozen target.
* **Side-channel attacks against firmware signing**: Outside this
  project; see `secure/src/shuffle.rs` (F-16 DPA defence) and the OPTIGA
  Shielded Connection.

---

## Summary

The end-to-end statement of trust:

> *Given* a Lean kernel that checks proofs correctly, solc 0.8.28 that
> compiles correctly, an EVM consensus client that executes per spec,
> a SHA-256 precompile that implements FIPS 180-4, and the cited
> Barbosa/Hülsing line of SPHINCS+ cryptographic assumptions,
> **then** `SphincsCVerify` proves:
>
> * The Lean reference verifier `Spec.Signature.verify` is functionally
>   correct (theorem `verify_signs` in `Spec/Theorems.lean`).
> * The structured verifier and the offset-indexed Yul-shaped verifier
>   produce the same result (theorem `verifyRefined_eq_spec` in
>   `Verifier/Equivalence.lean`, modulo the section-lemma TODOs).
> * `PQSmartWallet.validateUserOp` only succeeds via the verifier
>   (theorem `validateSignature_only_via_verify` in
>   `Wallet/Invariants.lean`).
> * The bootstrap key is unremovable; the combined slot cap is an
>   inductive invariant; the CREATE2 address depends only on
>   `(masterPkSeed, masterPkRoot)`.

The unprovable parts (EUF-CMA, deployed bytecode equivalence, gas) are
named axioms with explicit citations and a clear path to eliminating
each one if the engagement budget grows.
