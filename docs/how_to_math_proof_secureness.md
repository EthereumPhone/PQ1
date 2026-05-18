# Fully Formally Verifying a Post-Quantum (SPHINCS+C) ERC-4337 Smart Wallet on EVM: A Technical Playbook

## Executive Summary

You want **full proof-assistant–level verification** (Lean 4 / Coq / Isabelle, not SMT/BMC) of a Coinbase-Smart-Wallet-derived ERC-4337 account whose only substantive deviation is that signature verification uses **SPHINCS+C target-sum (SHA-256, n=16, h=18, d=2, h′=9, a=11, k=13, w=8, len=43, target_sum=205, simple hash tweaks, 4008-byte signatures)** — a non-NIST, size-optimized SPHINCS+ instance.

The honest answer: **no existing toolchain (LFG Labs' Verity included) is today capable of end-to-end producing a single machine-checked theorem of the form "this deployed EVM bytecode is functionally equivalent to a reference SPHINCS+C verifier AND that verifier is EUF-CMA secure under stated hash assumptions."** Reaching that target requires assembling three independently-maturing pieces of research (Verity-style verified EDSL→Yul compilers, Barbosa/Hülsing-style machine-checked SPHINCS+ proofs in EasyCrypt, and a refinement bridge between them) plus substantial new engineering. A realistic, defensible plan is to *decompose* the goal into:

1. A Lean 4 reference SPHINCS+C verifier with a proven **functional-correctness theorem** ("a signature produced by the reference signer accepts under the reference verifier") and an **EUF-CMA-style security theorem** under modeled hash assumptions.
2. A proof that the **Solidity/Yul implementation refines that Lean reference** (this is what Verity-style frameworks aim at).
3. A separately-proven Lean model of the ERC-4337 / Coinbase-Smart-Wallet scaffolding (nonces, ownership, UUPS upgrade, `validateUserOp`, replay protection, ERC-1271, and — if used — `IAggregator` signature aggregation).

The rest of this report explains how to actually do this, what is and is not achievable today, and where the unavoidable trusted-computing-base (TCB) and axiom boundaries lie.

---

## 1. The LFG Labs / Verity Approach in Detail

### 1.1 What Verity actually is

Verity (`github.com/lfglabs-dev/verity`, mirrored at `github.com/Th0rgal/verity`, web home `veritylang.com` / `lfglabs.dev`) is **a formally verified smart-contract compiler written in Lean 4**. It is not a tool that takes existing Solidity and proves things about it. Instead, it is an **embedded DSL** inside Lean 4 (the `verity_contract` macro) in which you author the contract; specifications are Lean propositions; proofs are Lean tactic scripts checked by the Lean kernel; and a Lean-implemented compiler emits Yul, which `solc` (pinned at 0.8.33) then lowers to EVM bytecode.

Authoring example (from the Verity README):

```lean
verity_contract Counter where
  storage count : Uint256 := slot 0
  function increment () : Unit := do
    let current ← getStorage count
    setStorage count (add current 1)

theorem increment_correct (s : ContractState) :
    let s' := ((increment).run s).snd
    s'.storage 0 = add (s.storage 0) 1 := by rfl
```

The compiler is itself proven correct through three layers, each a Lean theorem:

| Layer | Statement | File / status |
|---|---|---|
| **Layer 1** | EDSL `Contract` monad execution ≡ declarative `CompilationModel` interpretation | `TypedIRCompilerCorrectness.lean` — generic typed-IR core + per-contract bridge theorems for the supported fragment |
| **Layer 2** | `CompilationModel → IR` semantics preserved | `Compiler/Proofs/IRGeneration/Contract.lean` — generic whole-contract theorem for the supported fragment; the former generic body-simulation axiom has been eliminated |
| **Layer 3** | `IR → Yul` preserved | `Compiler/Proofs/YulGeneration/Preservation.lean` — generic statement/function-level preservation; one explicit *theorem hypothesis* (not an axiom) remains for the dispatch bridge; non-payable cases must see word-level zero `msg.value`, and per-case non-wrapping calldata-width guards are explicit |
| **Yul→bytecode** | **Not verified** | trusted external `solc 0.8.33+commit.64118f21`, pin enforced in CI |

As of the most recent `TRUST_ASSUMPTIONS.md` and `AXIOMS.md` we inspected (last updated 2026-05-12 in the repo), Verity reports **0 `sorry` placeholders and 0 documented project-level Lean axioms** across the compiler stack — the last axiom (`solidityMappingSlot_lt_evmModulus`) was eliminated by replacing an opaque FFI keccak with a kernel-computable Keccak engine in `Compiler/Keccak/Sponge.lean`. All 15 low-level EVM arithmetic builtins (`add, sub, mul, div, mod, lt, gt, eq, iszero, and, or, xor, not, shl, shr`) are proven (not assumed) to match EVM wrapping arithmetic at 2^256. The runtime authority for the EndToEnd path is the `lfglabs-dev/EVMYulLean` fork (a 2-commits-ahead, non-semantic fork of `NethermindEth/EVMYulLean`), with 25 proven universal pure bridge theorems and 11 context/env/storage builtin bridge theorems covering the 36 builtin bridge cases.

### 1.2 Verity's published TCB (trusted-but-not-verified parts)

This matters enormously for any production engagement:

1. **`solc` 0.8.33** for Yul→bytecode. CI enforces the pin and Yul-compileability checks.
2. **The `verity_contract` macro elaborator** itself (`Verity/Macro/Translate.lean`) — a Lean metaprogram that translates the surface syntax into both the executable Lean monadic semantics and the `CompilationModel`. A bug here would silently desynchronize what is proven from what is compiled. Mitigated by macro-generated `_semantic_preservation` body-alignment checks and differential Foundry tests, *not* by a proof.
3. **The Lean 4 kernel** (universal assumption for Lean-based verification).
4. **Linked Yul libraries** (e.g., precompile wrappers, Poseidon) — semantics trusted; compiler only validates names/arities/collisions.
5. **`keccak256` as a primitive**: Verity emits a machine-readable trust report and explicit primitive assumption `keccak256_memory_slice_matches_evm` whenever a contract uses `Expr.keccak256` — collision-resistance is the same trust class as Solidity itself.
6. **EVM gas is not modeled** — semantic correctness does **not** imply gas safety. This is critical because a 4008-byte SPHINCS+C signature stresses calldata and memory costs significantly.
7. **`delegatecall`/proxy/UUPS-upgradeability flows are explicitly outside the proof-interpreter model** (tracked as issue #1420, with a `--deny-proxy-upgradeability` flag for fail-closed builds). This is directly relevant: `CoinbaseSmartWallet` is `UUPSUpgradeable`.
8. **External Call Modules (ECMs)** for precompile calls (`0x01 ecrecover, 0x02 sha256, 0x06/0x07/0x08 BN254`, plus typed ERC-20 and ERC-4626 patterns) — each module's `compile` correctness is a trust assumption per module, with axiom aggregation surfaced via `--verbose` and `--trust-report`. The fail-closed flag `--deny-unchecked-dependencies` excludes contracts touching unchecked foreign surfaces.
9. **Local unsafe / refinement obligations** for assembly-shaped boundaries — surfaced in `--trust-report`; `--deny-local-obligations` fails closed on any obligation that remains `assumed` or `unchecked`.

### 1.3 What Verity verifies *today*

The Verity repo currently ships proofs for a small set of contracts (SimpleStorage 20 theorems, Counter 28, SafeCounter 25, Owned 23, OwnedCounter 48, Ledger 33, SimpleToken 61, ERC20 19, ERC721 11, ReentrancyExample 5, plus a CryptoHash linker demo without proofs). **No contract in the verified set approaches the surface area or cryptographic complexity of a SPHINCS+C-verifying ERC-4337 account.** The ABI-level dynamic-type support that landed most recently is `String` for parsing/calldata/returnBytes/events; Solidity-style dynamic string storage layout, dynamic linked externals, dynamic local aliases, and the full `try/catch` surface are still being expanded (issues #1159, #1161). Dynamic-bytes handling sufficient for routine ERC-20 work exists; sustained byte-array operations on a 4008-byte signature with extensive inner SHA-256 chains are *not* on the verified examples.

A separate Verity asset is **`github.com/lfglabs-dev/verity-benchmark`** — a reproducible benchmark scaffold for Verity-based smart-contract verification research. For a serious engagement, contributing your SPHINCS+C wallet (or a stripped-down "verifier-only" variant) to this benchmark is the natural way to ensure long-term reproducibility, regression-testing as Verity itself evolves, and public scrutiny of the trust report.

### 1.4 The Verity paper draft and AI-assisted workflow

LFG Labs advertises a research paper at `lfglabs.dev/papers/verity.pdf` (the PDF returned a permissions error from our fetcher in this session; only the public Verity website, `lfglabs.dev`, GitHub README/AXIOMS/TRUST_ASSUMPTIONS, and `veritylang.com` could be retrieved directly). The methodology described in public materials and the repo is:

- Express the contract in the Lean EDSL → Lean automatically produces both a runnable semantic interpretation and a declarative compilation model.
- Specs and invariants are written in `Verity/Specs/<Name>/Spec.lean` and `Invariants.lean`; proofs in `Contracts/<Name>/Proofs/`.
- Compilation correctness is global (one set of theorems applies to the whole supported fragment), so the per-contract effort is mainly the specification proofs.
- The README explicitly states: "Much of this repository was built with **heavy AI assistance, with every proof machine-checked by Lean regardless of origin**." The thesis is that LLM agents will close the per-property effort gap; until then, Verity is positioned for "high-assurance contracts" rather than as a Certora/Halmos competitor. A `CLAUDE.md` is checked into the repo, signaling that LFG Labs' workflow is built around Anthropic's Claude as a proof-writing co-pilot, with Lean's kernel as the final unconditional authority.

LFG Labs' commercial engagement model (from `lfglabs.dev`) is: translate the client's contract into Lean 4 specs, prove correctness across all execution paths "parallel to your dev cycle," deliver "machine-checkable proofs, a plain-English report, and a Formally Verified credential," with re-verification of contract changes for ≥3 months extendable to 12. They cap engagements at 4 protocols/quarter and offer a refund if they can neither find a bug nor verify the contract.

### 1.5 Limitations relevant to a SPHINCS+C ERC-4337 account

Putting the above together, the gaps Verity would have to close *before* it could fully verify your contract are substantial:

- **You cannot author "the Coinbase Smart Wallet" in Verity's EDSL today** — you would have to re-implement the contract in the EDSL, *then* prove the re-implementation refines a specification. This is the standard Verity workflow but it is **not** "verifying the original Solidity"; it produces a *new*, verified contract intended to replace it.
- UUPS proxy / `delegatecall` upgrade flow is currently outside the proof-interpreter model (#1420). The Coinbase wallet uses UUPSUpgradeable; you would either prove a stripped-down non-upgradeable variant, gate the upgrade path behind a local refinement obligation, or extend Verity itself.
- Heavy byte-array manipulation, in-loop SHA-256 precompile calls, and 4008-byte calldata at WOTS+ chain depth are outside the verified example surface. The SHA-256 (`0x02`) precompile is covered by an ECM, but the semantic correctness of *that* ECM is a trust assumption — and you would be invoking it thousands of times per signature verification.
- The verified-compiler story is the strongest part of Verity. The verified *cryptographic-property* story is essentially absent; Verity does not currently ship any equivalent of the EasyCrypt SPHINCS+ proof, and Lean's mathlib lacks a production-grade SHA-256 spec, ADRS modeling, or hash-based-signature libraries.

---

## 2. Landscape of Full Formal Verification for EVM / Solidity

### 2.1 Proof-assistant-grade EVM semantics (the only path to *full* proofs)

| Project | Logic / framework | Level | Maturity for your task |
|---|---|---|---|
| **KEVM** (Hildenbrandt et al., U. Illinois / Runtime Verification, CSF 2018) | K Framework with reachability-logic prover | EVM bytecode | Most complete formal EVM semantics; passes the 40,683-test EVM stress suite. Used commercially by Runtime Verification for ERC-20 verification and as the engine under **Kontrol** (KEVM-based symbolic execution of Foundry tests). Capable of unbounded proofs but production usage typically uses Kontrol's bounded mode. |
| **eth-isabelle** (Hirai; Amani/Bégel/Bortin/Staples, CPP 2018) | Isabelle/HOL + Lem | EVM bytecode | Sound Hoare-style program logic over basic blocks of straight-line bytecode. Active development effectively paused around Isabelle 2017 era. Good academic foundation; not a production tool. |
| **Dafny-EVM / evm-dafny** (ConsenSys, Cassez/Fuller/Ghale/Pearce/Quiles, FM 2023) | Dafny (Hoare logic + SMT backend) | EVM bytecode | Readable, executable; passes Ethereum common tests; allows pre-/post-condition–style proofs at bytecode level. Dafny is verification-aware but proofs lean on Z3 — so "full proofs" rely on the Dafny soundness chain rather than a small kernel. |
| **Verity** (LFG Labs) | Lean 4 | EDSL → Yul (solc-trusted to bytecode) | Source-level, not pre-existing Solidity. See §1. |
| **Coq EVM efforts** | Coq | various | Multiple research prototypes, none production-scale. The Yoichi Hirai eth-isabelle work has Coq export paths via Lem. |
| **Act** (Ethereum Foundation FV team) | Custom spec language → Coq export + SMT via hevm | Bytecode equivalence | Compiles spec into Pass/Fail claims; the SMT/hevm backend proves bytecode equivalence; the Coq export enables higher-complexity properties. Still small-spec-oriented. |
| **F* / hax** (Cryspen) | F* / Coq / ProVerif | Rust source | Not EVM-targeted, but extremely relevant for the *crypto core*; see §3. |

### 2.2 SMT-based / bounded tools (full disclosure for completeness, not the user's primary target)

- **Certora Prover** — CVL specification language, cloud-based SMT solving. Powerful invariant prover and the de facto industry tool for serious DeFi audits, but **bounded loop unrolling by default** (default loop bound 1, increased by `--loop_iter`). It cannot give true unbounded proofs over arbitrary-depth iteration without manually supplied loop invariants, and at SPHINCS+C iteration depths (Merkle trees of height 18, WOTS+ chains over 43 elements each up to `w=8`, FORS over `k=13` trees of height 11) this becomes infeasible without significant CVL invariant engineering.
- **Halmos** (a16z) — Foundry-style symbolic test framework using Z3. Free, integrates with Foundry; same fundamental boundedness limitation. Excellent for the AA scaffolding (access control, replay) but not the SPHINCS+C core.
- **hevm** (Ethereum FV team; Dxo/Soos/Paraskevopoulou/Lundfall/Brockman, CAV 2024) — Haskell-based symbolic execution engine over EVM bytecode; can verify equivalence between two bytecode objects; same boundedness profile.
- **Kontrol** (Runtime Verification) — KEVM under the hood, Foundry-style frontend, with the option to fall back on full reachability-logic proofs but in practice used bounded. Runtime Verification also offers **KLab** (proof explorer) and commercial KEVM-based audits as a service.
- **Solidity SMTChecker** — built into solc, very limited scope; useful only for simple arithmetic/assertion claims.
- **Manticore, Mythril, Slither** — symbolic execution / static analysis, well below your target.

The cited Runtime Verification piece "Formally Verifying Loops: Part 1" makes the explicit point that *all* of Certora / Halmos / hevm / Kontrol default to bounded loop unrolling and that "the symbolic execution engines we used here give us very weak correctness guarantees" without supplied invariants — exactly the problem you face with SPHINCS+C verification.

### 2.3 Bytecode-level vs source-level: tradeoffs

Two clean architectures exist:

**Source-level (Verity-style):** You write the contract in a Lean (or Dafny/Coq) DSL whose semantics is the spec. The trust gap is then the compiler from DSL→Yul→bytecode. Verity verifies DSL→Yul; the Yul→bytecode step is trusted to `solc`. Advantage: you can prove rich, structured properties cleanly at the same abstraction level you write at. Disadvantage: you do not verify *your existing Solidity code*; you verify a re-implementation.

**Bytecode-level (KEVM/eth-isabelle/Dafny-EVM-style):** Compile your existing Solidity normally; then state and prove properties about the resulting bytecode against a formal EVM semantics. Advantage: the deployed artifact is what you proved about. Disadvantage: proofs are much harder (no source-level structure), and you are committed to a formal EVM semantics that itself must be trusted to match the real EVM (KEVM, Dafny-EVM, and EVMYulLean each have an Ethereum-test conformance story but none are themselves *proven equivalent* to geth or reth).

For your goal, the cleanest **hybrid** is: prove a Lean reference implementation correct (functional + cryptographic), then prove that **the compiled bytecode of your Solidity refines that Lean reference**, by symbolic-execution-style equivalence checking (hevm, Kontrol) at the bytecode level *or* by Verity-style source-coercion. Both approaches force you to confront the same TCB: solc, the EVM semantics, and `keccak256`/`sha256` precompile correctness.

### 2.4 TCB summary across approaches

Any "fully verified" claim about this contract will leave the following in the TCB unless you do new research to discharge them:

- Lean 4 kernel (or Coq kernel, Isabelle kernel — small, well-trusted).
- `solc` 0.8.33 (or your compiler version) — *the* largest unverified component in Verity-style stories. CompCert-style verified Yul→bytecode does not exist.
- EVM semantics — KEVM/EVMYulLean/Dafny-EVM all rely on conformance testing against Ethereum execution-spec tests.
- The SHA-256 precompile (`0x02`) implementation in the consensus client — trusted to match FIPS 180-4.
- Collision/preimage assumptions on SHA-256 (these are *cryptographic* axioms, not implementation bugs).
- For Verity specifically: the `verity_contract` macro elaborator, ECM modules, linked Yul libraries, gas accounting.

---

## 3. Formally Verifying Post-Quantum / Hash-Based Signature Schemes

### 3.1 The Barbosa–Hülsing EasyCrypt line of work (the most relevant prior art)

The single most directly applicable body of work is the EasyCrypt mechanization of SPHINCS+ and XMSS by Manuel Barbosa, François Dupressoir, Andreas Hülsing, Matthias Meijers, and Pierre-Yves Strub:

- **"Machine-Checked Security for XMSS as in RFC 8391 and SPHINCS+"** — IACR ePrint 2023/408, CRYPTO 2023. First EasyCrypt mechanization of the security proof of XMSS and the crucial lemma shared with SPHINCS+, confirming the Hülsing–Kudinov 2022 recovery proof.
- **"A Tight Security Proof for SPHINCS+, Formally Verified"** — IACR ePrint 2024/910, ASIACRYPT 2024 (LNCS 15487, pp. 35–67). Machine-checked, modular tight EUF-CMA bound for SPHINCS+ in EasyCrypt, with the message-hashing function modeled as a random oracle. The companion repository `github.com/MM45/FV-SPHINCSPLUS-EC` builds with EasyCrypt 2026.02 / Z3 4.13.4 / Alt-Ergo 2.6.0.

Critically for you: this work proves **security properties** of SPHINCS+ in EasyCrypt's computational model (relations among games), it modularly reuses XMSS artifacts, and it ships a generic library for Merkle trees, binary trees, and hash-function properties. The proofs do **not** directly target SPHINCS+C, but the modular decomposition is *exactly* the right shape to extend: WOTS+C and FORS+C in the Hülsing PQC2022 paper are *target-sum-encoded variants* of WOTS+ and FORS, and the rest of the SPHINCS+ tree machinery is unchanged. The "interleaved target subset resilience" property analyzed in the SPHINCS+ proof is the abstraction layer at which you would extend the analysis.

EasyCrypt is not Lean 4. It is a separate proof assistant with an SMT backend (Z3, Alt-Ergo, CVC) and a relational-Hoare-logic core; its kernel is larger than Lean's but it is purpose-built for game-based cryptographic proofs. **If your goal is post-quantum cryptographic security proofs, EasyCrypt is the right tool; if your goal is integration with Verity's Lean compiler stack, you have a translation problem.**

### 3.2 The SPHINCS+C paper itself

The SPHINCS+C scheme you instantiate is from:

- **Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost,"** presented at NIST's Fourth PQC Standardization Conference (PQC2022); `csrc.nist.gov/csrc/media/Events/2022/fourth-pqc-standardization-conference/documents/papers/sphincs-plus-c-pqc2022.pdf`.

The two key ideas are (i) **WOTS+C**: a Winternitz variant where the signer searches for a counter so that the encoded digest hits a fixed target sum, removing the WOTS+ checksum chains and shrinking signatures (~20% smaller for the SLH-DSA-128s-equivalent parameter set: 7856→6304 bytes); and (ii) **FORS+C**: an analogous counter-search reducing FORS signature size. Your parameter set (n=16, h=18, d=2, h′=9, a=11, k=13, w=8, len=43, target_sum=205) is *not* one of the table-2 parameter sets in the paper — it appears to be a custom size-optimized instance, likely chosen to fit signatures into ~4008 bytes (the paper notes len=43 corresponds to the truncated `len_1`-only WOTS+C encoding at n=16, w=8). A related theoretical result — "WOTS+ … with constant-sum encoding is size-optimal not only under Winternitz's OTS framework, but also among all tree-based OTS designs" — has been argued in the broader literature on constant-sum / Bos–Chaum encodings and is referenced from the SPHINCS+C paper.

**There is, to our knowledge, no published machine-checked security proof of SPHINCS+C as a whole, and certainly none for this specific parameter set.** Any "fully verified" claim must either (a) extend the Barbosa et al. EasyCrypt development to cover WOTS+C and FORS+C (significant but tractable research engineering — likely 6–18 person-months), or (b) explicitly carve "the underlying scheme is cryptographically secure" out of the TCB as a stated assumption and verify only the *verification-routine functional correctness*.

### 3.3 Existing implementation-level FV of post-quantum crypto (where Lean 4 stands today)

The Cryspen ecosystem is the leading example of mechanized implementation-level FV for post-quantum crypto:

- **hax** — a Rust→F*/Rocq/ProVerif translator (Cryspen). Used to verify libcrux's Rust implementations of ML-KEM and ML-DSA in F* (`crates.io/crates/libcrux-ml-dsa`; portable+AVX2 field arithmetic, NTT, and serialization are formally verified). Proves panic-freedom, secret-independence, and functional correctness against high-level specs.
- **libcrux** (`github.com/cryspen/libcrux`) — Rust crypto library combining HACL*-derived (F*-verified) and hax-verified code. Notably, **libcrux's SPHINCS+ / SLH-DSA implementation is not yet verified to the same level** as their ML-KEM/ML-DSA — the published material covers ML-KEM and ML-DSA explicitly, not SLH-DSA.
- **liboqs-rust** — Open Quantum Safe Rust bindings; carries SPHINCS+ but no independent FV audit. Notably, per the Project Eleven survey "The State of Post-Quantum Cryptography in Rust," liboqs-rust's SPHINCS+ port has not been updated to match the final SLH-DSA standardization.

For Lean 4 specifically, there is **no production-grade hash-based-signature mechanization** as of early 2026, and Lean's mathlib has no FIPS 180-4 SHA-256 formal model comparable to Andrew Appel's Verified Software Toolchain SHA-256 verification ("Verification of a Cryptographic Primitive: SHA-256," TOPLAS 37(2), 2015), which proved functional correctness of OpenSSL's SHA-256 C code in Coq against a separation logic.

### 3.4 What "verifying a verification routine" actually means

Since your contract only **verifies** signatures (never signs), the property you most directly need is **verification soundness**, not signing correctness:

- **Functional verification correctness** (decidable, mechanically provable): For every input `(pk, msg, σ)` such that `σ` was honestly produced by the reference signing algorithm on `pk, msg`, the verifier accepts. Conversely, for malformed `σ` (wrong length, indices out of range, target-sum constraint not satisfied), the verifier rejects. This is a pure functional-correctness theorem and is what Lean / Coq / Dafny excel at.
- **Cryptographic soundness (EUF-CMA-style)** (only with cryptographic axioms): For every PPT adversary querying a signing oracle, the probability of producing `(msg*, σ*)` with `msg*` not queried such that `Verify(pk, msg*, σ*)` accepts is negligible, assuming SHA-256 satisfies (a) **interleaved target subset resilience** / SM-TCR / multi-target preimage resistance for the tweakable-hash modes used and (b) the message-hash random-oracle assumption (which Barbosa et al. show is necessary for the tight bound).

A "fully verified verifier" without (b) is a *contradiction in terms* — the cryptographic guarantee is what makes the verifier meaningful, not the C/Solidity code. You should state the cryptographic axioms explicitly in your TCB and either accept them (the pragmatic choice) or commit to extending Barbosa et al.'s EasyCrypt to SPHINCS+C (the heroic choice).

### 3.5 Modeling SHA-256, tweakable hashes, and ADRS

Concrete artifacts available today:

- **VST/Coq SHA-256** (Appel, 2015) — functional correctness of OpenSSL's C SHA-256 against a Coq spec of FIPS 180-4. Reusable as the *spec* of the hash function used by SPHINCS+C if you target Coq.
- **HACL*/F\* SHA-2** — F*-verified SHA-256 implementations underpinning libcrux; usable if you go the F*/Rust route.
- **Lean / mathlib** — no production SHA-256 yet; you would need to write one (substantial but well-trodden territory — likely 1–3 person-months for a kernel-computable Lean 4 spec). Verity's `Compiler/Keccak/Sponge.lean` shows that a kernel-computable Keccak engine is feasible inside Lean; SHA-256 is structurally similar.
- **ADRS structure and tweakable hash** — SPHINCS+ defines five ADRS types (WOTS+, WOTS+ public-key compression, FORS, FORS public-key compression, hypertree) packed into 32-byte structures in the SHA-2 variants. Modeling ADRS in Lean is straightforward — it is a tagged record over byte fields — but the *simple* (non-robust) tweakable hash you use must be carefully specified: `F(PK.seed, ADRS, M1) = SHA-256(PK.seed ‖ ADRS_compressed ‖ M1)` for the n=16 SHA-2 variants uses a 64-byte zero-padded ADRS in the "compressed" form and truncates the SHA-256 output to n=16 bytes (the SPHINCS+ submission v3 spec at `sphincs.org/data/sphincs+-round3-specification.pdf` is the canonical reference). For the security argument the assumption you need is SM-TCR / interleaved target-subset-resilience on this construction — exactly what Barbosa et al. axiomatize.

---

## 4. End-to-End Methodology / Playbook for *Your* Contract

This is the realistic plan. It assumes Lean 4 / Verity as the spine because that is what you asked for; alternatives are noted inline.

### 4.1 Decomposition

Split the contract into three independently-verifiable strata:

| Stratum | Verification target | Property to prove | Tool |
|---|---|---|---|
| **A: SPHINCS+C verifier core** | `verifySPHINCSplusC(pk, msg, σ) → bool` | (i) functional correctness vs. reference signer; (ii) cryptographic soundness under stated SHA-256 / SM-TCR / random-oracle axioms | Lean 4 reference (for FV alignment with Verity) + optionally EasyCrypt port of Barbosa et al. for the cryptographic theorem |
| **B: ERC-4337 / Coinbase wallet scaffolding** | `validateUserOp`, nonce/replay handling, ERC-1271 `isValidSignature`, `MultiOwnable`, UUPS upgrade, executor dispatch, (optional) `IAggregator` aggregation | Functional correctness against a Lean state-transition spec; non-bypass invariants (no path validates a UserOp without a verifier-accepted signature) | Verity (rewrite in EDSL) + Certora/Halmos for cross-check |
| **C: Bytecode↔reference equivalence** | The deployed EVM bytecode behaves as the Lean reference verifier on all calldata | Bytecode equivalence | Verity's Yul output + hevm/Kontrol bytecode equivalence checking, or KEVM reachability proofs |

### 4.2 Stratum A — the SPHINCS+C verifier in Lean 4

**Step 1: Specify the parameter set as Lean definitions.** All of n=16, h=18, d=2, h′=9, a=11, k=13, w=8, len=43, target_sum=205 become `def`s in a `SPHINCSplusC.Params` module. Compute derived quantities (signature size = (1 + k·(a+1) + h + d·len) · n + counter overhead; with len=43 and target-sum encoding accounting for the omitted checksum, you should obtain exactly 4008 bytes — first sanity check, also exercises Lean's `decide`/`native_decide` on `Nat` arithmetic).

**Step 2: Model SHA-256 abstractly first, concretely second.**
- Abstract: declare `opaque sha256 : ByteArray → ByteArray` with a postcondition `(sha256 m).size = 32` and an *axiom* "behaves as FIPS 180-4." Prove all of SPHINCS+C functional correctness relative to this abstract.
- Concrete: replace the opaque with a kernel-computable SHA-256 (modeled on `Compiler/Keccak/Sponge.lean`'s style). Prove that the concrete implementation matches the abstract spec on all 32-byte chunks. The concrete computability is essential because Verity needs `by rfl`-style discharge for the `Compiler/Selectors.lean`-equivalent compile-time computations.

**Step 3: Define ADRS, tweakable hashes, WOTS+C, FORS+C, hypertree, and the verifier.**
- `ADRS` as a structure with layer, tree, type, keypair, chain, hash, treeHeight, treeIndex fields, exactly as the SPHINCS+ v3 spec.
- `T_l : ByteArray → ADRS → ByteArray → ByteArray` and `H : ByteArray → ADRS → ByteArray → ByteArray` and `F : ByteArray → ADRS → ByteArray → ByteArray` as definitions on top of `sha256` with the simple (non-robust) construction.
- `WOTSplusC.PKfromSig`, `FORSplusC.PKfromSig`, `XMSS.PKfromSig`, `HT.verify`, `SPHINCSplusC.verify`. Each is a structurally-recursive pure function over byte arrays; Lean's termination checker handles them straightforwardly because all loops are bounded by `len`, `k`, `a`, `h′`, `d`.

**Step 4: Prove functional correctness.** State `theorem verify_signs : ∀ sk pk msg, keygen produces (sk, pk) → verify pk msg (sign sk msg) = true`. The proof unfolds definitions and reduces (~5,000–15,000 lines of Lean given the Barbosa et al. precedent of >50,000 EasyCrypt lines for the security proof, but functional correctness is much simpler than EUF-CMA).

**Step 5: State (and possibly prove) cryptographic soundness.** Two options:
- *Axiomatize*: introduce `axiom EUF_CMA_SPHINCSplusC : ∀ (𝒜 : Adversary), Pr[Forge(𝒜)] ≤ ε(SHA-256-assumptions, parameters)`. Document explicitly that this is a *cryptographic axiom*, not an implementation property; cite the SPHINCS+C paper for the bound; note that the bound is conjectured-to-extend-from but not formally proved-equivalent-to the Barbosa et al. SPHINCS+ tight bound.
- *Prove*: port the Barbosa et al. modular development to SPHINCS+C (extend their WOTS+ and FORS modules with the counter-search variants; reprove SM-TCR/itsr lemmas for the simple hash mode at n=16; recompose the top-level theorem). This is the rigorous path. Effort: very approximately 9–18 person-months for a team with prior EasyCrypt experience, or significantly more without it. Result lives in EasyCrypt, not Lean; you would then either (a) accept EasyCrypt's TCB alongside Lean's for the security theorem only, or (b) commit to a Lean port (multi-year effort with no precedent).

### 4.3 Stratum B — the AA scaffolding

The Coinbase Smart Wallet's `CoinbaseSmartWallet.sol` (from `github.com/coinbase/smart-wallet/blob/main/src/CoinbaseSmartWallet.sol`) implements `ERC1271, IAccount, MultiOwnable, UUPSUpgradeable, Receiver` and stages signatures through a `SignatureWrapper { uint256 ownerIndex; bytes signatureData }`. The relevant invariants to spec and prove:

1. **`validateUserOp` non-bypass**: for any `UserOperation`, `validateUserOp` returns `SIG_VALIDATION_SUCCESS` only if `_validateSignature` returns true, which (post-modification) calls `verifySPHINCSplusC` on the user's stored public key for `ownerIndex`. Theorem: ∀ userOp, ∀ pk in owners, validateUserOp returns success ⇒ ∃ σ ∈ userOp.signature, verifySPHINCSplusC(pk, hash(userOp), σ) = true.
2. **Replay protection**: the EntryPoint's nonce mechanism plus the wallet's own `replaySafeHash` (chain-id–binding) prevents cross-chain replay except for cross-chain replayable owner updates explicitly marked so. Theorem: ∀ executed userOp, ∀ chain c, the same `(nonce, chainId)` pair cannot be executed twice (modulo the explicitly cross-chain-replayable category).
3. **`MultiOwnable` access control**: only currently-registered owners can `addOwnerPublicKey`, `removeOwnerAtIndex`. Theorem family modeled on the Verity Owned/OwnedCounter pattern. Coinbase's design allows up to 2^256 concurrent owners, each transacting independently — your spec must allow an owner-permutation invariant rather than a single-owner invariant.
4. **UUPS upgrade safety**: `_authorizeUpgrade` is gated by the same owner-or-self check. Theorem: no path through any function except a properly-authorized `upgradeToAndCall` changes the implementation slot. *This is exactly the area Verity does not yet model* (issue #1420). Options: (a) prove a non-upgradeable variant for production deployment, with a separate audit of the upgrade machinery; (b) gate the entire `_authorizeUpgrade` + `upgradeToAndCall` path behind a *local refinement obligation* in Verity (surfaced explicitly in `--trust-report`) and verify the rest unconditionally; (c) extend Verity itself to model `delegatecall`-based proxies — meaningful but bounded research work.
5. **ERC-1271 consistency**: `isValidSignature(hash, sig)` and `validateUserOp` use the same signature-validation function modulo replay-safe-hash domain separation.
6. **(If used) `IAggregator` aggregation**: ERC-4337 allows accounts to specify an external aggregator contract (`IAggregator.validateUserOpSignature`, `IAggregator.aggregateSignatures`, `IAggregator.validateSignatures`) to batch-validate signatures across multiple UserOps. Hash-based signatures like SPHINCS+ generally do **not** support non-interactive aggregation (unlike BLS), so for SPHINCS+C the natural design is to declare no aggregator (return the zero address from `getAggregator`-style queries). The theorem you need is then trivial — but it must be stated explicitly: "`validateUserOp` never returns a nonzero aggregator." If you *do* implement aggregation (e.g., concatenation-based bundling), it must be specified separately and proved sound; this is a significant additional verification target.

**Recommended approach for Stratum B**: rewrite the wallet in Verity's EDSL. This is the only path to Lean-level proofs of the scaffolding inside Verity today. Issues to negotiate with LFG Labs or fix in-house first:

- UUPS / `delegatecall` support (Verity issue #1420) — see above.
- Dynamic-bytes for the 4008-byte signature blob in calldata — Verity's `String`/`bytes` dynamic-type support is recent (issue #1159) and you need to confirm it handles your access patterns (slicing into 32-byte fields and feeding them to `sha256` via the precompile ECM, thousands of times per verification).
- `sha256` precompile ECM — already in Verity's `Compiler/Modules/` (precompile 0x02 is listed in the ECM set alongside 0x01/0x06/0x07/0x08); the *semantic correctness* of this ECM is a trust assumption, so the bridge between "Lean's `sha256` definition" and "the on-chain `0x02.staticcall` result" needs an explicit assumption module that says "the EVM's precompile at `0x02` computes FIPS 180-4 SHA-256."
- Gas accounting — Verity does not model gas. Coverage of gas-griefing attacks on AA accounts (a frequent class of 4337 issues) needs *separate* attention via Foundry tests and `eth_estimateGas` empirical bounds.

**Cross-check with Certora/Halmos**: for Stratum B's invariants (access control, replay, nonce monotonicity), a parallel CVL specification and Halmos symbolic tests are inexpensive insurance and catch specification mistakes much faster than Lean proof failures. LFG Labs themselves recommend this combination in their README: "For most teams, Certora or Halmos will be the practical choice because their automation is far ahead. Verity is for cases where you need mathematical certainty."

### 4.4 Stratum C — Lean reference ↔ deployed bytecode

This is the structurally hardest stratum, and the one where Verity's value is concentrated. Three recipes (in order of preference for your goal):

**Recipe C1 (Verity-native — recommended for your stated goal):** Author the verifier in Verity's EDSL. The Verity compilation proofs (Layer 1+2+3) then automatically guarantee that the emitted Yul (and post-`solc` bytecode, modulo `solc`'s trust) preserves the Lean semantics. Per-contract specification proofs in `Contracts/Wallet/Proofs/` connect the EDSL to your top-level wallet theorems. The remaining bridge is: prove that the Verity-EDSL `sphincsVerify` function inside the contract is *equivalent* to your standalone Lean reference `SPHINCSplusC.verify` (a pure Lean ≡ Lean proof, ~weeks of work for a careful engineer; mostly mechanical once the spec is stable).

**Recipe C2 (Hax/F\* extraction route — interesting alternative):** Write the verifier in Rust, verify it via hax/F* against a high-level spec (analogous to Cryspen's libcrux ML-KEM/ML-DSA workflow), then *extract* Yul/EVM bytecode from the Rust via a verified path. *This last step does not exist as a polished tool today* — there is no Cryspen-style Rust→Yul extractor with proven semantic preservation. So C2 currently degenerates into: prove the spec in F* (or Coq via hax-Rocq backend), then re-implement in Verity-EDSL, then prove equivalence. This is more redundant work than C1 but produces a *second-source* Rust implementation that can also live in a libcrux-style library and be reused off-chain.

**Recipe C3 (bytecode equivalence, fallback):** Keep your existing Solidity. Use hevm or Kontrol to prove (bounded) equivalence between your Solidity-compiled bytecode and a Yul implementation extracted from the Lean reference. This sidesteps Verity entirely for the implementation but only gives bounded guarantees over loop depth — fundamentally insufficient for SPHINCS+C's nested-loop structure unless you supply loop invariants, at which point you have re-derived most of the difficulty of a full proof. Use C3 for *spot-equivalence* on critical small routines (e.g., the WOTS+C chaining function) as defense-in-depth alongside C1.

Recipe C1 is the right choice given your stated preference for Lean 4 and unbounded proofs.

### 4.5 Solidity↔Lean connection: the menu of techniques

It is worth being explicit about the *kinds* of bridge that can exist between Solidity source and a proof assistant; the literature scatters these:

- **Re-authoring in a verified DSL** (Verity, Dafny-EVM in part) — you write the contract once in the DSL; the DSL is the spec; the verified compiler produces the bytecode. This is what we recommend.
- **Translation / extraction**: an automated tool reads Solidity and emits a proof-assistant model. There is no production-grade Solidity→Lean translator today; Yul→KEVM is automated but K's reachability logic is the proof system, not Lean.
- **Refinement proof**: you write the Lean (or Coq) reference, you write the Solidity, and you prove a refinement relation between executions of the EVM bytecode (under a formal EVM semantics) and executions of the Lean reference. Act ↔ hevm/Coq is the closest existing instantiation; it works for small contracts but does not scale.
- **Equivalence by symbolic execution**: hevm `equivalence`, Kontrol equivalence checking — bounded.
- **Roundtripping via hax/F\* (cryptography-only)**: prove a Rust reference; cross-check the Solidity via differential testing against the Rust; do *not* claim a single end-to-end theorem. This is the pragmatic state of the art at libcrux.

For this contract, C1 + Foundry differential testing against a hax/F*-style Rust reference (if you also build one) is the most robust assurance package.

### 4.6 Hard parts you should plan for explicitly

These are the technically nasty issues that *will* eat time:

- **Non-linear `uint256` arithmetic** — SPHINCS+C verification is mostly byte manipulation and SHA-256 calls, but counter encoding, base-w decoding, and the target-sum check involve modular arithmetic that needs care. Verity's `Compiler/Proofs/ArithmeticProfile.lean` proves wrapping arithmetic at 2^256, and `Verity/Stdlib` exposes `safeMul, safeDiv` — but SMT solvers underneath any tool you use (including Lean's own `omega`/`decide`) handle non-linear integer arithmetic only poorly; expect to write manual proofs for multiplicative invariants.
- **`keccak256` in scaffolding**: although your *signature scheme* uses SHA-256, the Coinbase wallet still uses `keccak256` for owner storage hashing, selectors, and the EntryPoint hash. Verity's kernel-computable Keccak engine handles this, but at the cost of moderate proof-time inflation on every `decide`-style discharge.
- **Large byte-array manipulation**: at 4008 bytes per signature, Lean's `ByteArray` performance is critical. Use `ByteArray.get!` patterns aligned to 32-byte EVM-word boundaries; avoid `List Byte`. Verity's IR currently models calldata reads at a specific abstraction level — confirm with LFG Labs that slicing a 4008-byte parameter into 32-byte chunks for repeated precompile invocation is on a smooth path. The `ABI-level String` work was recent; bytes-of-that-size is the natural stress test.
- **EVM memory modeling**: Verity's IR-level memory model has been refactored multiple times (the recent definition refactor in PR #1639 left Layer 2 proof scripts being repaired with `sorry` placeholders in some intermediate states per their status doc — confirm the current state before committing). Memory layout for the SHA-256 precompile call (input pointer + length) must match Solidity's expectations exactly.
- **Recursion / loop depth**: WOTS+ chains iterate up to `w-1 = 7` times each, for `len = 43` chains, inside FORS verification (`k = 13` Merkle paths of height `a = 11`), inside the hypertree (`h = 18` total, `h′ = 9` subtree, `d = 2` layers, `len = 43` WOTS+ per subtree). A naive Lean encoding will explode kernel reduction times; you will likely need `simp`-set engineering and possibly reflective tactics.
- **EntryPoint interaction**: ERC-4337 specifies strict storage-access rules during `validateUserOp` for the alt-mempool simulation phase. Your spec must enforce that `_validateSignature` reads only the wallet's own storage and the data passed in — a non-trivial property to state cleanly in Lean.
- **Calldata gas non-linearity**: a 4008-byte calldata `UserOperation.signature` costs ~64,000 gas just for the calldata bytes (16 gas/non-zero byte). Combined with thousands of SHA-256 precompile calls (60 + 12·⌈|data|/32⌉ gas each), the per-`validateUserOp` cost may exceed bundler limits. This is *not* a verification concern but a deployability concern that will reshape engineering decisions.

### 4.7 Effort, team, and cost estimate

Calibration points: Barbosa et al.'s EasyCrypt SPHINCS+ proof is roughly 50,000+ lines of EasyCrypt, took multiple person-years, and built on a >5-year line of work on hash-based-signature formal verification. CompCert is 100,000 lines of Coq, 6 person-years. The Verity compiler stack to its current state (≈ a year of work with heavy AI assistance per LFG Labs' own description) is in the same order of magnitude. A realistic estimate for fully verifying this contract to the standard you describe:

| Component | Skills required | Estimated effort |
|---|---|---|
| Lean 4 SHA-256 spec + functional-correctness proof | Strong Lean 4; mathlib familiarity | 2–4 person-months |
| Lean 4 SPHINCS+C reference verifier + functional-correctness theorem | Strong Lean 4; understanding of SPHINCS+ spec; cryptography literacy | 4–8 person-months |
| Cryptographic security proof of SPHINCS+C (extending Barbosa et al. in EasyCrypt) — *if pursued* | Senior EasyCrypt cryptographer; prior SPHINCS+/XMSS proof experience | 9–18 person-months |
| Verity EDSL rewrite of the wallet (including UUPS extension or restructuring, dynamic-bytes patterns, precompile ECMs) | Lean 4 + Solidity + Verity internals | 6–12 person-months |
| Specification proofs for AA scaffolding (Stratum B) | Lean 4; ERC-4337 semantics | 3–6 person-months |
| Bridge from EDSL `sphincsVerify` to standalone Lean reference | Lean 4 | 2–4 person-months |
| Differential testing against reference C SPHINCS+C (e.g., a fork of `github.com/sphincs/sphincsplus`) | Embedded C, test-vector generation | 1–2 person-months |
| Certora CVL spec for AA scaffolding (complementary) | CVL; DeFi audit experience | 1–2 person-months |
| **Total (without cryptographic security re-proof)** | | **~19–38 person-months** |
| **Total (with cryptographic security re-proof)** | | **~28–56 person-months** |

This is at the upper end of what is feasible for a small team and would typically be a 1–2-year engagement at LFG Labs' scale (their stated capacity is 4 protocols/quarter, so they are obviously *not* doing a 2-year project per client today — what they call "formally verified" in their commercial offering will be much narrower than what you are asking for).

### 4.8 Source-level vs bytecode-level for *this* contract: explicit recommendation

**Go source-level via Verity (Recipe C1) for the verifier and the scaffolding, with two specific carve-outs:**

1. **SHA-256 precompile**: leave the bridge "EVM precompile 0x02 implements FIPS 180-4 SHA-256" as an explicit axiom in your trust report. This is the same trust class as Solidity's own `sha256(...)` builtin and is unavoidable without verifying the consensus client.
2. **Gas behavior**: Verify functional correctness in Verity; verify gas behavior empirically via Foundry differential tests against the reference SPHINCS+C signer. State explicitly that "the contract reverts within the EntryPoint's gas limits for honest signatures" is *not* a theorem but an empirical claim with stated bounds.

The bytecode-level approach (KEVM/Kontrol or hevm against the original Solidity) is a useful *secondary* check — use it for spot-equivalence on critical small routines — but it cannot be the primary assurance vehicle at SPHINCS+C's iteration depths.

---

## 5. Practical Recommendations and Alternatives

### 5.1 Concrete recommended path

Given your explicit preference for the LFG / Lean 4 approach and full proofs, the practical recommendation is a **two-track structure**:

**Track 1 (Lean 4 / Verity — your primary target):**
1. Stand up the SPHINCS+C reference verifier in Lean 4 in-house. Do this *first*, in isolation from any EVM concern. Iterate to functional correctness against test vectors from a forked `sphincs/sphincsplus` reference C implementation with WOTS+C/FORS+C added.
2. Engage LFG Labs *concurrently* on the AA scaffolding. They are the world's only commercial vendor of Lean-4-based smart-contract verification today; their effort gap is real, and their incentive is correctly aligned (they refund if they cannot prove or refute). Insist on (a) a published `--trust-report` listing every axiom and ECM, (b) explicit handling of UUPS / proxy, (c) a public benchmark entry in `lfglabs-dev/verity-benchmark` so the proof set is reproducible, and (d) a written acknowledgment that *their* current TCB includes `solc` 0.8.33, the macro elaborator, and the sha256 ECM bridge.
3. Connect (1) and (2) via the bridge proof in §4.4 Recipe C1. This is the deliverable that closes the loop.

**Track 2 (defense in depth):**
4. Run Certora and/or Halmos on the original Coinbase-Smart-Wallet-derived Solidity for the AA scaffolding properties (replay, access control, upgrade). This finds bugs faster and gives you a second-source verification you can cite alongside the Lean proofs.
5. Differentially test the deployed bytecode against the C reference SPHINCS+C and against a Rust port (consider contributing the SPHINCS+C variant to libcrux for hax/F* verification — Cryspen has the relevant expertise from ML-DSA).
6. Commission an EasyCrypt extension of Barbosa et al. to SPHINCS+C *only if* the cryptographic-security theorem is part of your assurance target. Otherwise, document the cryptographic security as a stated assumption citing the Hülsing PQC2022 paper.

### 5.2 LFG Labs engagement vs in-house

- **Engage LFG Labs for the scaffolding and the Verity-EDSL compilation correctness**, because that is exactly where they are uniquely positioned. They built and own the verified compiler.
- **Do the SPHINCS+C cryptography in-house or via a specialized vendor** (Cryspen for implementation-level FV; the Barbosa/Hülsing/Meijers research group at TU Eindhoven / U. Porto / U. Bristol / Inria for EasyCrypt security proofs; Runtime Verification for KEVM/Kontrol assistance on the bytecode side; Galois or Trail of Bits for tactic engineering). LFG Labs has not, to public knowledge, shipped a hash-based-signature mechanization; the value they add to the crypto core is small.
- **In-house alone is feasible but slow**: with a 2–3-person team containing one strong Lean 4 expert, one experienced Solidity engineer, and one cryptographer, you can do the whole thing on the timelines in §4.7. Without an existing Lean expert, expect 2–3× slower.

### 5.3 Complementary approaches worth combining

- **Certora Prover** on the AA scaffolding for cross-validation of invariants — a known and trusted CVL framework. Pair with Halmos for free open-source coverage.
- **hevm equivalence** on critical functions between (i) Solidity-compiled bytecode and (ii) Verity-emitted Yul-compiled bytecode. This guards against subtle solc bugs.
- **Differential fuzzing against a reference**: fork `github.com/sphincs/sphincsplus`, add the WOTS+C/FORS+C target-sum modifications, generate test vectors, and exercise the deployed contract via Foundry against ~10⁶ random valid and invalid signatures. **This is not a proof** but it catches integration mistakes that proofs of the wrong specification cannot.
- **libcrux / hax co-development**: if a verified Rust SPHINCS+C lands in libcrux, you can use it as a second specification and prove cross-equivalence with the Lean reference, dramatically increasing assurance via redundancy.
- **Runtime Verification's commercial services**: KEVM/Kontrol-based audits are available commercially; if you want a second-source bytecode-level reachability proof on key functions (e.g., `validateUserOp`), engaging RV in parallel with LFG Labs provides genuine diversity (different proof assistants — K vs Lean — and different methodologies — reachability logic vs interactive theorem proving).
- **`verity-benchmark` participation**: contributing your contract (or a `verifier-only` variant) to the LFG benchmark repo gets you continuous regression as Verity matures and surface visibility to the research community.

### 5.4 Risks, common pitfalls, and what "fully verified" can and cannot mean

This is the most important section. Be explicit with stakeholders:

**What "fully verified" *will* mean for your contract:**
- The Lean reference SPHINCS+C verifier is functionally correct: a signature produced by the reference signing algorithm is accepted, and *certain* classes of malformed signatures (wrong size, indices out of bounds, target-sum violated) are rejected — *all by Lean kernel checking*.
- The Solidity/Yul implementation (or Verity-EDSL replacement) refines the Lean reference — under the trust assumptions in the Verity TCB.
- The AA scaffolding (nonces, multi-owner, ERC-1271, UUPS) satisfies stated invariants — by Lean proofs (and ideally also Certora-CVL proofs).

**What "fully verified" *will not* mean** unless additional work is done:
- It will not mean SPHINCS+C is cryptographically secure — only that *if* SHA-256 satisfies SM-TCR / target-subset-resilience-style assumptions in the random-oracle model for the message hash, *then* (per the Hülsing PQC2022 paper and an extension of Barbosa et al.) forgeries are computationally infeasible. The chain of formal proofs from your verifier to that conclusion is incomplete without porting/extending Barbosa et al.
- It will not mean the deployed contract behaves correctly on Ethereum if `solc` 0.8.33 has a codegen bug for your contract — `solc` is in the TCB.
- It will not mean the EVM precompile 0x02 actually implements FIPS 180-4 — this is a consensus-client trust assumption.
- It will not give gas-correctness or DoS-resistance guarantees; SPHINCS+C verification at these parameters is *expensive*, and gas-griefing analysis is a separate, empirical workstream.
- It will not catch spec bugs. The most common failure mode of formal verification is proving the wrong thing. The biggest single risk in this project is that the Lean specification of SPHINCS+C verification diverges in some subtle way from the *actual* SPHINCS+C as you intended it — wrong ADRS layout byte ordering, wrong target-sum-check ordering, wrong base-w decoding, etc. Mitigate with extensive test-vector–based co-validation against a reference implementation.
- It will not address front-end / user-experience / key-management failures (the most common real-world cause of smart-wallet loss).
- Verity's current proof-interpreter does not model `delegatecall`/proxy/upgradeability flows; if this gap is not closed before your engagement, your UUPS-upgrade path will sit outside the verified subset.
- It will not address signature aggregation if you implement it — `IAggregator` paths must be specified and proved separately.

**The Cryspen blog post "The strengths and limits of formal verification"** puts the underlying point well, applied to a different setting (Rust crypto): "the verification guarantees for libcrux code only extend to the verified modules. In addition, we need to carefully review and test all the unverified code, the system libraries, the Rust compiler, the hardware..." The same applies tenfold here.

### 5.5 Key papers, repos, tools, and teams

**Verity / LFG Labs:**
- `github.com/lfglabs-dev/verity` — the framework
- `github.com/lfglabs-dev/verity-benchmark` — reproducible benchmark scaffold for Verity-based research
- `github.com/Th0rgal/verity` — author's personal mirror
- `github.com/lfglabs-dev/EVMYulLean` — the EVMYulLean fork that provides the runtime authority for Verity's EndToEnd target
- `lfglabs.dev` — commercial site; `lfglabs.dev/papers/verity.pdf` — research paper draft (was not directly retrievable in this session)
- `veritylang.com` — docs site

**EVM formal verification:**
- KEVM — `github.com/runtimeverification/evm-semantics`; Hildenbrandt et al. CSF 2018
- eth-isabelle — `github.com/pirapira/eth-isabelle`; Amani/Bégel/Bortin/Staples CPP 2018 ("Towards Verifying Ethereum Smart Contract Bytecode in Isabelle/HOL")
- Dafny-EVM — `github.com/Consensys/evm-dafny`; Cassez/Fuller/Ghale/Pearce/Quiles FM 2023 (arXiv:2303.00152)
- Act / hevm — `fv.ethereum.org`; Dxo/Soos/Paraskevopoulou/Lundfall/Brockman CAV 2024
- Kontrol — `github.com/runtimeverification/kontrol`; KLab — Runtime Verification proof explorer
- Certora — `certora.com`; Halmos — `github.com/a16z/halmos`
- Overview repo — `github.com/leonardoalt/ethereum_formal_verification_overview`

**SPHINCS+ / hash-based-signature FV:**
- Barbosa/Dupressoir/Grégoire/Hülsing/Meijers/Strub, "Machine-Checked Security for XMSS as in RFC 8391 and SPHINCS+," IACR ePrint 2023/408, CRYPTO 2023
- Barbosa/Dupressoir/Hülsing/Meijers/Strub, "A Tight Security Proof for SPHINCS+, Formally Verified," IACR ePrint 2024/910, ASIACRYPT 2024, LNCS 15487
- Companion repo `github.com/MM45/FV-SPHINCSPLUS-EC`
- Hülsing et al., "SPHINCS+C: Compressing SPHINCS+ With (Almost) No Cost," NIST PQC2022 proceedings, `csrc.nist.gov`
- SPHINCS+ spec v3: `sphincs.org/data/sphincs+-round3-specification.pdf`
- Reference C: `github.com/sphincs/sphincsplus`
- Cryspen libcrux: `github.com/cryspen/libcrux`; hax toolchain: `cryspen.com/hax-toolchain/`
- Appel, "Verification of a Cryptographic Primitive: SHA-256," TOPLAS 37(2), 2015

**Coinbase Smart Wallet / ERC-4337:**
- `github.com/coinbase/smart-wallet`; `CoinbaseSmartWallet.sol`
- ERC-4337 spec: `eips.ethereum.org/EIPS/eip-4337`
- Daimo passkey precedent; Solady ERC4337 base; LightAccount (Alchemy)

**Teams in the space worth knowing:** LFG Labs (Verity, Lean 4), Cryspen (hax, libcrux, F\*), Runtime Verification (KEVM, Kontrol, KLab), ConsenSys Diligence (Dafny-EVM), Certora, a16z (Halmos), Trail of Bits, OpenZeppelin, Galois (Cryptol/SAW), Inria/INRIA-EPFL/U. Bristol/TU Eindhoven (EasyCrypt — Barbosa/Dupressoir/Grégoire/Hülsing/Meijers/Strub), Princeton (Appel/VST), MIT/Harvard/CMU for Coq verification of low-level cryptographic code.

---

## 6. Bottom Line

A fully-verified-in-the-proof-assistant-sense SPHINCS+C-verifying ERC-4337 smart wallet on EVM is **not a one-engagement, one-tool deliverable today**. It is achievable, but it requires:

1. A new Lean 4 mechanization of SPHINCS+C verification with explicit cryptographic axioms (or an extension of the Barbosa et al. EasyCrypt development).
2. A Verity-style verified compilation of the contract from a Lean EDSL to EVM bytecode, with explicit acknowledgment that `solc`, EVM semantics, the macro elaborator, and the SHA-256 precompile bridge remain in the TCB.
3. Lean proofs of the ERC-4337 / Coinbase wallet scaffolding invariants — *after* Verity grows UUPS / proxy support or you restructure the wallet to remove it; and explicit treatment of any `IAggregator` aggregation path.
4. Defense-in-depth from Certora/Halmos on the scaffolding, hevm/Kontrol equivalence on critical functions, and differential fuzzing against a reference C / Rust SPHINCS+C.

The total honest effort estimate is on the order of 1.5 to 4 person-years depending on whether you include a fresh cryptographic-security proof of SPHINCS+C itself. LFG Labs is the right partner for the EVM-side Lean compilation correctness and the scaffolding proofs; the cryptographic core is best done in-house or with cryptography-specialist FV vendors (Cryspen, the Barbosa/Hülsing/Meijers research line, Galois, Runtime Verification). The end-state guarantee is mathematical certainty about *functional* properties under stated cryptographic and `solc`/EVM/precompile axioms — which is the most that any honest formal-verification claim can offer, and which is genuinely worth the investment for a contract that uses a non-standardized post-quantum scheme on chain.