# Verity v0.1.0 — primitive map for SPHINCS+C10 verifier port

> Companion to `docs/handoff-verity-c10-verifier.md` §4 Phase 0.
>
> Written 2026-05-11. Based on inspection of upstream
> `lfglabs-dev/verity` at tag `v0.1.0` (commit
> `caac8a6831cdda8f7d09035cd92c8dcc84cf6e51`), fetched via the
> `contracts/verity/lakefile.lean` dependency. No upstream PRs have
> been opened; this doc is the input for future Phase 0 work.

## 1. What Verity v0.1.0 actually has

Verity v0.1.0 is a **minimal Lean 4 EDSL** for porting small EVM
contracts — closer in scope to a teaching DSL than to a production
DSL like Halmos or Certora. The full type and primitive set is:

### `Verity.Core` (the EDSL)

| Name | Type | Purpose |
|------|------|---------|
| `Address` | `abbrev String` | Account address (string-typed; ≠ 20-byte address) |
| `Uint256` | `abbrev Verity.Core.Uint256` | 256-bit integer with EVM semantics |
| `Bool'` | `abbrev Bool` | Boolean |
| `Bytes` | `abbrev List Nat` | Variable-length byte string |
| `StorageSlot α` | `structure { slot : Nat }` | Typed storage slot reference |
| `ContractState` | `structure { storage, storageAddr, storageMap, sender, thisAddress, msgValue, blockTimestamp, knownAddresses }` | EVM-flavored state monad payload |
| `ContractResult α` | `inductive \| success a s \| revert msg s` | Explicit success / revert |
| `Contract α` | `abbrev ContractState → ContractResult α` | The contract monad |
| `pure` / `bind` | EDSL monad ops | |
| `getStorage` / `setStorage` | `StorageSlot Uint256 → Contract _` | Single Uint256 cell |
| `getStorageAddr` / `setStorageAddr` | `StorageSlot Address → Contract _` | Single Address cell |
| `getMapping` / `setMapping` | `StorageSlot (Address → Uint256) → Contract _` | mapping(address ⇒ uint) |
| `msgSender` / `contractAddress` / `msgValue` / `blockTimestamp` | `Contract _` | Read-only context |
| `require` | `Bool → String → Contract Unit` | EVM `require` |

### `Verity.EVM.Uint256` + `Verity.Core.Uint256`

- `Uint256` as `structure { val : Nat, isLt : val < 2^256 }`.
- Arithmetic with EVM wrapping semantics.
- Division / mod by zero returns 0.

### `Verity.Stdlib.Math`

- Generic math lemmas used by the example proofs (no surprises).

### `Compiler.*` (the Lean → Yul codegen pipeline)

- `Compiler.IR` — IR over `Yul.YulExpr` / `Yul.YulStmt`.
- `Compiler.Yul.Ast` — Yul AST: `lit n`, `hex n`, `str s`, `ident name`, `call func args`, plus `let_`, `assign`, `if_`, `switch`, `block`, `funcDef`.
- `Compiler.Selectors` — function-selector emission.
- `Compiler.Specs` — declarative contract specs.
- `Compiler.CompileDriver`, `Compiler.Linker` — drives the pipeline.

### `Verity.Examples/*` (the existing verified contracts)

11 small contracts: `SimpleStorage`, `Counter`, `SafeCounter`,
`Owned`, `OwnedCounter`, `Ledger`, `SimpleToken`, `ReentrancyExample`,
`CryptoHash` (placeholder — Poseidon hash slot is a TODO; see
`Verity/Examples/CryptoHash.lean:20-35`). Plus `Verity.Specs/*` and
`Verity.Proofs/*` for verification.

## 2. What the SPHINCS+C10 verifier needs

Per `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol` (202
lines of Yul) and the handoff §4 Phase 0:

### 2a. SHA-256 precompile (~322 calls per verify)

The Yul verifier calls `staticcall(gas(), 0x02, ptr, len, out, 32)`
~322 times per `verify`:

| Phase | Call count |
|-------|-----------|
| H_msg | 1 |
| FORS leaf hash (K=13 + forced-zero) | 13 |
| FORS auth-path walk ((K-1)·A = 132) | 132 |
| FORS PK compression | 1 |
| Per hypertree layer (×D=2): WOTS digest 1 + WOTS chains ~162 + WOTS PK 1 + Merkle 9 | 173 × 2 = 346 |
| Net | ≈322 |

**Verity has**: no SHA-256 primitive. `Compiler/Yul/Ast.lean` exposes
arbitrary `call(func, args)` so emitting `staticcall(..., 0x02, ...)`
is mechanically possible at the IR layer. But there is no axiom about
what 0x02 *returns* — the equivalence proofs at Layer 1/2/3 treat
calls as opaque. Without an axiomatised semantics, `sha256(input) =
expected` cannot be reasoned about in Lean.

### 2b. Calldata read

The verifier reads a 4008-byte `bytes calldata sig`. Yul:
`calldataload(offset)`, `calldatacopy(dst, src, len)`.

**Verity has**: no `calldata` primitive. The EDSL is whole-contract,
not function-fragment-level. Examples take input via the
`ContractState.sender` etc.; arbitrary calldata is not in the
abstraction.

### 2c. Sub-word bitfield ops

Three patterns:

- Branchless Merkle swap: `let s := shl(5, and(pathIdx, 1))`
  (`SPHINCsC10Asm.sol:84-86, 185-187`).
- 3-bit digit unpack: `and(shr(mul(ii, 3), d), 0x7)` at lines 137,
  144.
- ADRS bit-position constants: `shl(128, 3)` etc. at lines 67, 82, 97,
  106, 122, 148-149, 153, 163, 173, 181-183.

**Verity has**: `Uint256` with arithmetic but no exposed `shl`,
`shr`, `and` primitives at the EDSL level. The Yul AST has
`call("shl", ...)` etc. available — Yul emits these for bit ops —
but the EDSL doesn't surface them as `def`s. Adding them would
require new `Verity.EVM.Bits` module with:
- `shl : Uint256 → Uint256 → Contract Uint256` (axiomatised: `shl n x =
  x * 2^n mod 2^256`)
- `shr : Uint256 → Uint256 → Contract Uint256`
- `and` : `Uint256 → Uint256 → Contract Uint256`

### 2d. Scratch-buffer aliasing

The Yul verifier reuses `[0x80 + i*0x20]` (slots 0..42) across three
phases per layer: FORS roots → WOTS endpoints → hypertree
intermediates. This is the kind of memory-aliasing pattern that
high-level EDSLs deliberately avoid.

**Verity has**: no explicit scratch-buffer abstraction. The EDSL
treats memory as opaque (everything goes through `ContractState`).
Yul codegen emits `mstore(off, val)` but the equivalence proof
doesn't reason about memory layout — it's an axiom that
arbitrary-position `mstore` is observationally indistinguishable
from any other memory model.

For our purposes, what we actually need is a `scratch` primitive
with a **disjoint-frame axiom**: each phase reads from a disjoint
slice of scratch, so its writes don't affect prior phases'
computations. This is non-trivial to formalise — see Halmos /
Symbolic Halmos for the precedent.

## 3. Gap table

| Primitive | Status in Verity v0.1.0 | Effort to add |
|-----------|-------------------------|---------------|
| `precompile.sha256` | Missing | 1–2 weeks (axiomatised semantics + Yul codegen of `staticcall(0x02)` + equivalence proof) |
| `calldata.read` / `calldata.copy` | Missing | 1 week (new `Contract` action + Yul `calldataload`) |
| `bits.shl` / `bits.shr` / `bits.and` (`Uint256`-level) | Partial: `Uint256` exists but bit-ops not exposed at EDSL | 1 week (3 `def`s + 3 axioms + Yul emit) |
| `memory.scratch` (with disjoint-frame axiom) | Missing — Verity has implicit memory model | 2–3 weeks (new memory abstraction + disjoint-frame lemma + Yul `mstore`/`mload` codegen with offset tracking) |
| `Bytes32` / `Bytes16` / `Bytes4` type aliases | Missing | < 1 day (just `abbrev`s in `Verity.EVM.Bytes`) |
| `ByteVec` (`Array UInt8`) | Has `Bytes := List Nat` — different shape | 2 days (refactor to `Array UInt8` + helper lemmas) |
| ERC-7201 `NamespacedStorage` | Missing — Verity uses linear `slot : Nat` | 1 week (storage namespacing + collision-resistance axiom via `keccak256` axiom) |
| External call with frame-separation | Missing | 2 weeks (axiomatised `extCall : Address → Uint256 → Bytes → Contract Bytes` + frame-separation lemma) |
| `UserOp` (ERC-4337 v0.6) types | Missing | < 1 day (`structure UserOp06` + ABI encode/decode lemmas) |

**Net minimum to land Phases 1-7 of the handoff**: ~8–12 person-weeks
of upstream Verity work, **before** any of the actual Lean port
files start to make sense in the Verity EDSL.

## 4. Recommended Phase-0 upstream issue drafts

Order by dependency (#1 unblocks #2-7).

### Issue #1 — `[EDSL] Add bytes32/bytes16/byte-vector type aliases`

**Why**: Every cryptographic primitive operates on fixed-width byte
strings. `Bytes := List Nat` is wrong-shaped and slow; we need
`ByteVec = Array UInt8` plus `Bytes32 = { v : ByteVec // v.size = 32 }`
etc. — at minimum as `abbrev`s.

**Body**: Add `Verity.EVM.Bytes` module with `ByteVec`, `Bytes32`,
`Bytes16`, `Bytes4` and helper lemmas (`size_eq`, `extract`,
`getElem?`).

### Issue #2 — `[EDSL] Expose Uint256 bit-ops at EDSL level`

**Body**: Three new `Contract`-monad actions `shl`, `shr`, `and` over
`Uint256`, axiomatised with EVM semantics. Yul codegen via existing
`call("shl", ...)` IR node.

### Issue #3 — `[EDSL] Add Verity.Crypto.Sha256 with precompile axiom`

**Body**: `axiom sha256 : ByteVec → Bytes32` + `axiom sha256_size`
+ `axiom sha256_deterministic`. Yul codegen produces
`staticcall(gas, 0x02, in_off, in_len, out_off, 32)`. The Layer-3
equivalence proof must show the Yul `staticcall(0x02, ...)` returns
`sha256(input)`.

### Issue #4 — `[EDSL] Add Verity.EVM.Calldata` with `read`/`copy`

**Body**: `def calldataRead : Nat → Contract (Option Uint256)` (read
one 32-byte slot; `None` if out of bounds). Yul codegen: `calldataload`.

### Issue #5 — `[EDSL] Add memory.scratch with disjoint-frame axiom`

**Body**: `structure ScratchRegion { offset, size }` + axioms about
write-disjoint regions not interfering. Required for the C10
verifier's three-phase reuse of `[0x80 + i*0x20]`.

### Issue #6 — `[Storage] Add Verity.Storage.Namespaced for ERC-7201`

**Body**: `NamespacedStorage` parametrised by a `Bytes32` slot
literal. Required by Part A's `PQMultiOwnable` and by the wallet's
storage isolation.

### Issue #7 — `[EDSL] Add external call with frame-separation`

**Body**: `extCall : Address → Uint256 → ByteVec → Contract (Bool ×
ByteVec)` + axiom that `extCall` cannot touch our `NamespacedStorage`
namespace (P3 of Part A's Step-0 spike).

## 5. Status / next steps

- **2026-05-11**: this primitive-map landed alongside the pure-Lean
  reference implementation at `contracts/verity/PQSigner/Verifier/`.
  The reference implementation does NOT depend on any of the missing
  Verity primitives — it uses Lean stdlib types (`Array UInt8`,
  `Nat`, `UInt32`, `UInt64`) and an opaque `sha256` axiom.

- **Until Phase 0 lands**: the pure-Lean reference + the multi-vector
  KAT diff harness (`contracts/smart-wallet/test/c10_test_vectors.json`)
  + the Foundry tests (`contracts/smart-wallet/test/SPHINCsC10Asm.t.sol`)
  + the deployed Yul verifier form a closed loop. Verifier soundness
  is empirically witnessed; the Lean port machine-checks the
  parameter-set / forced-zero / target_sum / branchless-swap /
  length-enforcement / ADRS-layout invariants.

- **Once Phase 0 lands**: the pure-Lean reference can be re-pointed
  at Verity's actual primitives, the codegen pipeline emits Yul, and
  the chain becomes: Lean spec → Verity-emitted Yul → solc 0.8.33 →
  bytecode. The `verify_byte_equivalent_to_rust` axiom at
  `Top.lean:113` is the final theorem at that point.

- **Fork vs upstream**: the handoff §4 Phase 0 mandates "if upstream
  refuses, fork". Recommended approach: open the seven issues above
  in a single thread (referencing this doc); offer to bring them in
  as PRs over 2–3 months. If maintainers decline, fork and add the
  primitives in a `verity-pqsigner` branch.

## 6. Footguns specific to Phase 0

1. **`Verity.Core.Bytes := List Nat`** is the wrong representation
   for crypto work. Performance and proof ergonomics both suffer
   compared to `Array UInt8`. The upstream maintainers may push
   back on changing this; if so, we layer `Verity.EVM.Bytes` on top
   and convert at the boundaries.

2. **Verity's `Address := String`** is non-standard. For our
   purposes we don't need `Address` arithmetic; treating it as
   opaque is fine. But the `keccak256` axiom for ERC-7201 storage
   slots needs to operate on byte strings, not `String`s — so we
   may need a `Bytes20` overlay for the ERC-7201 derivation.

3. **The `Contract` monad gates every action through `ContractState`**.
   That's fine for stateful examples (Counter etc.) but for a
   stateless `verify` function we want a pure function returning
   `Bool`. Need a `pureView : Contract α → α` or similar projection
   axiomatised under "no state side-effects."

4. **Verity has no `staticcall` distinction**. All external calls
   look the same. For the verifier, we need to know that
   `staticcall` cannot mutate state. Likely a layer-3 (Yul codegen)
   concern, not EDSL-level.

5. **The Compiler/Yul AST has no `mstore`/`mload`** as first-class
   statements — only via `call("mstore", ...)`. That's fine for
   codegen, but it means we can't typecheck offset arithmetic at
   the IR layer. A small AST extension would help (`mstore : YulExpr
   → YulExpr → YulStmt`) but is not strictly required.

---

**End of recon doc.** Next deliverable: write up the seven issues
above as draft Markdown bodies in a Phase-0 PR thread.
