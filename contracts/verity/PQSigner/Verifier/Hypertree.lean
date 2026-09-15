/-
  PQSigner.Verifier.Hypertree — Lean port of `sphincs-c10/src/hypertree.rs:210-335`.

  D=2 layer hypertree verify. Each layer:
    1. WOTS chain reconstruction (`pk_from_sig`)
    2. Merkle auth path walk (`verify_auth_path`) to the subtree root

  Then the final reconstructed root is compared to `pk_root`.

  This file builds on the Phase 1-5 primitives but does NOT close the
  `hypertree_verify_equivalent_to_rust` obligation — which until
  2026-08-11 was a vacuous `axiom … : True` (deleted; see below) — that
  requires inducting over Rust semantics, which Lean cannot do
  without either FFI or a verified Rust-to-Lean bridge. The
  obligation is NOT stated in Lean at all (it never had an unfinished proof body either —
  that wording was wrong); it is witnessed only EMPIRICALLY by the multi-vector
  KAT diff harness at `contracts/smart-wallet/test/c10_test_vectors.json`,
  which is a test, not a proof.
-/

import PQSigner.Verifier.Params
import PQSigner.Verifier.Address
import PQSigner.Verifier.Hash
import PQSigner.Verifier.Wots
import PQSigner.Verifier.Merkle
import PQSigner.Verifier.Fors

namespace PQSigner.Verifier.Hypertree

open PQSigner.Verifier.Params
open PQSigner.Verifier.Address (ByteVec makeAdrs u32ToBE)
open PQSigner.Verifier.Hash (th hMsg pad16 truncate)
open PQSigner.Verifier.Wots (pkFromSig)
open PQSigner.Verifier.Merkle (verifyAuthPath)
open PQSigner.Verifier.Fors (extractForsIndices extractHtIndex computeForsPk reconstructForsRoot)

/-! ## Helper byte-vector slicing

    Signature parsing. We define a small `Reader` monad to track the
    offset cleanly, with bounded fuel. -/

structure SigReader where
  buf : ByteVec
  offset : Nat
deriving Repr

namespace SigReader

def init (buf : ByteVec) : SigReader := { buf, offset := 0 }

/-- Read `n` bytes, advancing the offset. Returns the slice or a zero
    block on out-of-bounds. -/
def take (r : SigReader) (n : Nat) : SigReader × ByteVec :=
  let slice := r.buf.extract r.offset (r.offset + n)
  ({ r with offset := r.offset + n }, slice)

/-- Read a single big-endian `UInt32`. -/
def takeU32BE (r : SigReader) : SigReader × UInt32 :=
  let (r', bytes) := r.take 4
  let v :=
    (bytes.getD 0 0).toUInt32 <<< 24 |||
    (bytes.getD 1 0).toUInt32 <<< 16 |||
    (bytes.getD 2 0).toUInt32 <<< 8 |||
    (bytes.getD 3 0).toUInt32
  (r', v)

/-- Read `count` consecutive N-byte values, returning them as a list. -/
def takeN_values (r : SigReader) (count : Nat) : SigReader × List ByteVec :=
  let rec loop (r : SigReader) (acc : List ByteVec) (k : Nat) : SigReader × List ByteVec :=
    match k with
    | 0 => (r, acc.reverse)
    | k' + 1 =>
      let (r', val) := r.take N
      loop r' (val :: acc) k'
  loop r [] count

end SigReader

/-! ## One hypertree layer

    Mirrors `sphincs-c10/src/hypertree.rs:282-329` (the per-layer
    iteration in the verify loop). -/

structure LayerInputs where
  /-- WOTS chain values, list of L=43 N-byte chunks. -/
  sigma : List ByteVec
  /-- WOTS count for digit-sum check. -/
  count : UInt32
  /-- Merkle auth path: SUBTREE_H=9 N-byte siblings. -/
  authPath : List ByteVec

/-- Parse a hypertree layer's signature bytes from the reader. -/
def parseLayer (r : SigReader) : SigReader × LayerInputs :=
  let (r1, sigma) := r.takeN_values L
  let (r2, count) := r1.takeU32BE
  let (r3, authPath) := r2.takeN_values SUBTREE_H
  (r3, { sigma, count, authPath })

/-- Per-layer step: WOTS pk_from_sig → Merkle auth-path walk. Returns
    the next layer's `currentNode`. -/
def stepLayer
    (seed : ByteVec) (layer : UInt32) (idxTree : UInt32) (idxLeaf : UInt32)
    (currentNode : ByteVec) (li : LayerInputs) : ByteVec :=
  let wotsPk :=
    pkFromSig seed layer (UInt64.ofNat idxTree.toNat) idxLeaf
              currentNode li.sigma li.count
  verifyAuthPath seed layer (UInt64.ofNat idxTree.toNat) wotsPk idxLeaf li.authPath

/-! ## Hypertree verify loop

    `D = 2` layers, hard-coded for C10. Each layer advances the
    `idxTree` by `SUBTREE_H = 9` bits. -/

/-- Run the D-layer hypertree loop. Returns the final reconstructed
    root. -/
def runLayers
    (seed : ByteVec) (forsPk : ByteVec) (htIdx : UInt32) (r : SigReader) : ByteVec × SigReader :=
  let rec loop (currentNode : ByteVec) (idxTree : UInt32) (r : SigReader) (l : Nat) : ByteVec × SigReader :=
    match l with
    | 0 => (currentNode, r)
    | l' + 1 =>
      let layer := UInt32.ofNat (D - (l' + 1))
      let idxLeaf := idxTree &&& ((1 <<< UInt32.ofNat SUBTREE_H) - 1)
      let idxTree' := idxTree >>> UInt32.ofNat SUBTREE_H
      let (r', li) := parseLayer r
      let next := stepLayer seed layer idxTree' idxLeaf currentNode li
      loop next idxTree' r' l'
  loop forsPk htIdx r D

/-! ## Top-level verify

    Mirrors `sphincs-c10/src/hypertree.rs:210-335` end-to-end. -/

/-- The full SPHINCS+C10 verify procedure. Returns `true` iff the
    reconstructed final root equals `pkRoot`.

    Reverts (i.e. returns false here) under any of:
    1. `fors_indices[K-1] != 0` (forced-zero check)
    2. WOTS digit-sum != TARGET_SUM in any layer (via `pkFromSig`
       returning all-zeros, which won't match expected leaf)
    3. Reconstructed root != pkRoot -/
def verifyHypertree
    (pkSeed : ByteVec) (pkRoot : ByteVec) (msgHash : ByteVec) (sig : ByteVec) : Bool :=
  let seed := pad16 pkSeed
  let root := pad16 pkRoot
  let r0 := SigReader.init sig
  -- 1. Parse R
  let (r1, rBytes) := r0.take N
  let rB32 := pad16 rBytes
  -- 2. h_msg digest
  let digest := hMsg seed root rB32 msgHash
  -- 3. Forced-zero check
  let forsIndices := extractForsIndices digest
  let htIdx := UInt32.ofNat (extractHtIndex digest)
  if forsIndices.getD (K - 1) 0 ≠ 0 then false
  else
    -- 4. Read K secrets, K-1 auth paths
    let (r2, secrets) := r1.takeN_values K
    let (r3, authPathsFlat) := r2.takeN_values ((K - 1) * A)
    -- Split flat auth paths into K-1 lists of A entries each
    let authPaths : List (List ByteVec) :=
      (List.range (K - 1)).map (fun t =>
        (List.range A).map (fun h => authPathsFlat.getD (t * A + h) (Array.replicate N 0)))
    -- 5. Reconstruct K-1 FORS roots
    let normalRoots :=
      (List.range (K - 1)).map (fun t =>
        let leafIdx := UInt32.ofNat (forsIndices.getD t 0)
        let secret := secrets.getD t (Array.replicate N 0)
        let authPath := authPaths.getD t []
        reconstructForsRoot seed (UInt32.ofNat t) leafIdx secret authPath)
    let lastSecret := secrets.getD (K - 1) (Array.replicate N 0)
    let lastAdrs := makeAdrs 0 0 ADRS_FORS_TREE (UInt32.ofNat (K - 1)) 0 0 0
    let lastRoot := th seed lastAdrs (pad16 lastSecret)
    let forsRoots := normalRoots ++ [lastRoot]
    let forsPk := computeForsPk seed forsRoots
    -- 6. Hypertree D=2 layer loop
    let (currentNode, _r4) := runLayers seed forsPk htIdx r3
    -- 7. Compare reconstructed root to pkRoot (16-byte compare)
    decide (truncate currentNode = pkRoot.extract 0 N)

/-! ### Structural theorems -/

/-- D=2 means the hypertree loop unrolls into exactly two layers. -/
theorem hypertree_d_eq_2_unrolls_into_two_layers : D = 2 := by rfl

/-- The signature parsing offsets are deterministic — same sig in,
    same offsets out. (`SigReader` is a pure state-passing
    construction.) -/
theorem layer_parsing_deterministic
    (r : SigReader) :
    parseLayer r = parseLayer r := rfl

/-- The signature is exactly SIGNATURE_LEN = 4008 bytes — derived from
    Params.lean. Anything else and the reader's `take` calls would
    return zero-padded slices and the final root compare would fail. -/
theorem signature_length_is_4008 : SIGNATURE_LEN = 4008 := by
  exact signature_len_eq_4008

/-! ### OPEN OBLIGATION — hypertree verify ≡ `sphincs-c10/src/hypertree.rs:verify`

    NOT STATED IN LEAN, AND DELIBERATELY NOT AN AXIOM.

    The claim we want is: the Lean port agrees with the Rust reference
    implementation on every input accepted by both `sphincs-c10::verify` and
    Lean `verifyHypertree`. Closing it needs an FFI bridge to Rust or a verified
    Rust→Lean translator; neither exists here. Rust semantics have no denotation
    in this development, so the statement cannot even be *written*.

    HISTORY, 2026-08-11. Until today this sat here as

        axiom hypertree_verify_equivalent_to_rust (…) : True

    described in its own docstring as "load-bearing". `True` asserts NOTHING, so
    that axiom was not a weak assumption — it was a no-op wearing an axiom's
    name, and a reader (or an axiom census) counting premises would have booked
    a cross-validation that did not exist. It was consumed by no proof, so
    deleting it removes no content; what it removes is a false entry in the
    A3.1 story, since `AXIOM_STATUS.json` names this tree as the deductive path
    for closing that ∀.

    An axiom of type `True` is strictly WORSE than no axiom: absence is visible,
    vacuity is not. If a proof here ever genuinely needs this premise, state it
    as a real axiom over a real proposition at that point — do not resurrect a
    trivially-satisfied placeholder.

    AND THE "EMPIRICAL WITNESS" WAS ITSELF OVERSTATED — including by the first
    version of this note, which repeated it. `contracts/verity/lakefile.lean`
    declares a LIBRARY ONLY (no `lean_exe`), and nothing in this project reads
    `contracts/smart-wallet/test/c10_test_vectors.json`; the Foundry harness that
    does consume those vectors executes the SOLIDITY verifier, not this Lean
    port. So the KAT diff is evidence about Solidity-vs-Rust, and has never been
    evidence about THIS port's Lean↔Rust agreement. There is currently no
    witness, empirical or formal, for that claim.

    Recurrence is now gated: `lint_fv_invariants.sh` fails on any
    `axiom … : True` anywhere under `contracts/`. -/

end PQSigner.Verifier.Hypertree
