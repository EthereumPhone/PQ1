/-
ByteVec: fixed-length byte arrays, the atomic data unit for everything in
the SPHINCS+ stack.

Design notes:

  We define `ByteVec n` as a structure carrying an `Array UInt8` together
  with a length proof. This:

  * Lets us reuse Lean's fast native `Array` operations for any
    concrete computation (test-vector evaluation, differential testing).
  * Carries the length proof at the type level, so the verifier signature
    `verify : ByteVec N → ByteVec N → ByteVec 32 → ByteVec SignatureLen → Bool`
    is impossible to call with mismatched lengths.

  We deliberately do **not** depend on Mathlib — the byte layer only
  needs core Lean's `Array` / `Nat` / `UInt8` primitives, and the
  cryptographic-game layer (`Crypto/`) sits at the spec level. A future
  engagement that mechanises the EUF-CMA proof in Lean would import
  mathlib for `Finset` / `MeasureTheory`.
-/

namespace SphincsCVerify.Spec

/-- A fixed-length byte vector. -/
structure ByteVec (n : Nat) where
  data : Array UInt8
  size_eq : data.size = n
deriving DecidableEq

namespace ByteVec

/-- Cast across a proof of length equality. -/
@[inline]
def cast {m n : Nat} (h : m = n) (v : ByteVec m) : ByteVec n :=
  ⟨v.data, h ▸ v.size_eq⟩

/-- Total `get` indexed by `Fin n`. -/
@[inline]
def get {n : Nat} (v : ByteVec n) (i : Fin n) : UInt8 :=
  let i' : Fin v.data.size := i.cast v.size_eq.symm
  v.data[i']

/-- The all-zero byte vector. -/
def zero (n : Nat) : ByteVec n :=
  ⟨Array.replicate n (0 : UInt8), by simp⟩

/-- The all-`0xFF` byte vector — used inside `H_msg` for domain separation. -/
def ones (n : Nat) : ByteVec n :=
  ⟨Array.replicate n (0xFF : UInt8), by simp⟩

/-- Concatenation `xs ++ ys`. -/
def append {m n : Nat} (xs : ByteVec m) (ys : ByteVec n) : ByteVec (m + n) :=
  ⟨xs.data ++ ys.data, by
    simp [xs.size_eq, ys.size_eq]⟩

instance {m n : Nat} : HAppend (ByteVec m) (ByteVec n) (ByteVec (m + n)) where
  hAppend := ByteVec.append

/-- Take the first `k` bytes; requires `k ≤ n`. -/
def take {n : Nat} (v : ByteVec n) (k : Nat) (h : k ≤ n) : ByteVec k :=
  ⟨v.data.extract 0 k, by
    have hsize : v.data.size = n := v.size_eq
    simp [Array.size_extract, hsize, Nat.min_eq_left h]⟩

/-- Drop the first `k` bytes; requires `k ≤ n`. -/
def drop {n : Nat} (v : ByteVec n) (k : Nat) (_h : k ≤ n) : ByteVec (n - k) :=
  ⟨v.data.extract k n, by
    have hsize : v.data.size = n := v.size_eq
    simp [Array.size_extract, hsize]⟩

/-- Encode a `UInt32` in big-endian as 4 bytes. -/
def ofU32BE (x : UInt32) : ByteVec 4 :=
  let b0 : UInt8 := UInt8.ofNat (((x.toNat >>> 24)) &&& 0xFF)
  let b1 : UInt8 := UInt8.ofNat (((x.toNat >>> 16)) &&& 0xFF)
  let b2 : UInt8 := UInt8.ofNat (((x.toNat >>>  8)) &&& 0xFF)
  let b3 : UInt8 := UInt8.ofNat ((x.toNat) &&& 0xFF)
  ⟨#[b0, b1, b2, b3], by simp⟩

/-- Encode a `UInt64` in big-endian as 8 bytes. -/
def ofU64BE (x : UInt64) : ByteVec 8 :=
  let b0 : UInt8 := UInt8.ofNat (((x.toNat >>> 56)))
  let b1 : UInt8 := UInt8.ofNat (((x.toNat >>> 48)) &&& 0xFF)
  let b2 : UInt8 := UInt8.ofNat (((x.toNat >>> 40)) &&& 0xFF)
  let b3 : UInt8 := UInt8.ofNat (((x.toNat >>> 32)) &&& 0xFF)
  let b4 : UInt8 := UInt8.ofNat (((x.toNat >>> 24)) &&& 0xFF)
  let b5 : UInt8 := UInt8.ofNat (((x.toNat >>> 16)) &&& 0xFF)
  let b6 : UInt8 := UInt8.ofNat (((x.toNat >>>  8)) &&& 0xFF)
  let b7 : UInt8 := UInt8.ofNat ((x.toNat) &&& 0xFF)
  ⟨#[b0, b1, b2, b3, b4, b5, b6, b7], by simp⟩

/-- Pad a 16-byte value into a 32-byte EVM word: value in bytes [0..16),
    bottom 16 bytes zero. Matches `pad16` in `sphincs-c10/src/hash.rs`. -/
def pad16 (v : ByteVec 16) : ByteVec 32 :=
  cast (by decide) (v.append (zero 16))

/-- Encode a `UInt32` as a 32-byte big-endian uint256
    (value in bytes [28..32)). -/
def u32ToB32 (x : UInt32) : ByteVec 32 :=
  cast (by decide) ((zero 28).append (ofU32BE x))

/-- Encode a `UInt64` as a 32-byte big-endian uint256
    (value in bytes [24..32)). -/
def u64ToB32 (x : UInt64) : ByteVec 32 :=
  cast (by decide) ((zero 24).append (ofU64BE x))

/-- Encode a `Nat` as a 32-byte big-endian uint256. Only the bottom
    256 bits of `x` are used (matches Solidity `uint256` semantics).
    The encoding is byte-equal to `abi.encodePacked(uint256(x))`. -/
def natToB32 (x : Nat) : ByteVec 32 :=
  ⟨Array.ofFn (n := 32) (fun (i : Fin 32) =>
     UInt8.ofNat ((x >>> ((31 - i.val) * 8)) &&& 0xff)),
   by simp [Array.size_ofFn]⟩

/-- Truncate a 32-byte digest to the top `N = 16` bytes. -/
def truncate16 (d : ByteVec 32) : ByteVec 16 :=
  d.take 16 (by decide)

/-- Extensionality for `ByteVec`: equal `data` implies equal `ByteVec`s.
    The `size_eq` proofs are identical by proof irrelevance. -/
theorem ext_data {n : Nat} {a b : ByteVec n} (h : a.data = b.data) : a = b := by
  cases a; cases b; subst h; rfl

/-! ## Calldata-shaped loads

The Solidity verifier indexes the signature blob via `calldataload` —
which reads a 32-byte word at an offset, returning zero-padded data
when the read exceeds calldata. We model that here so the offset-indexed
verifier (`Verifier.Refined`) and the structural deserialiser
(`Spec.Signature.deserialise`) share *the same* byte-extraction primitive.
Sharing the definitions is what makes `load_R_consistent` and friends in
`Verifier/Equivalence.lean` discharge by `rfl`. -/

/-- Load a 32-byte word from a byte vector at `offset`. Out-of-bounds
    reads return zero (matches `calldataload`'s zero-padding). -/
def loadWord32 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 32 :=
  if h : offset + 32 ≤ n then
    ⟨sig.data.extract offset (offset + 32), by
      have hsize : sig.data.size = n := sig.size_eq
      simp [Array.size_extract, hsize, Nat.min_eq_left h]⟩
  else
    zero 32

/-- Load a 16-byte (N-masked) value: top 16 bytes of the 32-byte word
    at `offset`. -/
def loadValue16 {n : Nat} (sig : ByteVec n) (offset : Nat) : ByteVec 16 :=
  (loadWord32 sig offset).take 16 (by decide)

/-- Load a `UInt32` big-endian at `offset`. Used for the per-layer
    `count` field. -/
def loadU32BE {n : Nat} (sig : ByteVec n) (offset : Nat) : UInt32 :=
  let b0 := if h : offset < n then sig.get ⟨offset, h⟩ else 0
  let b1 := if h : offset + 1 < n then sig.get ⟨offset+1, h⟩ else 0
  let b2 := if h : offset + 2 < n then sig.get ⟨offset+2, h⟩ else 0
  let b3 := if h : offset + 3 < n then sig.get ⟨offset+3, h⟩ else 0
  (UInt32.ofNat b0.toNat <<< 24) |||
  (UInt32.ofNat b1.toNat <<< 16) |||
  (UInt32.ofNat b2.toNat <<< 8) |||
  (UInt32.ofNat b3.toNat)

/-! ### Concrete short literals used by the SPHINCS+C10 hashes -/

/-- The 4-byte domain tag `b"wots"`. -/
def wotsTag : ByteVec 4 :=
  ⟨#[0x77, 0x6F, 0x74, 0x73], by simp⟩  -- "wots"

/-- The 4-byte domain tag `b"fors"`. -/
def forsTag : ByteVec 4 :=
  ⟨#[0x66, 0x6F, 0x72, 0x73], by simp⟩  -- "fors"

/-- The 7-byte domain tag `b"R_grind"`. -/
def rGrindTag : ByteVec 7 :=
  ⟨#[0x52, 0x5F, 0x67, 0x72, 0x69, 0x6E, 0x64], by simp⟩  -- "R_grind"

end ByteVec

end SphincsCVerify.Spec
