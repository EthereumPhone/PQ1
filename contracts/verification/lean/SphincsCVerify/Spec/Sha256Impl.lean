/-
FIPS 180-4 SHA-256 — kernel-computable reference implementation.

Ported from the Trail of Bits scroll-fv reference
(`Spec/SHA256/SHA256.lean`, github.com/trailofbits/scroll-fv) with two
adaptations:

  1. No Mathlib dependency: we use core Lean's `BitVec` from `Init.Data.BitVec`
     rather than `Mathlib.Data.BitVec`. The SHA-256 round/schedule
     definitions are unchanged.

  2. Byte I/O uses `UInt8` (and ultimately `ByteVec n`) instead of
     `BitVec 8`, matching the rest of this project's byte layer. The
     conversions are constant-time and definitionally transparent.

This module exists to replace the historical `opaque sha256 : List
ByteSeg → ByteVec 32` in `Spec/Hash.lean` with a *kernel-computable*
definition. With this in hand:

  * NIST CAVS test vectors (`SHA-256("")`, `SHA-256("abc")`, NIST one-
    and two-block) reduce by `decide` / `native_decide`.
  * The `Verifier/Equivalence.lean` refinement lemmas can lean on
    byte-level offset arithmetic without going through an opaque seal.
  * The cryptographic axioms in `Crypto/Assumptions.lean` are untouched
    — they remain abstract postulates about the *function* `sha256`,
    which now happens to also be definitionally equal to this
    FIPS 180-4 implementation. The Lean kernel never has to *compute*
    SHA-256 to verify the EUF-CMA argument; computability is a strict
    strengthening of the prior opaque-only treatment.

Reference: NIST FIPS 180-4, § 6.2.2.
-/

namespace SphincsCVerify.Spec.Sha256Impl

/-! ## Word types and constants -/

abbrev Word : Type := BitVec 32

/-- Number of compression rounds (FIPS 180-4 § 6.2.2). -/
def Rounds : Nat := 64

/-- Number of 32-bit words in the hash state / digest. -/
def DigestWords : Nat := 8

/-- Number of 32-bit words in one message block (512 bits / 32). -/
def BlockWords : Nat := 16

/-! ## Bit-level operations (FIPS 180-4 § 4.1.2) -/

/-- Right-rotate by `n` bit positions: `(x >>> n) | (x <<< (32 - n))`. -/
@[inline] def rotr (x : Word) (n : Nat) : Word :=
  (x >>> n) ||| (x <<< (32 - n))

/-- Ch(e, f, g) = (e AND f) XOR (NOT e AND g). -/
@[inline] def ch (e f g : Word) : Word :=
  (e &&& f) ^^^ ((~~~ e) &&& g)

/-- Maj(a, b, c) = (a AND b) XOR (a AND c) XOR (b AND c). -/
@[inline] def maj (a b c : Word) : Word :=
  (a &&& b) ^^^ (a &&& c) ^^^ (b &&& c)

/-- Σ₀(x) = ROTR²(x) ⊕ ROTR¹³(x) ⊕ ROTR²²(x). -/
@[inline] def bigSigma0 (x : Word) : Word :=
  rotr x 2 ^^^ rotr x 13 ^^^ rotr x 22

/-- Σ₁(x) = ROTR⁶(x) ⊕ ROTR¹¹(x) ⊕ ROTR²⁵(x). -/
@[inline] def bigSigma1 (x : Word) : Word :=
  rotr x 6 ^^^ rotr x 11 ^^^ rotr x 25

/-- σ₀(x) = ROTR⁷(x) ⊕ ROTR¹⁸(x) ⊕ SHR³(x). -/
@[inline] def smallSigma0 (x : Word) : Word :=
  rotr x 7 ^^^ rotr x 18 ^^^ (x >>> 3)

/-- σ₁(x) = ROTR¹⁷(x) ⊕ ROTR¹⁹(x) ⊕ SHR¹⁰(x). -/
@[inline] def smallSigma1 (x : Word) : Word :=
  rotr x 17 ^^^ rotr x 19 ^^^ (x >>> 10)

/-! ## Constants (FIPS 180-4 § 5.3.3 + § 4.2.2) -/

/-- Initial hash values H⁽⁰⁾ — first 32 bits of fractional parts of
    √2 ‥ √19. -/
def H0 : Array Word := #[
  0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
  0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
]

/-- 64 round constants K — first 32 bits of fractional parts of cube
    roots of the first 64 primes. -/
def K : Array Word := #[
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
  0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
  0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
  0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
  0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
  0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
  0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
  0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
  0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

/-! ## Message schedule (FIPS 180-4 § 6.2.2, Step 1) -/

/-- Expand a 16-word block to a 64-word message schedule.

    For 16 ≤ t < 64:
      W[t] = σ₁(W[t-2]) + W[t-7] + σ₀(W[t-15]) + W[t-16] -/
def messageSchedule (block : Array Word) : Array Word :=
  let rec expand (w : Array Word) (t : Nat) : Array Word :=
    if t ≥ 64 then w
    else
      let wt :=
        smallSigma1 (w.getD (t - 2) 0) +
        (w.getD (t - 7) 0) +
        smallSigma0 (w.getD (t - 15) 0) +
        (w.getD (t - 16) 0)
      expand (w.push wt) (t + 1)
  termination_by 64 - t
  expand block 16

/-! ## Working variables -/

/-- The eight working variables `a, b, c, d, e, f, g, h`. -/
structure Working where
  a : Word
  b : Word
  c : Word
  d : Word
  e : Word
  f : Word
  g : Word
  h : Word
deriving Repr, DecidableEq

/-- Read working variables from an 8-word state array. -/
def Working.ofArray (s : Array Word) : Working :=
  { a := s.getD 0 0, b := s.getD 1 0, c := s.getD 2 0, d := s.getD 3 0,
    e := s.getD 4 0, f := s.getD 5 0, g := s.getD 6 0, h := s.getD 7 0 }

/-- Pack working variables into an 8-word array. -/
def Working.toArray (w : Working) : Array Word :=
  #[w.a, w.b, w.c, w.d, w.e, w.f, w.g, w.h]

/-! ## Compression round (FIPS 180-4 § 6.2.2, Step 3) -/

/-- Single compression round at position `t`. -/
def round (w : Working) (kt wt : Word) : Working :=
  let t1 := w.h + bigSigma1 w.e + ch w.e w.f w.g + kt + wt
  let t2 := bigSigma0 w.a + maj w.a w.b w.c
  { a := t1 + t2
  , b := w.a
  , c := w.b
  , d := w.c
  , e := w.d + t1
  , f := w.e
  , g := w.f
  , h := w.g }

/-- Run all 64 rounds of the compression function. -/
def runRounds (schedule : Array Word) (w0 : Working) : Working :=
  let rec go (t : Nat) (w : Working) : Working :=
    if t ≥ 64 then w
    else go (t + 1) (round w (K.getD t 0) (schedule.getD t 0))
  termination_by 64 - t
  go 0 w0

/-- Element-wise addition of two 8-word states (mod 2³², per `BitVec` `+`). -/
def stateAdd (x y : Array Word) : Array Word :=
  let rec go (i : Nat) (acc : Array Word) : Array Word :=
    if i ≥ x.size then acc
    else go (i + 1) (acc.push ((x.getD i 0) + (y.getD i 0)))
  termination_by x.size - i
  go 0 #[]

/-- Full compression function for one 512-bit block (FIPS 180-4
    § 6.2.2, Steps 1-4). -/
def compress (h : Array Word) (block : Array Word) : Array Word :=
  let schedule := messageSchedule block
  let w := runRounds schedule (Working.ofArray h)
  stateAdd h w.toArray

/-! ## Byte/word conversions (big-endian) -/

/-- Convert a `UInt8` to a `Word`, value in `[0, 256)`. -/
@[inline] def u8ToWord (b : UInt8) : Word :=
  BitVec.ofNat 32 b.toNat

/-- Convert a `Word` to a `UInt8`, taking the low 8 bits. -/
@[inline] def wordLowU8 (w : Word) : UInt8 :=
  UInt8.ofNat (w.toNat &&& 0xFF)

/-- Extract the byte at position `pos` (0 = MSB, 3 = LSB) of a 32-bit
    big-endian word. -/
@[inline] def wordByteBE (w : Word) (pos : Nat) : UInt8 :=
  wordLowU8 (w >>> (8 * (3 - pos)))

/-- Pack 4 bytes big-endian into one `Word`. -/
@[inline] def bytesToWordBE (b0 b1 b2 b3 : UInt8) : Word :=
  (u8ToWord b0 <<< 24) ||| (u8ToWord b1 <<< 16) |||
  (u8ToWord b2 <<< 8)  ||| u8ToWord b3

/-- Convert an `Array UInt8` (length multiple of 4) into an array of
    big-endian `Word`s. -/
def bytesToWords (bytes : Array UInt8) : Array Word :=
  let nWords := bytes.size / 4
  let rec go (i : Nat) (acc : Array Word) : Array Word :=
    if i ≥ nWords then acc
    else
      let w := bytesToWordBE
                  (bytes.getD (4 * i) 0)
                  (bytes.getD (4 * i + 1) 0)
                  (bytes.getD (4 * i + 2) 0)
                  (bytes.getD (4 * i + 3) 0)
      go (i + 1) (acc.push w)
  termination_by nWords - i
  go 0 #[]

/-- Convert an array of big-endian `Word`s into bytes. -/
def wordsToBytes (words : Array Word) : Array UInt8 :=
  let rec go (i : Nat) (acc : Array UInt8) : Array UInt8 :=
    if i ≥ words.size then acc
    else
      let w := words.getD i 0
      go (i + 1)
        (((acc.push (wordByteBE w 0)).push (wordByteBE w 1)).push
           (wordByteBE w 2) |>.push (wordByteBE w 3))
  termination_by words.size - i
  go 0 #[]

/-! ## Padding (FIPS 180-4 § 5.1.1) -/

/-- Number of zero-padding bytes between the `0x80` byte and the 64-bit
    length suffix so the total length is a multiple of 64. -/
def zeroPadCount (msgLen : Nat) : Nat :=
  -- After appending 0x80 and the 8-byte length we want the total
  -- length to be divisible by 64.
  let used := (msgLen + 1 + 8) % 64
  if used = 0 then 0 else 64 - used

/-- Big-endian 8-byte encoding of a 64-bit value. -/
def encodeBE64 (n : Nat) : Array UInt8 :=
  #[ UInt8.ofNat ((n >>> 56) &&& 0xFF)
   , UInt8.ofNat ((n >>> 48) &&& 0xFF)
   , UInt8.ofNat ((n >>> 40) &&& 0xFF)
   , UInt8.ofNat ((n >>> 32) &&& 0xFF)
   , UInt8.ofNat ((n >>> 24) &&& 0xFF)
   , UInt8.ofNat ((n >>> 16) &&& 0xFF)
   , UInt8.ofNat ((n >>>  8) &&& 0xFF)
   , UInt8.ofNat ( n         &&& 0xFF) ]

/-- An array of `n` zero bytes. -/
def zeroBytes (n : Nat) : Array UInt8 :=
  Array.replicate n (0 : UInt8)

/-- FIPS 180-4 § 5.1.1 padding: append `0x80`, zero-pad to a 56-mod-64
    boundary, then append the 64-bit big-endian bit length. -/
def pad (msg : Array UInt8) : Array UInt8 :=
  let bitLen : Nat := msg.size * 8
  let nZeros : Nat := zeroPadCount msg.size
  ((msg.push (0x80 : UInt8)) ++ zeroBytes nZeros) ++ encodeBE64 bitLen

/-- Split a padded byte array (size divisible by 64) into 64-byte
    blocks; each block is represented as 16 big-endian `Word`s. -/
def toBlocks (padded : Array UInt8) : Array (Array Word) :=
  let nBlocks := padded.size / 64
  let rec go (i : Nat) (acc : Array (Array Word)) : Array (Array Word) :=
    if i ≥ nBlocks then acc
    else
      let blockBytes := padded.extract (64 * i) (64 * i + 64)
      go (i + 1) (acc.push (bytesToWords blockBytes))
  termination_by nBlocks - i
  go 0 #[]

/-! ## Full SHA-256 -/

/-- Compute SHA-256 over a byte sequence, returning an 8-word state. -/
def sha256Words (msg : Array UInt8) : Array Word :=
  let padded := pad msg
  let blocks := toBlocks padded
  blocks.foldl compress H0

/-- Compute SHA-256 over a byte sequence, returning a 32-byte digest. -/
def sha256Bytes (msg : Array UInt8) : Array UInt8 :=
  wordsToBytes (sha256Words msg)

/-! ## Size lemma

`sha256Bytes` always returns exactly 32 bytes. Used by the wrapper in
`Spec/Hash.lean` to package the output as a `ByteVec 32`. We do not
prove the FIPS 180-4 mathematical correctness lemma here — that
property is what the cryptographic axioms in `Crypto/Assumptions.lean`
range over. -/

/-- Helper: `wordsToBytes.go` pushes exactly four bytes per word it
    consumes, so its output size is exactly `4 * remaining`. -/
private theorem wordsToBytes_go_size
    (words : Array Word) :
    ∀ (i : Nat) (acc : Array UInt8),
      (wordsToBytes.go words i acc).size =
        acc.size + 4 * (words.size - i) := by
  intro i acc
  induction h : words.size - i generalizing i acc with
  | zero =>
    unfold wordsToBytes.go
    have hge : i ≥ words.size := by omega
    simp [hge]
  | succ k ih =>
    unfold wordsToBytes.go
    have hlt : ¬ (i ≥ words.size) := by omega
    simp only [hlt, if_false]
    have ih' := ih (i + 1)
      ((((acc.push (wordByteBE (words.getD i 0) 0)).push
           (wordByteBE (words.getD i 0) 1)).push
           (wordByteBE (words.getD i 0) 2)).push
           (wordByteBE (words.getD i 0) 3))
      (by omega)
    rw [ih']
    simp [Array.size_push]
    omega

/-- `wordsToBytes` of an 8-word state yields 32 bytes. -/
theorem wordsToBytes_size_of_eight (words : Array Word)
    (h : words.size = 8) :
    (wordsToBytes words).size = 32 := by
  unfold wordsToBytes
  have hgo := wordsToBytes_go_size words 0 #[]
  simp at hgo
  rw [hgo, h]

/-- Helper: `stateAdd.go` pushes exactly one element per index from
    0..x.size. -/
private theorem stateAdd_go_size (x y : Array Word) :
    ∀ (i : Nat) (acc : Array Word),
      i ≤ x.size →
      (stateAdd.go x y i acc).size = acc.size + (x.size - i) := by
  intro i acc _hle
  induction h : x.size - i generalizing i acc with
  | zero =>
    unfold stateAdd.go
    have hge : i ≥ x.size := by omega
    simp [hge]
  | succ k ih =>
    unfold stateAdd.go
    have hlt : ¬ (i ≥ x.size) := by omega
    simp only [hlt, if_false]
    have ih' := ih (i + 1)
      (acc.push ((x.getD i 0) + (y.getD i 0))) (by omega) (by omega)
    rw [ih']
    simp [Array.size_push]
    omega

/-- `stateAdd` preserves the LHS state's size. -/
theorem stateAdd_size (x y : Array Word) :
    (stateAdd x y).size = x.size := by
  unfold stateAdd
  have := stateAdd_go_size x y 0 #[] (Nat.zero_le _)
  rw [this]; simp

/-- `Working.toArray` always has size 8. -/
theorem working_toArray_size (w : Working) :
    w.toArray.size = 8 := by
  cases w; rfl

/-- `H0` has size 8 by definition. -/
theorem H0_size : H0.size = 8 := by decide

/-- One round of `compress` preserves the state size (= 8). -/
theorem compress_preserves_size (h block : Array Word)
    (hh : h.size = 8) :
    (compress h block).size = 8 := by
  unfold compress
  rw [stateAdd_size, hh]

/-- Fold of `compress` over a list of blocks preserves state size 8. -/
private theorem list_foldl_compress_size : ∀ (blocks : List (Array Word))
    (init : Array Word), init.size = 8 →
    (blocks.foldl compress init).size = 8
  | [], init, hi => by simp [hi]
  | b :: bs, init, hi => by
    simp only [List.foldl]
    exact list_foldl_compress_size bs (compress init b)
      (compress_preserves_size _ _ hi)

/-- Fold of `compress` over a sequence of blocks preserves state size 8. -/
private theorem foldl_compress_size (blocks : Array (Array Word))
    (init : Array Word) (hi : init.size = 8) :
    (blocks.foldl compress init).size = 8 := by
  rw [← Array.foldl_toList]
  exact list_foldl_compress_size blocks.toList init hi

/-- `sha256Words` always returns an 8-word state. -/
theorem sha256Words_size (msg : Array UInt8) :
    (sha256Words msg).size = 8 := by
  unfold sha256Words
  exact foldl_compress_size _ _ H0_size

/-- `sha256Bytes` always returns a 32-byte digest. -/
theorem sha256Bytes_size (msg : Array UInt8) :
    (sha256Bytes msg).size = 32 := by
  unfold sha256Bytes
  exact wordsToBytes_size_of_eight _ (sha256Words_size msg)

end SphincsCVerify.Spec.Sha256Impl
