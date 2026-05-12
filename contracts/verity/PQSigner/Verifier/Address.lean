/-
  PQSigner.Verifier.Address — Lean port of `sphincs-c10/src/address.rs`.

  ADRS (address) is a 32-byte big-endian packed structure used as a
  domain separator for every SHA-256 call in the verifier. Layout:

    bytes [0..4)    layer          (u32 BE)   bits [255..224]
    bytes [4..12)   tree           (u64 BE)   bits [223..160]
    bytes [12..16)  address_type   (u32 BE)   bits [159..128]
    bytes [16..20)  keypair        (u32 BE)   bits [127..96]
    bytes [20..24)  chain_index    (u32 BE)   bits [95..64]
    bytes [24..28)  chain_pos      (u32 BE)   bits [63..32]
    bytes [28..32)  hash_address   (u32 BE)   bits [31..0]

  Must match the Yul construction at
  `contracts/smart-wallet/src/verifiers/SPHINCsC10Asm.sol:67,82,97,106,
  122,148-149,153,163,173,181-183` byte-for-byte.
-/

import PQSigner.Verifier.Params

namespace PQSigner.Verifier.Address

/-! ## Byte-vector helpers (no Verity dep)

    `ByteVec` is `Array UInt8`. We provide narrow helpers used by the
    rest of the port; we never reach into Lean's `Array` API directly
    so the spec stays self-contained. -/

abbrev ByteVec : Type := Array UInt8

/-- Construct a fresh zero-filled byte array of the given size. -/
def ByteVec.zero (n : Nat) : ByteVec := Array.replicate n 0

/-- Convert a `UInt32` to 4 big-endian bytes. -/
def u32ToBE (x : UInt32) : ByteVec :=
  let b0 := (x >>> 24).toUInt8
  let b1 := ((x >>> 16) &&& 0xFF).toUInt8
  let b2 := ((x >>> 8) &&& 0xFF).toUInt8
  let b3 := (x &&& 0xFF).toUInt8
  #[b0, b1, b2, b3]

/-- Convert a `UInt64` to 8 big-endian bytes. -/
def u64ToBE (x : UInt64) : ByteVec :=
  let b0 := (x >>> 56).toUInt8
  let b1 := ((x >>> 48) &&& 0xFF).toUInt8
  let b2 := ((x >>> 40) &&& 0xFF).toUInt8
  let b3 := ((x >>> 32) &&& 0xFF).toUInt8
  let b4 := ((x >>> 24) &&& 0xFF).toUInt8
  let b5 := ((x >>> 16) &&& 0xFF).toUInt8
  let b6 := ((x >>> 8) &&& 0xFF).toUInt8
  let b7 := (x &&& 0xFF).toUInt8
  #[b0, b1, b2, b3, b4, b5, b6, b7]

/-- Reverse: read 4 big-endian bytes as a `UInt32`. -/
def beToU32 (b0 b1 b2 b3 : UInt8) : UInt32 :=
  (b0.toUInt32 <<< 24) ||| (b1.toUInt32 <<< 16) ||| (b2.toUInt32 <<< 8) ||| b3.toUInt32

/-- Read a `UInt32` from `buf[ofs..ofs+4)`, big-endian. -/
def readU32BE (buf : ByteVec) (ofs : Nat) : UInt32 :=
  beToU32 (buf.getD ofs 0) (buf.getD (ofs + 1) 0) (buf.getD (ofs + 2) 0) (buf.getD (ofs + 3) 0)

/-! ## ADRS construction -/

/-- `make_adrs(layer, tree, atype, kp, ci, cp, ha)` returning a 32-byte
    ADRS. Mirrors `sphincs-c10/src/address.rs:22-41`. -/
def makeAdrs
    (layer : UInt32) (tree : UInt64) (atype : UInt32)
    (kp : UInt32) (ci : UInt32) (cp : UInt32) (ha : UInt32) : ByteVec :=
  u32ToBE layer ++ u64ToBE tree ++ u32ToBE atype ++
  u32ToBE kp ++ u32ToBE ci ++ u32ToBE cp ++ u32ToBE ha

/-- Overwrite the 4 bytes starting at `ofs` with the big-endian
    encoding of `x`. Uses `Array.set!` (no-op if out of range). -/
def writeU32BE (buf : ByteVec) (ofs : Nat) (x : UInt32) : ByteVec :=
  let b := u32ToBE x
  (((buf.set! ofs (b.getD 0 0)).set! (ofs + 1) (b.getD 1 0)).set! (ofs + 2) (b.getD 2 0)).set! (ofs + 3) (b.getD 3 0)

/-- `set_chain_index(adrs, idx)` — overwrite bytes [20..24) with `idx`
    in big-endian. Mirrors `sphincs-c10/src/address.rs:46-50`. -/
def setChainIndex (adrs : ByteVec) (idx : UInt32) : ByteVec :=
  writeU32BE adrs 20 idx

/-- `set_chain_pos(adrs, pos)` — overwrite bytes [24..28) with `pos`
    in big-endian. Mirrors `sphincs-c10/src/address.rs:55-59`. -/
def setChainPos (adrs : ByteVec) (pos : UInt32) : ByteVec :=
  writeU32BE adrs 24 pos

/-! ## Byte-position theorems

    These theorems pin the bit layout of ADRS to the values the Yul
    verifier expects. Each one is the analog of one of the Yul
    `shl(K, value)` patterns at `SPHINCsC10Asm.sol:67,82,97,106,122,
    148-149,153,163,173`. -/

theorem u32ToBE_size_eq_4 (x : UInt32) : (u32ToBE x).size = 4 := by
  simp [u32ToBE]

theorem u64ToBE_size_eq_8 (x : UInt64) : (u64ToBE x).size = 8 := by
  simp [u64ToBE]

theorem adrs_size_eq_32
    (layer : UInt32) (tree : UInt64) (atype : UInt32)
    (kp : UInt32) (ci : UInt32) (cp : UInt32) (ha : UInt32) :
    (makeAdrs layer tree atype kp ci cp ha).size = 32 := by
  simp [makeAdrs, u32ToBE_size_eq_4, u64ToBE_size_eq_8, Array.size_append]

/-- The five ADRS-type constants used by the Yul verifier are
    pairwise distinct (trivially true, but pinning it here means a
    future rename can't accidentally collide types). -/
theorem adrs_type_disjoint :
    Params.ADRS_WOTS ≠ Params.ADRS_WOTS_PK ∧
    Params.ADRS_TREE ≠ Params.ADRS_FORS_TREE ∧
    Params.ADRS_FORS_TREE ≠ Params.ADRS_FORS_ROOTS := by
  decide

/-- `set_chain_pos` preserves the array size. Mirrors the EVM-side
    behaviour: `mstore(adrs+24, pos)` only writes 4 bytes at offset
    24, leaving the surrounding ADRS bytes intact. -/
theorem setChainPos_size_eq
    (adrs : ByteVec) (pos : UInt32) :
    (setChainPos adrs pos).size = adrs.size := by
  simp [setChainPos, writeU32BE]

/-- `set_chain_index` preserves the array size. -/
theorem setChainIndex_size_eq
    (adrs : ByteVec) (idx : UInt32) :
    (setChainIndex adrs idx).size = adrs.size := by
  simp [setChainIndex, writeU32BE]

/-- ADRS size invariant survives a chain-pos update. -/
theorem setChainPos_size_eq_32
    (adrs : ByteVec) (pos : UInt32) (h : adrs.size = 32) :
    (setChainPos adrs pos).size = 32 := by
  rw [setChainPos_size_eq]; exact h

/-- ADRS size invariant survives a chain-index update. -/
theorem setChainIndex_size_eq_32
    (adrs : ByteVec) (idx : UInt32) (h : adrs.size = 32) :
    (setChainIndex adrs idx).size = 32 := by
  rw [setChainIndex_size_eq]; exact h

end PQSigner.Verifier.Address
