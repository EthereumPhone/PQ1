/-
ADRS (address) construction for domain separation.

An ADRS is a 32-byte structure packed as:

```
  bytes [0..4)    layer         (u32 BE)
  bytes [4..12)   tree          (u64 BE)
  bytes [12..16)  address_type  (u32 BE)
  bytes [16..20)  keypair       (u32 BE)
  bytes [20..24)  chain_index   (u32 BE)
  bytes [24..28)  chain_pos     (u32 BE)
  bytes [28..32)  hash_address  (u32 BE)
```

Matches `sphincs-c10/src/address.rs::make_adrs` and the inline Yul
address construction in `SPHINCsC10Asm.sol`.

The encoding lives at the **byte** level, not the integer level, because
the Solidity verifier composes ADRS values via 32-byte memory writes and
bitwise OR — we model that directly so the equivalence proof in
`Bridge/Refinement.lean` is symbolic rather than arithmetic.
-/

import SphincsCVerify.Spec.Bytes
import SphincsCVerify.Spec.Params

namespace SphincsCVerify.Spec

open ByteVec

/-- An ADRS is structurally a `ByteVec 32`. We keep it as a `def` (not
    `abbrev`) so the type checker treats `Adrs` and `ByteVec 32` as
    related-via-defeq rather than identical, surfacing accidental type
    confusion in client code. -/
def Adrs : Type := ByteVec 32

namespace Adrs

/-- Build a 32-byte ADRS from its packed components. Mirrors
    `make_adrs(layer, tree, atype, kp, ci, cp, ha)` in `address.rs`. -/
def make
    (layer : UInt32)
    (tree : UInt64)
    (atype : UInt32)
    (kp : UInt32)
    (ci : UInt32)
    (cp : UInt32)
    (ha : UInt32) : Adrs :=
  cast (by decide)
    (ofU32BE layer
      |>.append (ofU64BE tree)
      |>.append (ofU32BE atype)
      |>.append (ofU32BE kp)
      |>.append (ofU32BE ci)
      |>.append (ofU32BE cp)
      |>.append (ofU32BE ha))

/-- Return a copy of `a` with the `chain_index` field (bytes [20..24)) set
    to `idx`. Mirrors `set_chain_index`. -/
def setChainIndex (a : Adrs) (idx : UInt32) : Adrs :=
  -- Replace bytes [20..24) with `ofU32BE idx`.
  let prefix4 : ByteVec 20 :=
    ⟨a.data.extract 0 20, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  let suffix : ByteVec 8 :=
    ⟨a.data.extract 24 32, by
      have : a.data.size = 32 := a.size_eq
      simp [Array.size_extract, this]⟩
  cast (by decide) (prefix4.append (ofU32BE idx) |>.append suffix)

/-! ### Convenience builders matching the Rust call-sites. -/

/-- ADRS for a WOTS chain leaf at hypertree (layer, tree, kp). -/
def wots (layer : UInt32) (tree : UInt64) (kp : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_WOTS) kp 0 0 0

/-- ADRS for the WOTS public-key compression hash at (layer, tree, kp). -/
def wotsPk (layer : UInt32) (tree : UInt64) (kp : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_WOTS_PK) kp 0 0 0

/-- ADRS for an XMSS subtree inner node at (layer, tree, height, idx). -/
def treeNode (layer : UInt32) (tree : UInt64) (height parentIdx : UInt32) : Adrs :=
  make layer tree (UInt32.ofNat ADRS_TREE) 0 0 height parentIdx

/-- ADRS for a FORS tree node at (treeIdx, height, parentIdx). -/
def forsNode (treeIdx height parentIdx : UInt32) : Adrs :=
  make 0 0 (UInt32.ofNat ADRS_FORS_TREE) treeIdx 0 height parentIdx

/-- ADRS for the FORS roots compression hash. -/
def forsRoots : Adrs :=
  make 0 0 (UInt32.ofNat ADRS_FORS_ROOTS) 0 0 0 0

end Adrs

end SphincsCVerify.Spec
