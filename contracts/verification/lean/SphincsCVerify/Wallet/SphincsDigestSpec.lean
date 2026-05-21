/-
Spec-level theorems about `sphincsDigest`.

The two top-level statements are:

  * `sphincsDigest_preimage_len` — the preimage is exactly 360 bytes
    (definitional; the `ByteVec 360` return type carries it).

  * `sphincsDigest_field_binding` — two UserOps that produce the same
    `sphincsDigest` must agree on every preimage byte. Under the
    SHA-256 collision-resistance axiom
    (`sha256_injective_on_fixed_length`), this gives the cryptographic
    binding the wallet relies on: a signed digest commits to the
    sender, nonce, chainId, and the SHA-256 of callData (etc.).

The second theorem is what Claim 1 — "signature-to-execution binding" —
needs at the cryptographic layer. The operational layer (the H-3
transient-storage parity check ensuring the same op flows through
validation and execution) is in `Wallet/Execute.lean`.
-/

import SphincsCVerify.Wallet.ValidateUserOp
import SphincsCVerify.Crypto.Assumptions

namespace SphincsCVerify.Wallet.SphincsDigestSpec

open SphincsCVerify.Spec
open SphincsCVerify.Crypto
open SphincsCVerify.Wallet.ValidateUserOp

/-! ## Preimage length (definitional) -/

/-- The `sphincsDigest` preimage is exactly 360 bytes.

    This is by construction — `sphincsDigestPreimage` returns
    `ByteVec 360`, whose underlying `Array UInt8` has size 360 by the
    `size_eq` proof carried in the structure. -/
theorem sphincsDigest_preimage_len
    (op : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat) :
    (sphincsDigestPreimage op entryPoint chainId).data.size = 360 :=
  (sphincsDigestPreimage op entryPoint chainId).size_eq

/-! ## Cryptographic field binding

If two ops produce the same `sphincsDigest`, their preimage byte
arrays are equal (under `sha256_injective_on_fixed_length`). Since the
preimage layout is positional and uses injective encodings
(`natToB32`, `sha256OfArr`, raw `ByteVec`), equal preimages imply
equal field commitments. -/

/-- A single-segment flattening identity:
    `ByteSeg.flatten [ByteSeg.ofByteVec v] = v.data`. -/
private theorem flatten_single
    {n : Nat} (v : ByteVec n) :
    ByteSeg.flatten [ByteSeg.ofByteVec v] = v.data := by
  unfold ByteSeg.flatten ByteSeg.ofByteVec
  simp [List.foldl]

/-- **Preimage equality.** Two ops producing the same `sphincsDigest`
    have equal preimage byte arrays.

    Proof: `sphincsDigest = sha256_concat preimage = sha256
    [ofByteVec preimage]`. Both preimages flatten to a 360-byte
    array. Apply `sha256_injective_on_fixed_length` and rewrite via
    `flatten_single`. -/
theorem sphincsDigest_preimage_eq
    (op1 op2 : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (h : sphincsDigest op1 entryPoint chainId = sphincsDigest op2 entryPoint chainId) :
    (sphincsDigestPreimage op1 entryPoint chainId).data
      = (sphincsDigestPreimage op2 entryPoint chainId).data := by
  -- Convert h into the segment-list form sha256_injective_on_fixed_length expects.
  unfold sphincsDigest sha256_concat at h
  -- h : sha256 [ofByteVec preimage1] = sha256 [ofByteVec preimage2]
  -- Lengths agree by the ByteVec 360 type.
  have hlen :
      (ByteSeg.flatten [ByteSeg.ofByteVec (sphincsDigestPreimage op1 entryPoint chainId)]).size
        = (ByteSeg.flatten [ByteSeg.ofByteVec (sphincsDigestPreimage op2 entryPoint chainId)]).size := by
    rw [flatten_single, flatten_single]
    rw [(sphincsDigestPreimage op1 entryPoint chainId).size_eq,
        (sphincsDigestPreimage op2 entryPoint chainId).size_eq]
  have hflat :=
    sha256_injective_on_fixed_length
      [ByteSeg.ofByteVec (sphincsDigestPreimage op1 entryPoint chainId)]
      [ByteSeg.ofByteVec (sphincsDigestPreimage op2 entryPoint chainId)]
      hlen h
  rwa [flatten_single, flatten_single] at hflat

/-- **Field binding — preimage form.** Equal digests imply the entire
    360-byte preimage is identical (as a `ByteVec`).

    This is the cryptographic statement Claim 1 cites. Per-field
    decomposition (sender, nonce, sha256(callData), etc. are each
    pinned by their byte range) follows from the positional layout
    documented on `sphincsDigestPreimage`. -/
theorem sphincsDigest_field_binding
    (op1 op2 : UserOperation) (entryPoint : ByteVec 20) (chainId : Nat)
    (h : sphincsDigest op1 entryPoint chainId = sphincsDigest op2 entryPoint chainId) :
    sphincsDigestPreimage op1 entryPoint chainId
      = sphincsDigestPreimage op2 entryPoint chainId := by
  apply ByteVec.ext_data
  exact sphincsDigest_preimage_eq op1 op2 entryPoint chainId h

end SphincsCVerify.Wallet.SphincsDigestSpec
