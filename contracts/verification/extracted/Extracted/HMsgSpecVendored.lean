/- Verbatim version bridge for H_msg. The fidelity gate checks these
   declarations against Spec/Bytes.lean and Spec/Hash.lean. -/
import Extracted.SpecVendored
import Extracted.Sha256Vendored

namespace SphincsCVerify.Spec
namespace ByteVec
def ones (n : Nat) : ByteVec n :=
  ⟨Array.replicate n (0xFF : UInt8), by simp⟩

end ByteVec
open ByteVec

structure ByteSeg where
  size : Nat
  bytes : ByteVec size

namespace ByteSeg

/-- Coerce a fixed-length byte vector to a `ByteSeg`. -/
@[inline]
def ofByteVec {n : Nat} (v : ByteVec n) : ByteSeg :=
  ⟨n, v⟩

end ByteSeg

def ByteSeg.flatten (segs : List ByteSeg) : Array UInt8 :=
  segs.foldl (init := #[]) fun acc seg => acc ++ seg.bytes.data

/-- FIPS 180-4 SHA-256, lifted to take a list of byte segments and
    return a fixed-length `ByteVec 32`.

    This is the *concrete* SHA-256 backing every tweakable-hash and
    domain-separation primitive in the SPHINCS+C10 stack. The
    `@[irreducible]` attribute on `sha256` (below) prevents the kernel
    from unfolding the 64-round body inside unrelated tactic contexts,
    so all the existing algebraic proofs (treating `sha256` as a black
    box) keep working unchanged. When you actually want to *compute* a
    concrete digest (e.g. NIST CAVS test vectors), `unfold sha256
    sha256_impl` exposes the FIPS 180-4 reference. -/
def sha256_impl (segs : List ByteSeg) : ByteVec 32 :=
  let bytes := ByteSeg.flatten segs
  let digest := Sha256Impl.sha256Bytes bytes
  ⟨digest, Sha256Impl.sha256Bytes_size bytes⟩

/-- SHA-256 over a (length-erased) list of byte segments. Returns the
    32-byte digest. Definitionally equal to `sha256_impl`, but sealed
    by `@[irreducible]` so unrelated proofs don't accidentally try to
    reduce the round function. -/
@[irreducible] def sha256 : List ByteSeg → ByteVec 32 := sha256_impl

/-- Unfolding lemma for `sha256`. Use this (or `show sha256_impl …`) in
    proofs that need to inspect the underlying FIPS 180-4 implementation,
    e.g. NIST CAVS test-vector decision proofs. -/
theorem sha256_eq_impl (segs : List ByteSeg) :
    sha256 segs = sha256_impl segs := by
  unfold sha256
  rfl

def hMsg
    (seed root : ByteVec 32) (r : ByteVec 32) (message : ByteVec 32)
    : ByteVec 32 :=
  sha256 [
    ByteSeg.ofByteVec seed,
    ByteSeg.ofByteVec root,
    ByteSeg.ofByteVec r,
    ByteSeg.ofByteVec message,
    ByteSeg.ofByteVec (ones 32)]

end SphincsCVerify.Spec
