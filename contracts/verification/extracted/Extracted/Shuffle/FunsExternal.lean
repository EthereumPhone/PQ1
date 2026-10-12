/- Explicit functional boundaries for the shuffle extraction.
   The private RustCrypto SHA block is modeled with the existing computable
   SHA-256 specification. This does not verify the RustCrypto backend.
   Zeroize returns a discarded scratch value; as in SlotKdf, only termination
   is modeled here. No physical erasure or side-channel claim follows. -/
import Extracted.Shuffle.Types
import Extracted.Sha256Pure

open Aeneas Aeneas.Std Result

namespace sphincs_c10

@[rust_fun "zeroize::{zeroize::Zeroize<@Z>}::zeroize"]
def zeroize.Zeroize.Blanket.zeroize {Z : Type}
    (_inst : zeroize.DefaultIsZeroes Z) (z : Z) : Result Z := ok z

@[rust_fun "zeroize::{zeroize::Zeroize<[@Z; @N]>}::zeroize"]
def Array.Insts.ZeroizeZeroize.zeroize {Z : Type} {N : Std.Usize}
    (_inst : zeroize.Zeroize Z) (a : Std.Array Z N) : Result (Std.Array Z N) := ok a

def shuffle.blockPreimage (seed : Std.Array Std.U8 32#usize) (counter : Std.U32) :
    List Std.U8 :=
  ("sphincs-c10-fisher-yates-v1".toUTF8.toList.map Sha256Pure.ofUInt8) ++
  seed.val ++
  [⟨BitVec.ofNat 8 (counter.val / 2^24)⟩,
   ⟨BitVec.ofNat 8 (counter.val / 2^16)⟩,
   ⟨BitVec.ofNat 8 (counter.val / 2^8)⟩,
   ⟨BitVec.ofNat 8 counter.val⟩]

@[rust_fun "sphincs_c10::shuffle::shuffle_hash_block"]
def shuffle.shuffle_hash_block (seed : Std.Array Std.U8 32#usize) (counter : Std.U32) :
    Result (Std.Array Std.U8 32#usize) :=
  ok (sha256_pure (shuffle.blockPreimage seed counter))

end sphincs_c10
