(* Every ordinary FORS index is an eleven-bit index, including short digests. *)
require import AllCore List IntDiv BitEncoding Ring StdRing StdOrder.
require import RawForest StackPowers.
import BS2Int IntID IntOrder.

lemma forest_index_range digest tree : 0<=forest_index digest tree<2048.
proof.
  rewrite /forest_index; split; first exact (bs2int_ge0 _).
  have h : bs2int (take 11 (drop (11*tree) digest)) < 2^11.
  + apply/(ltr_le_trans (2^(size (take 11 (drop (11*tree) digest))))).
    - exact (bs2int_le2Xs _).
    rewrite &(ler_weexpn2l) //= size_ge0 /= &(size_take_le) //.
  smt(stack_pow2_11).
qed.
