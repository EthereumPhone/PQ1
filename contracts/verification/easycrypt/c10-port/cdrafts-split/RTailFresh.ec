(* The actual ascending nonce stream makes private R inputs distinct.
   Across signing calls, freshness still needs an explicit history condition. *)
require import AllCore List FMap BitEncoding Ring.
require import C10RawOracle C10Bytes C10Counter RoleGrind PrefixGuess.
import BS2Int.

lemma counter_bytes_injective (c d : counter) :
  counter_bytes c = counter_bytes d => c = d.
proof.
  move=> he.
  have hb : counter_bits c = counter_bits d
    by rewrite -!counter_bytes_roundtrip he.
  have hv : U32.val c = U32.val d.
  + have hc := U32.valP c; have hd := U32.valP d.
    have hp : 2^32 = 4294967296 by rewrite (_ : 32 = 2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
    have hk : bs2int (counter_bits c) = bs2int (counter_bits d) by rewrite hb.
    by move: hk; rewrite /counter_bits !int2bsK 1:// 1:hp 1:// 1:// 1:hp 1://.
  by smt(U32.val_inj).
qed.

lemma r_tail_nonce_injective random message (c d : counter) :
  r_tail random message c = r_tail random message d => c = d.
proof.
  rewrite /r_tail => he.
  apply counter_bytes_injective.
  exact (catsI ([82;95;103;114;105;110;100] ++ random ++ message ++ nseq 28 0) _ _ he).
qed.

op r_query (random message : raw_input) (i : int) =
  r_tail random message (U32.insubd i).

lemma r_query_injective random message i j :
  0 <= i < signing_budget => 0 <= j < signing_budget =>
  r_query random message i = r_query random message j => i = j.
proof.
  rewrite /r_query => hi hj he.
  have hc := r_tail_nonce_injective random message (U32.insubd i) (U32.insubd j) he.
  have hi32 : 0 <= i < 4294967296 by move: hi; rewrite /signing_budget; smt().
  have hj32 : 0 <= j < 4294967296 by move: hj; rewrite /signing_budget; smt().
  smt(U32.insubdK).
qed.

op future_fresh (h : (raw_input,digest) fmap) random message i =
  forall j, i <= j < signing_budget => r_query random message j \notin h.

lemma future_fresh_current h random message i :
  i < signing_budget => future_fresh h random message i =>
  r_query random message i \notin h.
proof. by rewrite /future_fresh; smt(). qed.

lemma future_fresh_update h random message i rd :
  0 <= i < signing_budget => future_fresh h random message i =>
  future_fresh h.[r_query random message i <- rd] random message (i+1).
proof.
  rewrite /future_fresh => hi hf j hj.
  rewrite FMap.mem_set.
  have hn : r_query random message j <> r_query random message i
    by smt(r_query_injective).
  smt().
qed.

lemma derive_future_fresh random message i :
  hoare[Independent.derive :
    0 <= i < signing_budget /\ tail = r_query random message i /\
    future_fresh Independent.secrethistory random message i ==>
    future_fresh Independent.secrethistory random message (i+1)].
proof.
  proc; rcondt 1; first by auto; smt(future_fresh_current).
  auto; smt(future_fresh_update).
qed.
