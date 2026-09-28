(* The deployed eighteen-bit index reaches tree zero after two 9-bit layers. *)
require import AllCore List IntDiv BitEncoding Ring StdRing StdOrder.
require import C10RawOracle RawForest.
import BS2Int IntID IntOrder.

lemma hypertree_index_range digest : 0<=hypertree_index digest<262144.
proof.
  rewrite /hypertree_index; split; first exact (bs2int_ge0 _).
  have hpow : 2^18=262144 by rewrite (_:18=2*9) 1:// IntID.exprM (_:9=8+1) 1:// IntID.exprD_nneg 1,2:// (_:8=2*2*2) 1:// !IntID.exprM !IntID.expr2 /=; ring.
  have h : bs2int (take 18 (drop 143 digest)) < 2^18.
  + apply/(ltr_le_trans (2^(size (take 18 (drop 143 digest))))).
    - exact (bs2int_le2Xs _).
    rewrite &(ler_weexpn2l) //= size_ge0 /= &(size_take_le) //.
  smt().
qed.

op signer_tree ht layer = if layer=0 then ht else if layer=1 then ht %/ 512 else 0.

lemma signer_coordinate_step ht layer :
  0<=ht<262144 => 0<=layer<2 =>
  0<=signer_tree ht layer %%512<512 /\
  signer_tree ht layer %/512=signer_tree ht (layer+1).
proof.
  move=> hr hl; rewrite /signer_tree.
  have htop : (ht %/512) %/512=0 by smt(divz_ge0 ltz_divLR pdiv_small).
  have hm0 : 0<=ht %%512<512 by smt(modz_ge0 ltz_pmod).
  have hm1 : 0<=(ht %/512) %%512<512 by smt(modz_ge0 ltz_pmod).
  smt().
qed.

lemma signer_top_tree ht : signer_tree ht 2=0.
proof. by rewrite /signer_tree. qed.
