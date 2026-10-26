(* Exact field arithmetic used when composing the actual signer calls. *)
require import AllCore IntDiv Ring StdRing.

lemma addressed_tree_field_cardinality : 2^64=18446744073709551616.
proof. by rewrite (_ : 64=2*2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2. qed.

lemma addressed_signer_coordinate_bounds index :
  0<=index<262144 => 0<=index %/ 512<262144 /\ 0<=index %% 512<512.
proof.
  move=> hi.
  have hd : 0<=index %/ 512<512 by rewrite divz_ge0 1:// ltz_divLR 1://; smt().
  have hm := modz_ge0 index 512; have hn := ltz_pmod index 512; smt().
qed.
