(* Bounded WOTS coordinates cannot alias one another in private derivation inputs. *)
require import AllCore List FMap IntDiv BitEncoding.
require import C10RawOracle C10Bytes KeygenPrefixes RawKeygen RawSignature WotsReference ForsInputSeparation.
import BS2Int.

lemma be_value n x :
  0<=n => 0<=x<2^(8*n) => bs2int (bytes_to_bits (be n x))=x.
proof.
  move=> hn hx; rewrite /be bits_bytes_roundtrip 1:size_int2bs 1:/# int2bsK 1:/#; smt().
qed.
lemma be_injective n x y :
  0<=n => 0<=x<2^(8*n) => 0<=y<2^(8*n) => be n x=be n y => x=y.
proof. smt(be_value). qed.

lemma wots_tail_layer layer tree kp i : take 4 (wots_tail layer tree kp i)=be 4 layer.
proof. by rewrite /wots_tail -!catA take_size_cat 1:be_width. qed.
lemma wots_tail_tree layer tree kp i : take 32 (drop 4 (wots_tail layer tree kp i))=be 32 tree.
proof.
  rewrite /wots_tail -!catA drop_cat be_width 1:// /= drop0 take_size_cat 1:be_width; smt().
qed.
lemma wots_tail_kp layer tree kp i : take 4 (drop 36 (wots_tail layer tree kp i))=be 4 kp.
proof.
  have hw : size (be 4 layer ++ be 32 tree)=36 by rewrite size_cat !be_width.
  have he : wots_tail layer tree kp i=(be 4 layer ++ be 32 tree) ++ (be 4 kp ++ be 4 i)
    by rewrite /wots_tail catA.
  rewrite he drop_cat hw /= drop0 take_size_cat 1:be_width; smt().
qed.
lemma wots_tail_index layer tree kp i : drop 40 (wots_tail layer tree kp i)=be 4 i.
proof.
  have hw : size (be 4 layer ++ be 32 tree ++ be 4 kp)=40 by rewrite !size_cat !be_width.
  by rewrite /wots_tail -hw drop_size_cat.
qed.
lemma wots_key_injective layer tree kp i layer' tree' kp' i' :
  0<=layer<4294967296 => 0<=layer'<4294967296 =>
  0<=tree<2^256 => 0<=tree'<2^256 =>
  0<=kp<4294967296 => 0<=kp'<4294967296 =>
  0<=i<4294967296 => 0<=i'<4294967296 =>
  wots_key layer tree kp i=wots_key layer' tree' kp' i' =>
  layer=layer' /\ tree=tree' /\ kp=kp' /\ i=i'.
proof.
  move=> hl hl' ht ht' hk hk' hi hi' he.
  have he' : wots_tail layer tree kp i=wots_tail layer' tree' kp' i'
    by move: he; rewrite /wots_key; smt(catsI).
  have htree : be 32 tree=be 32 tree' by smt(wots_tail_tree).
  have htval := be_injective 32 tree tree' _ _ _ htree; first 3 smt().
  smt(wots_tail_layer wots_tail_kp wots_tail_index be4_injective).
qed.
lemma wots_fors_input_disjoint layer tree kp i tail :
  wots_key layer tree kp i<>fors_tag++tail.
proof. by rewrite /wots_key /wots_tag /fors_tag /=. qed.
lemma wots_r_input_disjoint layer tree kp i tail :
  head 0 tail=82 => wots_key layer tree kp i<>tail.
proof. rewrite /wots_key /wots_tag /=; smt(). qed.
