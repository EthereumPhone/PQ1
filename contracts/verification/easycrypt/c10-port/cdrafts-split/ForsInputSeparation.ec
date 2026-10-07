(* Exact bounded coordinate encoding. No secrecy claim is made by injectivity. *)
require import AllCore List IntDiv BitEncoding.
require import C10RawOracle C10Bytes RawKeygen RawFors RawSignature EncodedLayer.
require import KeygenPrefixes ForsPrivateLeaves RawForest ForestCoordinates SignerCoordinates.
import BS2Int.

lemma be4_injective x y :
  0<=x<4294967296 => 0<=y<4294967296 => be 4 x=be 4 y => x=y.
proof. smt(encoded_count_value). qed.

lemma fors_tail_head ht tree index : take 4 (fors_tail ht tree index)=be 4 ht.
proof. by rewrite /fors_tail -catA take_size_cat 1:be_width. qed.

lemma fors_tail_tree ht tree index : take 4 (drop 4 (fors_tail ht tree index))=be 4 tree.
proof.
  have hh : size (be 4 ht)=4 by apply be_width.
  have htree : size (be 4 tree)=4 by apply be_width.
  by rewrite /fors_tail -catA drop_cat hh /= drop0 take_cat htree /= take0 cats0.
qed.

lemma fors_tail_index ht tree index : drop 8 (fors_tail ht tree index)=be 4 index.
proof.
  have hw : size (be 4 ht ++ be 4 tree)=8 by rewrite size_cat !be_width.
  by rewrite /fors_tail -hw drop_size_cat.
qed.

lemma fors_tail_injective ht1 tree1 index1 ht2 tree2 index2 :
  0<=ht1<4294967296 => 0<=tree1<4294967296 => 0<=index1<4294967296 =>
  0<=ht2<4294967296 => 0<=tree2<4294967296 => 0<=index2<4294967296 =>
  fors_tail ht1 tree1 index1=fors_tail ht2 tree2 index2 =>
  ht1=ht2 /\ tree1=tree2 /\ index1=index2.
proof. smt(fors_tail_head fors_tail_tree fors_tail_index be4_injective). qed.

lemma fors_private_key_injective ht1 tree1 index1 ht2 tree2 index2 :
  0<=ht1<4294967296 => 0<=tree1<4294967296 => 0<=index1<4294967296 =>
  0<=ht2<4294967296 => 0<=tree2<4294967296 => 0<=index2<4294967296 =>
  fors_private_key ht1 tree1 index1=fors_private_key ht2 tree2 index2 =>
  ht1=ht2 /\ tree1=tree2 /\ index1=index2.
proof. rewrite /fors_private_key; smt(catsI fors_tail_injective). qed.

lemma fors_digest_coordinate_injective d1 t1 d2 t2 :
  0<=t1<13 => 0<=t2<13 =>
  fors_private_key (hypertree_index d1) t1 (forest_index d1 t1)=
    fors_private_key (hypertree_index d2) t2 (forest_index d2 t2) =>
  hypertree_index d1=hypertree_index d2 /\ t1=t2 /\ forest_index d1 t1=forest_index d2 t2.
proof. smt(fors_private_key_injective hypertree_index_range forest_index_range). qed.

lemma fors_private_key_width ht tree index : size (fors_private_key ht tree index)=16.
proof. by rewrite /fors_private_key /fors_tag /fors_tail !size_cat /= !be_width. qed.

lemma fors_wots_inputs_disjoint ht tree index tail :
  fors_private_key ht tree index <> wots_tag ++ tail.
proof. by rewrite /fors_private_key /fors_tag /wots_tag /=. qed.

lemma fors_r_inputs_disjoint ht tree index tail :
  head 0 tail=82 => fors_private_key ht tree index <> tail.
proof. rewrite /fors_private_key /fors_tag /=; smt(). qed.
