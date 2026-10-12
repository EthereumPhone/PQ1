(* Paired full-width address/private-input layouts. These equalities neither
   identify concrete SHA with an ideal oracle nor prove caller simulation. *)
require import AllCore List IntDiv Ring BitEncoding.
require import C10Bytes RawKeygen RawFors KeygenPrefixes RawSignature.
require import C10Representation.
import BS2Int BitChunking.

lemma be4_common x : 0 <= x < 2^32 => be 4 x = u32_bytes x.
proof.
  move=> hx.
  have hp8 : 2^8 = 256 by rewrite (_ : 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  rewrite /be /bits_to_bytes /chunk /u32_bytes size_int2bs /= map_mkseq.
  congr; apply eq_in_mkseq => i hi.
  rewrite /(\o) /=.
  by rewrite -bs2int_mod 1:// -bs2int_div 1:/# int2bsK 1:// 1:hx hp8.
qed.

lemma be8_common x : 0 <= x < 2^64 => be 8 x = u64_bytes x.
proof.
  move=> hx.
  have hp8 : 2^8 = 256 by rewrite (_ : 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  rewrite /be /bits_to_bytes /chunk /u64_bytes size_int2bs /= map_mkseq.
  congr; apply eq_in_mkseq => i hi.
  rewrite /(\o) /=.
  by rewrite -bs2int_mod 1:// -bs2int_div 1:/# int2bsK 1:// 1:hx hp8.
qed.

lemma zero_tree_bytes : bits_to_bytes (nseq 192 false) = nseq 24 0.
proof.
  rewrite /bits_to_bytes /chunk size_nseq /= map_mkseq.
  have hz : mkseq (bs2int \o fun i => take 8 (drop (8*i) (nseq 192 false))) 24 = nseq 24 0.
  + rewrite -(mkseq_nseq 24 0); apply eq_in_mkseq => i hi.
    by rewrite /(\o) /= -bs2int_mod 1:// -bs2int_div 1:/# bs2int_nseq_false.
  by rewrite hz rev_nseq.
qed.

lemma padded_tree_common tree : 0 <= tree < 2^64 =>
  be 32 tree = nseq 24 0 ++ u64_bytes tree.
proof.
  move=> ht.
  have hp64 : 2^64 = 18446744073709551616
    by rewrite (_ : 64=2*2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have hz : tree %/ 2^64 = 0 by rewrite hp64 divz_small 1:/#.
  rewrite /be (int2bs_cat 64 256) 1:// hz.
  rewrite int2bs0 /=.
  rewrite /bits_to_bytes chunk_cat 1:size_int2bs 1:// map_cat rev_cat.
  have hzero := zero_tree_bytes; rewrite /bits_to_bytes in hzero.
  rewrite hzero.
  have hb := be8_common tree ht; rewrite /be /bits_to_bytes in hb.
  by rewrite hb.
qed.

lemma address_common layer tree kind kp ci cp ha :
  0 <= layer < 2^32 => 0 <= tree < 2^64 => 0 <= kind < 2^32 =>
  0 <= kp < 2^32 => 0 <= ci < 2^32 => 0 <= cp < 2^32 => 0 <= ha < 2^32 =>
  address layer tree kind kp ci cp ha = address_words layer tree kind kp ci cp ha.
proof.
  move=> hl ht hk hkp hci hcp hha.
  by rewrite /address /address_words (be4_common layer hl) (be8_common tree ht)
    (be4_common kind hk) (be4_common kp hkp) (be4_common ci hci)
    (be4_common cp hcp) (be4_common ha hha).
qed.

(* The existing chain model reconstructs addresses from fields. These
   equalities connect the extracted window updates to those actual addresses. *)
lemma chain_index_common layer tree kind kp oldci cp ha ci :
  0 <= ci < 2^32 =>
  chain_index_words (address layer tree kind kp oldci cp ha) ci =
    address layer tree kind kp ci cp ha.
proof.
  move=> hci; rewrite /chain_index_words /address -(be4_common ci hci).
  by rewrite !take_cat !drop_cat !size_cat !be_width //= !catA ?take0 ?drop0 ?cats0.
qed.

lemma chain_position_common layer tree kind kp ci oldcp ha cp :
  0 <= cp < 2^32 =>
  chain_position_words (address layer tree kind kp ci oldcp ha) cp =
    address layer tree kind kp ci cp ha.
proof.
  move=> hcp; rewrite /chain_position_words /address -(be4_common cp hcp).
  by rewrite !take_cat !drop_cat !size_cat !be_width //= ?take0 ?drop0 ?cats0.
qed.

(* PreparationView supplies each tag to the keyed oracle. Prefixing the
   explicit secret yields these common preimages; no oracle relation follows. *)
lemma wots_private_common secret layer tree kp ci :
  0 <= layer < 2^32 => 0 <= tree < 2^64 => 0 <= kp < 2^32 => 0 <= ci < 2^32 =>
  secret ++ wots_tag ++ wots_tail layer tree kp ci =
    wots_private_preimage secret layer tree kp ci.
proof.
  move=> hl ht hkp hci.
  by rewrite /wots_tag /wots_tail /wots_private_preimage
    (be4_common layer hl) (padded_tree_common tree ht)
    (be4_common kp hkp) (be4_common ci hci) !catA.
qed.

lemma fors_private_common secret ht tree leaf :
  0 <= ht < 2^32 => 0 <= tree < 2^32 => 0 <= leaf < 2^32 =>
  secret ++ fors_tag ++ fors_tail ht tree leaf = fors_private_preimage secret ht tree leaf.
proof.
  move=> hh htree hl.
  by rewrite /fors_tag /fors_tail /fors_private_preimage
    (be4_common _ hh) (be4_common tree htree) (be4_common leaf hl) !catA.
qed.
