(* Paired preimage endpoints. These are byte-layout equalities, not a SHA
   idealization, hash-injectivity premise, or stateful caller simulation. *)
require import AllCore List IntDiv Ring BitEncoding.
require import C10Bytes C10Counter C10HashDomains RawKeygen.
require import C10Representation.
import BS2Int BitChunking.

lemma counter_common (c : counter) : counter_bytes c = u32_bytes (U32.val c).
proof.
  have hp8 : 2^8 = 256 by rewrite (_ : 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have hp32 : 2^32 = 4294967296
    by rewrite (_ : 32=2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have hc : 0 <= U32.val c < 2^32 by rewrite hp32 U32.valP.
  rewrite /counter_bytes /counter_bits /bits_to_bytes /chunk /u32_bytes
    size_int2bs /= map_mkseq.
  congr; apply eq_in_mkseq => i hi.
  rewrite /(\o) /=.
  by rewrite -bs2int_mod 1:// -bs2int_div 1:/# int2bsK 1:// 1:hc hp8.
qed.

lemma zero_word_bytes : bits_to_bytes (nseq 224 false) = nseq 28 0.
proof.
  rewrite /bits_to_bytes /chunk size_nseq /= map_mkseq.
  have hz : mkseq (bs2int \o fun i => take 8 (drop (8*i) (nseq 224 false))) 28 = nseq 28 0.
  + rewrite -(mkseq_nseq 28 0); apply eq_in_mkseq => i hi.
    by rewrite /(\o) /= -bs2int_mod 1:// -bs2int_div 1:/# bs2int_nseq_false.
  by rewrite hz rev_nseq.
qed.

lemma full_counter_word (c : counter) :
  be 32 (U32.val c) = nseq 28 0 ++ u32_bytes (U32.val c).
proof.
  have hp32 : 2^32 = 4294967296
    by rewrite (_ : 32=2*2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have hz : U32.val c %/ 2^32 = 0 by rewrite hp32 divz_small 1:U32.valP.
  rewrite -counter_common /be (int2bs_cat 32 256) 1:// hz int2bs0 /=.
  rewrite /bits_to_bytes chunk_cat 1:size_int2bs 1:// map_cat rev_cat.
  have hzero := zero_word_bytes; rewrite /bits_to_bytes in hzero.
  rewrite hzero.
  by rewrite /counter_bytes /counter_bits.
qed.

lemma pad_common v : pad v = pad_node v.
proof. by rewrite /pad /pad_node. qed.

lemma hmsg_input_common seed root random message :
  hmsg_input seed root random message = hmsg_preimage seed root random message.
proof. by rewrite /hmsg_input /hmsg_preimage. qed.

lemma th_input_common seed address value :
  seed ++ address ++ value = th_preimage seed address value.
proof. by rewrite /th_preimage. qed.

lemma pair_input_common seed address lhs rhs :
  pair_input seed address lhs rhs = pair_preimage seed address lhs rhs.
proof. by rewrite /pair_input /pair_preimage. qed.

lemma padded_nodes_common vs :
  flatten (map pad vs) = foldr (fun v tail => pad_node v ++ tail) [] vs.
proof.
  elim: vs => [|v vs ih] /=; first by rewrite flatten_nil.
  by rewrite flatten_cons /= ih /pad /pad_node.
qed.

lemma multi_input_common seed address vs :
  seed ++ address ++ flatten (map pad vs) = multi_preimage seed address vs.
proof. by rewrite /multi_preimage padded_nodes_common. qed.

lemma wots_input_common seed address message c :
  seed ++ address ++ message ++ nseq 28 0 ++ counter_bytes c =
    wots_preimage seed address message (U32.val c).
proof. by rewrite /wots_preimage counter_common. qed.

lemma wots_payload_common seed address node c :
  transcript seed address node c =
    wots_preimage seed address (pad_node (bits_to_bytes node)) (U32.val c).
proof. by rewrite /transcript /payload /wots_preimage /pad_node counter_common !catA. qed.

lemma randomizer_input_common secret random message c :
  r_input secret random message c = r_preimage secret random message (U32.val c).
proof. by rewrite /r_input /r_preimage counter_common. qed.

(* RawWots.count/recover use the complete 32-byte count slot, rather than
   the compact four-byte signature field. This equality covers every u32. *)
lemma raw_wots_input_common seed address message c :
  seed ++ address ++ pad message ++ be 32 (U32.val c) =
    wots_preimage seed address (pad_node message) (U32.val c).
proof. by rewrite /wots_preimage pad_common full_counter_word !catA. qed.

lemma role_randomizer_input_common secret random message c :
  secret ++ RoleGrind.r_tail random message c =
    r_preimage secret random message (U32.val c).
proof. by rewrite -RoleGrind.r_tail_layout randomizer_input_common. qed.
