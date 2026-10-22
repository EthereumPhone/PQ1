(* Generated functional-printer boundary and independent chain checks. *)
require import AllCore List IntDiv Ring C10Representation.
op clamp (x : int) : int = (max 0 x).
op embed (n : int) : int = (n).
op apply_backend (f : int list -> int list) (xs : int list) : int list = (f xs).
lemma clamp_negative : clamp (-1) = 0. proof. by rewrite /clamp. qed.
lemma clamp_zero : clamp 0 = 0. proof. by rewrite /clamp. qed.
lemma clamp_positive : clamp 7 = 7. proof. by rewrite /clamp. qed.
lemma count_roundtrip n : 0 <= n => clamp (embed n) = n. proof. rewrite /clamp /embed; smt(). qed.
lemma backend_application f xs : apply_backend f xs = f xs. proof. by rewrite /apply_backend. qed.
op toy (bs : int list) : int list = nseq 32 ((nth 0 bs 59 + 2 * nth 0 bs 64 + 1) %% 256).
lemma fixture_repeat16 (x : int) : nseq 16 x = [x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x].
proof. by rewrite (nseqS 15 x) 1:// (nseqS 14 x) 1:// (nseqS 13 x) 1:// (nseqS 12 x) 1:// (nseqS 11 x) 1:// (nseqS 10 x) 1:// (nseqS 9 x) 1:// (nseqS 8 x) 1:// (nseqS 7 x) 1:// (nseqS 6 x) 1:// (nseqS 5 x) 1:// (nseqS 4 x) 1:// (nseqS 3 x) 1:// (nseqS 2 x) 1:// (nseqS 1 x) 1:// (nseqS 0 x) 1:// nseq0. qed.
lemma fixture_repeat32 (x : int) : nseq 32 x = [x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x].
proof. by rewrite (nseqS 31 x) 1:// (nseqS 30 x) 1:// (nseqS 29 x) 1:// (nseqS 28 x) 1:// (nseqS 27 x) 1:// (nseqS 26 x) 1:// (nseqS 25 x) 1:// (nseqS 24 x) 1:// (nseqS 23 x) 1:// (nseqS 22 x) 1:// (nseqS 21 x) 1:// (nseqS 20 x) 1:// (nseqS 19 x) 1:// (nseqS 18 x) 1:// (nseqS 17 x) 1:// (nseqS 16 x) 1:// (nseqS 15 x) 1:// (nseqS 14 x) 1:// (nseqS 13 x) 1:// (nseqS 12 x) 1:// (nseqS 11 x) 1:// (nseqS 10 x) 1:// (nseqS 9 x) 1:// (nseqS 8 x) 1:// (nseqS 7 x) 1:// (nseqS 6 x) 1:// (nseqS 5 x) 1:// (nseqS 4 x) 1:// (nseqS 3 x) 1:// (nseqS 2 x) 1:// (nseqS 1 x) 1:// (nseqS 0 x) 1:// nseq0. qed.
lemma fixture_indices2 : iota_ 0 2 = [0; 1].
proof. by rewrite (iotaS 0 1) 1:// (iotaS 1 0) 1:// iota0 1://. qed.
lemma fixture_indices4 : iota_ 0 4 = [0; 1; 2; 3].
proof. by rewrite (iotaS 0 3) 1:// (iotaS 1 2) 1:// (iotaS 2 1) 1:// (iotaS 3 0) 1:// iota0 1://. qed.
lemma chain_0_0 : wots_chain_value toy (nseq 32 0) (nseq 32 0) (nseq 16 3) 0 0 = nseq 16 3.
proof. by rewrite /wots_chain_value /mkseq iota0 1://. qed.
lemma chain_5_1 : wots_chain_value toy (nseq 32 0) (nseq 32 0) (nseq 16 3) 5 1 = nseq 16 12.
proof.
  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.
  rewrite /wots_chain_value /mkseq iota1 /=.
  rewrite /hash_bytes_node /toy /th_preimage /chain_position_words /u32_bytes /pad_node !fixture_repeat16 !fixture_repeat32 /mkseq fixture_indices4 /=.
  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 !rev_cons !rev_nil /= /foldr ?fixture_repeat32 /=.
qed.
lemma chain_5_2 : wots_chain_value toy (nseq 32 0) (nseq 32 0) (nseq 16 3) 5 2 = nseq 16 31.
proof.
  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.
  rewrite /wots_chain_value /mkseq fixture_indices2 /=.
  rewrite /hash_bytes_node /toy /th_preimage /chain_position_words /u32_bytes /pad_node !fixture_repeat16 !fixture_repeat32 /mkseq fixture_indices4 /=.
  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 !rev_cons !rev_nil /= /foldr ?fixture_repeat32 /=.
qed.
lemma chain_255_2 : wots_chain_value toy (nseq 32 0) (nseq 32 0) (nseq 16 3) 255 2 = nseq 16 13.
proof.
  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.
  rewrite /wots_chain_value /mkseq fixture_indices2 /=.
  rewrite /hash_bytes_node /toy /th_preimage /chain_position_words /u32_bytes /pad_node !fixture_repeat16 !fixture_repeat32 /mkseq fixture_indices4 /=.
  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 !rev_cons !rev_nil /= /foldr ?fixture_repeat32 /=.
qed.
lemma chain_2147483648_1 : wots_chain_value toy (nseq 32 0) (nseq 32 0) (nseq 16 3) 2147483648 1 = nseq 16 7.
proof.
  have h8 : 2^8 = 256 by rewrite (_: 8=2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h16 : 2^16 = 65536 by rewrite (_: 16=2*2*2*2) 1:// !IntID.exprM !IntID.expr2.
  have h24 : 2^24 = 16777216 by rewrite (_: 24=8*3) 1:// IntID.exprM h8 (IntID.exprS _ 2) 1:// IntID.expr2.
  rewrite /wots_chain_value /mkseq iota1 /=.
  rewrite /hash_bytes_node /toy /th_preimage /chain_position_words /u32_bytes /pad_node !fixture_repeat16 !fixture_repeat32 /mkseq fixture_indices4 /=.
  by rewrite ?h8 ?h16 ?h24 ?IntID.expr0 !rev_cons !rev_nil /= /foldr ?fixture_repeat32 /=.
qed.
