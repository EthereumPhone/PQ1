(* Generated independent functional tree examples. *)
require import AllCore List IntDiv Ring C10Representation C10FunctionalTreeValue C10FunctionalBuildValue.
op toy (bs : int list) : int list = nseq 32 ((1 * (nth 0 bs 32) + 3 * (nth 0 bs 36) + 5 * (nth 0 bs 43) + 7 * (nth 0 bs 47) + 11 * (nth 0 bs 51) + 13 * (nth 0 bs 59) + 17 * (nth 0 bs 60) + 19 * (nth 0 bs 63) + 23 * (nth 0 bs 64) + 29 * (nth 0 bs 96)) %% 256).
lemma tree_repeat16 (x : int) : nseq 16 x = [x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x].
proof. by rewrite (nseqS 15 x) 1:// (nseqS 14 x) 1:// (nseqS 13 x) 1:// (nseqS 12 x) 1:// (nseqS 11 x) 1:// (nseqS 10 x) 1:// (nseqS 9 x) 1:// (nseqS 8 x) 1:// (nseqS 7 x) 1:// (nseqS 6 x) 1:// (nseqS 5 x) 1:// (nseqS 4 x) 1:// (nseqS 3 x) 1:// (nseqS 2 x) 1:// (nseqS 1 x) 1:// (nseqS 0 x) 1:// nseq0. qed.
lemma tree_repeat32 (x : int) : nseq 32 x = [x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x].
proof. by rewrite (nseqS 31 x) 1:// (nseqS 30 x) 1:// (nseqS 29 x) 1:// (nseqS 28 x) 1:// (nseqS 27 x) 1:// (nseqS 26 x) 1:// (nseqS 25 x) 1:// (nseqS 24 x) 1:// (nseqS 23 x) 1:// (nseqS 22 x) 1:// (nseqS 21 x) 1:// (nseqS 20 x) 1:// (nseqS 19 x) 1:// (nseqS 18 x) 1:// (nseqS 17 x) 1:// (nseqS 16 x) 1:// (nseqS 15 x) 1:// (nseqS 14 x) 1:// (nseqS 13 x) 1:// (nseqS 12 x) 1:// (nseqS 11 x) 1:// (nseqS 10 x) 1:// (nseqS 9 x) 1:// (nseqS 8 x) 1:// (nseqS 7 x) 1:// (nseqS 6 x) 1:// (nseqS 5 x) 1:// (nseqS 4 x) 1:// (nseqS 3 x) 1:// (nseqS 2 x) 1:// (nseqS 1 x) 1:// (nseqS 0 x) 1:// nseq0. qed.
lemma tree_indices4 : iota_ 0 4 = [0; 1; 2; 3].
proof. by rewrite (iotaS 0 3) 1:// (iotaS 1 2) 1:// (iotaS 2 1) 1:// (iotaS 3 0) 1:// iota0 1://. qed.
lemma tree_indices8 : iota_ 0 8 = [0; 1; 2; 3; 4; 5; 6; 7].
proof. by rewrite (iotaS 0 7) 1:// (iotaS 1 6) 1:// (iotaS 2 5) 1:// (iotaS 3 4) 1:// (iotaS 4 3) 1:// (iotaS 5 2) 1:// (iotaS 6 1) 1:// (iotaS 7 0) 1:// iota0 1://. qed.
lemma tree_pow1 : 2^1 = 2.
proof. by rewrite (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow2 : 2^2 = 4.
proof. by rewrite (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow3 : 2^3 = 8.
proof. by rewrite (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow4 : 2^4 = 16.
proof. by rewrite (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow5 : 2^5 = 32.
proof. by rewrite (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow6 : 2^6 = 64.
proof. by rewrite (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow7 : 2^7 = 128.
proof. by rewrite (IntID.exprS 2 6) 1:// (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow8 : 2^8 = 256.
proof. by rewrite (IntID.exprS 2 7) 1:// (IntID.exprS 2 6) 1:// (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow9 : 2^9 = 512.
proof. by rewrite (IntID.exprS 2 8) 1:// (IntID.exprS 2 7) 1:// (IntID.exprS 2 6) 1:// (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow10 : 2^10 = 1024.
proof. by rewrite (IntID.exprS 2 9) 1:// (IntID.exprS 2 8) 1:// (IntID.exprS 2 7) 1:// (IntID.exprS 2 6) 1:// (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow11 : 2^11 = 2048.
proof. by rewrite (IntID.exprS 2 10) 1:// (IntID.exprS 2 9) 1:// (IntID.exprS 2 8) 1:// (IntID.exprS 2 7) 1:// (IntID.exprS 2 6) 1:// (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// IntID.expr0. qed.
lemma tree_pow16 : 2^16 = 65536.
proof. by rewrite (_: 16=8*2) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_pow24 : 2^24 = 16777216.
proof. by rewrite (_: 24=8*3) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 2) 1:// (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_pow32 : 2^32 = 4294967296.
proof. by rewrite (_: 32=8*4) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 3) 1:// (IntID.exprS 256 2) 1:// (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_pow40 : 2^40 = 1099511627776.
proof. by rewrite (_: 40=8*5) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 4) 1:// (IntID.exprS 256 3) 1:// (IntID.exprS 256 2) 1:// (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_pow48 : 2^48 = 281474976710656.
proof. by rewrite (_: 48=8*6) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 5) 1:// (IntID.exprS 256 4) 1:// (IntID.exprS 256 3) 1:// (IntID.exprS 256 2) 1:// (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_pow56 : 2^56 = 72057594037927936.
proof. by rewrite (_: 56=8*7) 1:// IntID.exprM tree_pow8 (IntID.exprS 256 6) 1:// (IntID.exprS 256 5) 1:// (IntID.exprS 256 4) 1:// (IntID.exprS 256 3) 1:// (IntID.exprS 256 2) 1:// (IntID.exprS 256 1) 1:// (IntID.exprS 256 0) 1:// IntID.expr0. qed.
lemma tree_take_node (x : int) : take 16 (nseq 32 x) = nseq 16 x.
proof. by rewrite tree_repeat32 tree_repeat16 /=. qed.
op address_score (a : int list) = nth 0 a 0 + 3*nth 0 a 4 + 5*nth 0 a 11 +
  7*nth 0 a 15 + 11*nth 0 a 19 + 13*nth 0 a 27 + 17*nth 0 a 28 + 19*nth 0 a 31.
lemma tree_address_size l t k kp h p : size (address_words l t k kp 0 h p) = 32.
proof. by rewrite /address_words /u32_bytes /u64_bytes !size_cat !size_rev !size_mkseq. qed.
lemma tree_toy_pair a x y : size a = 32 =>
  tree_pair_value toy (nseq 32 0) a (nseq 16 x) (nseq 16 y) =
    nseq 16 ((address_score a + 23*x + 29*y) %% 256).
proof.
  move=> ha; rewrite /tree_pair_value /hash_bytes_node /toy /pair_preimage /pad_node.
  do ! (rewrite nth_cat 1:// ?size_cat ?size_nseq ?ha /max /=).
  by rewrite ?nth_nseq /= /address_score ?tree_take_node /=.
qed.
lemma tree_toy_leaf a x : size a = 32 =>
  hash_bytes_node toy (th_preimage (nseq 32 0) a (pad_node (nseq 16 x))) =
    nseq 16 ((address_score a + 23*x) %% 256).
proof.
  move=> ha; rewrite /hash_bytes_node /toy /th_preimage /pad_node.
  do ! (rewrite nth_cat 1:// ?size_cat ?size_nseq ?ha /max /=).
  by rewrite !tree_repeat16 /= /address_score tree_take_node ?tree_repeat16 /=.
qed.
lemma tree_address_score l t k kp h p :
  address_score (address_words l t k kp 0 h p) =
    l %/ 16777216 %% 256 + 3*(t %/ 72057594037927936 %% 256) + 5*(t %% 256) +
    7*(k %% 256) + 11*(kp %% 256) + 13*(h %% 256) +
    17*(p %/ 16777216 %% 256) + 19*(p %% 256).
proof.
  rewrite /address_score /address_words /u32_bytes /u64_bytes /mkseq tree_indices4 tree_indices8 /=.
  by rewrite ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
    ?IntID.expr0 !rev_cons !rev_nil /=.
qed.

op build_leaves (total : int) = mkseq (fun i => nseq 16 ((17*i+3) %% 256)) (2^total).
lemma build_indices9 : iota_ 0 9 = [0; 1; 2; 3; 4; 5; 6; 7; 8].
proof. by rewrite (iotaS 0 8) 1:// (iotaS 1 7) 1:// (iotaS 2 6) 1:// (iotaS 3 5) 1:// (iotaS 4 4) 1:// (iotaS 5 3) 1:// (iotaS 6 2) 1:// (iotaS 7 1) 1:// (iotaS 8 0) 1:// iota0 1://. qed.
lemma build_indices11 : iota_ 0 11 = [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10].
proof. by rewrite (iotaS 0 10) 1:// (iotaS 1 9) 1:// (iotaS 2 8) 1:// (iotaS 3 7) 1:// (iotaS 4 6) 1:// (iotaS 5 5) 1:// (iotaS 6 4) 1:// (iotaS 7 3) 1:// (iotaS 8 2) 1:// (iotaS 9 1) 1:// (iotaS 10 0) 1:// iota0 1://. qed.
lemma fors_zero_level0 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 0 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((17*i+3) %% 256)) 2048.
proof.
  by rewrite functional_build_zero /build_leaves tree_pow11.
qed.
lemma fors_zero_level1 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 1 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((251*i+171) %% 256)) 1024.
proof.
  rewrite (_ : 1=0+1) 1:// functional_build_next 1:// fors_zero_level0.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow10 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow10 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(0+1))) by rewrite /= ?tree_pow10 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level2 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 2 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((11*i+90) %% 256)) 512.
proof.
  rewrite (_ : 2=1+1) 1:// functional_build_next 1:// fors_zero_level1.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow9 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow9 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(1+1))) by rewrite /= ?tree_pow9 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level3 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 3 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+195) %% 256)) 256.
proof.
  rewrite (_ : 3=2+1) 1:// functional_build_next 1:// fors_zero_level2.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow8 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow8 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(2+1))) by rewrite /= ?tree_pow8 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level4 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 4 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+164) %% 256)) 128.
proof.
  rewrite (_ : 4=3+1) 1:// functional_build_next 1:// fors_zero_level3.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow7 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow7 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(3+1))) by rewrite /= ?tree_pow7 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level5 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 5 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+101) %% 256)) 64.
proof.
  rewrite (_ : 5=4+1) 1:// functional_build_next 1:// fors_zero_level4.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow6 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow6 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(4+1))) by rewrite /= ?tree_pow6 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level6 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 6 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+166) %% 256)) 32.
proof.
  rewrite (_ : 6=5+1) 1:// functional_build_next 1:// fors_zero_level5.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow5 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow5 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(5+1))) by rewrite /= ?tree_pow5 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level7 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 7 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+231) %% 256)) 16.
proof.
  rewrite (_ : 7=6+1) 1:// functional_build_next 1:// fors_zero_level6.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow4 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow4 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(6+1))) by rewrite /= ?tree_pow4 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level8 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 8 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+40) %% 256)) 8.
proof.
  rewrite (_ : 8=7+1) 1:// functional_build_next 1:// fors_zero_level7.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow3 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow3 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(7+1))) by rewrite /= ?tree_pow3 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level9 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 9 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+105) %% 256)) 4.
proof.
  rewrite (_ : 9=8+1) 1:// functional_build_next 1:// fors_zero_level8.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow2 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow2 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(8+1))) by rewrite /= ?tree_pow2 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level10 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 10 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+170) %% 256)) 2.
proof.
  rewrite (_ : 10=9+1) 1:// functional_build_next 1:// fors_zero_level9.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow1 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow1 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(9+1))) by rewrite /= ?tree_pow1 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_level11 : tree_nodes_value toy (nseq 32 0) 0 0 3 0 11 11 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+235) %% 256)) 1.
proof.
  rewrite (_ : 11=10+1) 1:// functional_build_next 1:// fors_zero_level10.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow0 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow0 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(10+1))) by rewrite /= ?tree_pow0 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_zero_root : tree_root_value toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) = nseq 16 235.
proof. by rewrite /tree_root_value fors_zero_level11 nth_mkseq 1://. qed.
lemma fors_zero_auth0 : tree_auth_values toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 0 = [nseq 16 20; nseq 16 166; nseq 16 101; nseq 16 78; nseq 16 47; nseq 16 240; nseq 16 49; nseq 16 114; nseq 16 179; nseq 16 244; nseq 16 53].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_zero_level0 fors_zero_level1 fors_zero_level2 fors_zero_level3 fors_zero_level4 fors_zero_level5 fors_zero_level6 fors_zero_level7 fors_zero_level8 fors_zero_level9 fors_zero_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_zero_auth1 : tree_auth_values toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 1 = [nseq 16 3; nseq 16 166; nseq 16 101; nseq 16 78; nseq 16 47; nseq 16 240; nseq 16 49; nseq 16 114; nseq 16 179; nseq 16 244; nseq 16 53].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_zero_level0 fors_zero_level1 fors_zero_level2 fors_zero_level3 fors_zero_level4 fors_zero_level5 fors_zero_level6 fors_zero_level7 fors_zero_level8 fors_zero_level9 fors_zero_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_zero_auth2047 : tree_auth_values toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 2047 = [nseq 16 225; nseq 16 181; nseq 16 68; nseq 16 173; nseq 16 14; nseq 16 15; nseq 16 240; nseq 16 129; nseq 16 106; nseq 16 127; nseq 16 170].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_zero_level0 fors_zero_level1 fors_zero_level2 fors_zero_level3 fors_zero_level4 fors_zero_level5 fors_zero_level6 fors_zero_level7 fors_zero_level8 fors_zero_level9 fors_zero_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_zero_auth2048 : tree_auth_values toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 2048 = nseq 11 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 2048);
    rewrite /build_leaves ?size_mkseq ?tree_pow11; smt().
qed.
lemma fors_zero_auth4294967295 : tree_auth_values toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 4294967295 = nseq 11 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 0 3 0 11 (build_leaves 11) 4294967295);
    rewrite /build_leaves ?size_mkseq ?tree_pow11; smt().
qed.
lemma fors_full_level0 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 0 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((17*i+3) %% 256)) 2048.
proof.
  by rewrite functional_build_zero /build_leaves tree_pow11.
qed.
lemma fors_full_level1 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 1 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((251*i+155) %% 256)) 1024.
proof.
  rewrite (_ : 1=0+1) 1:// functional_build_next 1:// fors_full_level0.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow10 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow10 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(0+1))) by rewrite /= ?tree_pow10 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level2 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 2 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((11*i+10) %% 256)) 512.
proof.
  rewrite (_ : 2=1+1) 1:// functional_build_next 1:// fors_full_level1.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow9 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow9 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(1+1))) by rewrite /= ?tree_pow9 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level3 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 3 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+115) %% 256)) 256.
proof.
  rewrite (_ : 3=2+1) 1:// functional_build_next 1:// fors_full_level2.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow8 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow8 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(2+1))) by rewrite /= ?tree_pow8 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level4 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 4 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+84) %% 256)) 128.
proof.
  rewrite (_ : 4=3+1) 1:// functional_build_next 1:// fors_full_level3.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow7 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow7 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(3+1))) by rewrite /= ?tree_pow7 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level5 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 5 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+21) %% 256)) 64.
proof.
  rewrite (_ : 5=4+1) 1:// functional_build_next 1:// fors_full_level4.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow6 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow6 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(4+1))) by rewrite /= ?tree_pow6 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level6 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 6 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+86) %% 256)) 32.
proof.
  rewrite (_ : 6=5+1) 1:// functional_build_next 1:// fors_full_level5.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow5 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow5 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(5+1))) by rewrite /= ?tree_pow5 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level7 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 7 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+151) %% 256)) 16.
proof.
  rewrite (_ : 7=6+1) 1:// functional_build_next 1:// fors_full_level6.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow4 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow4 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(6+1))) by rewrite /= ?tree_pow4 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level8 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 8 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+216) %% 256)) 8.
proof.
  rewrite (_ : 8=7+1) 1:// functional_build_next 1:// fors_full_level7.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow3 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow3 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(7+1))) by rewrite /= ?tree_pow3 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level9 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 9 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+25) %% 256)) 4.
proof.
  rewrite (_ : 9=8+1) 1:// functional_build_next 1:// fors_full_level8.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow2 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow2 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(8+1))) by rewrite /= ?tree_pow2 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level10 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 10 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+90) %% 256)) 2.
proof.
  rewrite (_ : 10=9+1) 1:// functional_build_next 1:// fors_full_level9.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow1 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow1 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(9+1))) by rewrite /= ?tree_pow1 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_level11 : tree_nodes_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 11 (build_leaves 11) =
  mkseq (fun i => nseq 16 ((139*i+155) %% 256)) 1.
proof.
  rewrite (_ : 11=10+1) 1:// functional_build_next 1:// fors_full_level10.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow0 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow0 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (11-(10+1))) by rewrite /= ?tree_pow0 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma fors_full_root : tree_root_value toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) = nseq 16 155.
proof. by rewrite /tree_root_value fors_full_level11 nth_mkseq 1://. qed.
lemma fors_full_auth0 : tree_auth_values toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 0 = [nseq 16 20; nseq 16 150; nseq 16 21; nseq 16 254; nseq 16 223; nseq 16 160; nseq 16 225; nseq 16 34; nseq 16 99; nseq 16 164; nseq 16 229].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_full_level0 fors_full_level1 fors_full_level2 fors_full_level3 fors_full_level4 fors_full_level5 fors_full_level6 fors_full_level7 fors_full_level8 fors_full_level9 fors_full_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_full_auth1 : tree_auth_values toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 1 = [nseq 16 3; nseq 16 150; nseq 16 21; nseq 16 254; nseq 16 223; nseq 16 160; nseq 16 225; nseq 16 34; nseq 16 99; nseq 16 164; nseq 16 229].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_full_level0 fors_full_level1 fors_full_level2 fors_full_level3 fors_full_level4 fors_full_level5 fors_full_level6 fors_full_level7 fors_full_level8 fors_full_level9 fors_full_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_full_auth2047 : tree_auth_values toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 2047 = [nseq 16 225; nseq 16 165; nseq 16 244; nseq 16 93; nseq 16 190; nseq 16 191; nseq 16 160; nseq 16 49; nseq 16 26; nseq 16 47; nseq 16 90].
proof.
  rewrite /tree_auth_values /mkseq build_indices11 /=.
  rewrite fors_full_level0 fors_full_level1 fors_full_level2 fors_full_level3 fors_full_level4 fors_full_level5 fors_full_level6 fors_full_level7 fors_full_level8 fors_full_level9 fors_full_level10.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma fors_full_auth2048 : tree_auth_values toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 2048 = nseq 11 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 2048);
    rewrite /build_leaves ?size_mkseq ?tree_pow11; smt().
qed.
lemma fors_full_auth4294967295 : tree_auth_values toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 4294967295 = nseq 11 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 4294967295 3 4294967295 11 (build_leaves 11) 4294967295);
    rewrite /build_leaves ?size_mkseq ?tree_pow11; smt().
qed.
lemma merkle_zero_level0 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 0 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((17*i+3) %% 256)) 512.
proof.
  by rewrite functional_build_zero /build_leaves tree_pow9.
qed.
lemma merkle_zero_level1 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 1 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((251*i+164) %% 256)) 256.
proof.
  rewrite (_ : 1=0+1) 1:// functional_build_next 1:// merkle_zero_level0.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow8 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow8 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(0+1))) by rewrite /= ?tree_pow8 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level2 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 2 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((11*i+231) %% 256)) 128.
proof.
  rewrite (_ : 2=1+1) 1:// functional_build_next 1:// merkle_zero_level1.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow7 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow7 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(1+1))) by rewrite /= ?tree_pow7 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level3 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 3 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+96) %% 256)) 64.
proof.
  rewrite (_ : 3=2+1) 1:// functional_build_next 1:// merkle_zero_level2.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow6 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow6 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(2+1))) by rewrite /= ?tree_pow6 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level4 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 4 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+129) %% 256)) 32.
proof.
  rewrite (_ : 4=3+1) 1:// functional_build_next 1:// merkle_zero_level3.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow5 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow5 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(3+1))) by rewrite /= ?tree_pow5 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level5 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 5 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+66) %% 256)) 16.
proof.
  rewrite (_ : 5=4+1) 1:// functional_build_next 1:// merkle_zero_level4.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow4 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow4 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(4+1))) by rewrite /= ?tree_pow4 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level6 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 6 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+131) %% 256)) 8.
proof.
  rewrite (_ : 6=5+1) 1:// functional_build_next 1:// merkle_zero_level5.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow3 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow3 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(5+1))) by rewrite /= ?tree_pow3 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level7 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 7 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+196) %% 256)) 4.
proof.
  rewrite (_ : 7=6+1) 1:// functional_build_next 1:// merkle_zero_level6.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow2 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow2 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(6+1))) by rewrite /= ?tree_pow2 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level8 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 8 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+5) %% 256)) 2.
proof.
  rewrite (_ : 8=7+1) 1:// functional_build_next 1:// merkle_zero_level7.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow1 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow1 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(7+1))) by rewrite /= ?tree_pow1 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_level9 : tree_nodes_value toy (nseq 32 0) 0 0 2 0 9 9 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+70) %% 256)) 1.
proof.
  rewrite (_ : 9=8+1) 1:// functional_build_next 1:// merkle_zero_level8.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow0 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow0 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(8+1))) by rewrite /= ?tree_pow0 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_zero_root : tree_root_value toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) = nseq 16 70.
proof. by rewrite /tree_root_value merkle_zero_level9 nth_mkseq 1://. qed.
lemma merkle_zero_auth0 : tree_auth_values toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 0 = [nseq 16 20; nseq 16 159; nseq 16 242; nseq 16 235; nseq 16 12; nseq 16 205; nseq 16 14; nseq 16 79; nseq 16 144].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_zero_level0 merkle_zero_level1 merkle_zero_level2 merkle_zero_level3 merkle_zero_level4 merkle_zero_level5 merkle_zero_level6 merkle_zero_level7 merkle_zero_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_zero_auth1 : tree_auth_values toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 1 = [nseq 16 3; nseq 16 159; nseq 16 242; nseq 16 235; nseq 16 12; nseq 16 205; nseq 16 14; nseq 16 79; nseq 16 144].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_zero_level0 merkle_zero_level1 merkle_zero_level2 merkle_zero_level3 merkle_zero_level4 merkle_zero_level5 merkle_zero_level6 merkle_zero_level7 merkle_zero_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_zero_auth511 : tree_auth_values toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 511 = [nseq 16 225; nseq 16 174; nseq 16 81; nseq 16 10; nseq 16 203; nseq 16 220; nseq 16 197; nseq 16 218; nseq 16 5].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_zero_level0 merkle_zero_level1 merkle_zero_level2 merkle_zero_level3 merkle_zero_level4 merkle_zero_level5 merkle_zero_level6 merkle_zero_level7 merkle_zero_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_zero_auth512 : tree_auth_values toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 512 = nseq 9 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 512);
    rewrite /build_leaves ?size_mkseq ?tree_pow9; smt().
qed.
lemma merkle_zero_auth4294967295 : tree_auth_values toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 4294967295 = nseq 9 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 0 0 2 0 9 (build_leaves 9) 4294967295);
    rewrite /build_leaves ?size_mkseq ?tree_pow9; smt().
qed.
lemma merkle_full_level0 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 0 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((17*i+3) %% 256)) 512.
proof.
  by rewrite functional_build_zero /build_leaves tree_pow9.
qed.
lemma merkle_full_level1 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 1 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((251*i+155) %% 256)) 256.
proof.
  rewrite (_ : 1=0+1) 1:// functional_build_next 1:// merkle_full_level0.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow8 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow8 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(0+1))) by rewrite /= ?tree_pow8 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level2 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 2 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((11*i+10) %% 256)) 128.
proof.
  rewrite (_ : 2=1+1) 1:// functional_build_next 1:// merkle_full_level1.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow7 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow7 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(1+1))) by rewrite /= ?tree_pow7 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level3 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 3 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+115) %% 256)) 64.
proof.
  rewrite (_ : 3=2+1) 1:// functional_build_next 1:// merkle_full_level2.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow6 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow6 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(2+1))) by rewrite /= ?tree_pow6 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level4 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 4 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+84) %% 256)) 32.
proof.
  rewrite (_ : 4=3+1) 1:// functional_build_next 1:// merkle_full_level3.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow5 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow5 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(3+1))) by rewrite /= ?tree_pow5 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level5 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 5 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+21) %% 256)) 16.
proof.
  rewrite (_ : 5=4+1) 1:// functional_build_next 1:// merkle_full_level4.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow4 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow4 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(4+1))) by rewrite /= ?tree_pow4 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level6 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 6 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+86) %% 256)) 8.
proof.
  rewrite (_ : 6=5+1) 1:// functional_build_next 1:// merkle_full_level5.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow3 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow3 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(5+1))) by rewrite /= ?tree_pow3 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level7 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 7 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+151) %% 256)) 4.
proof.
  rewrite (_ : 7=6+1) 1:// functional_build_next 1:// merkle_full_level6.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow2 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow2 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(6+1))) by rewrite /= ?tree_pow2 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level8 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 8 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+216) %% 256)) 2.
proof.
  rewrite (_ : 8=7+1) 1:// functional_build_next 1:// merkle_full_level7.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow1 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow1 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(7+1))) by rewrite /= ?tree_pow1 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_level9 : tree_nodes_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 9 (build_leaves 9) =
  mkseq (fun i => nseq 16 ((139*i+25) %% 256)) 1.
proof.
  rewrite (_ : 9=8+1) 1:// functional_build_next 1:// merkle_full_level8.
  apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_level_size size_mkseq /= ?tree_pow0 ?IntID.expr0.
  move=> i; rewrite functional_level_size /= ?tree_pow0 ?IntID.expr0 => hi.
  have hb : 0 <= i < 2^(max 0 (9-(8+1))) by rewrite /= ?tree_pow0 ?IntID.expr0.
  rewrite functional_level_nth 1:hb !nth_mkseq 1,2,3:/# /=.
  rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  congr; smt().
qed.
lemma merkle_full_root : tree_root_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) = nseq 16 25.
proof. by rewrite /tree_root_value merkle_full_level9 nth_mkseq 1://. qed.
lemma merkle_full_auth0 : tree_auth_values toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 0 = [nseq 16 20; nseq 16 150; nseq 16 21; nseq 16 254; nseq 16 223; nseq 16 160; nseq 16 225; nseq 16 34; nseq 16 99].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_full_level0 merkle_full_level1 merkle_full_level2 merkle_full_level3 merkle_full_level4 merkle_full_level5 merkle_full_level6 merkle_full_level7 merkle_full_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_full_auth1 : tree_auth_values toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 1 = [nseq 16 3; nseq 16 150; nseq 16 21; nseq 16 254; nseq 16 223; nseq 16 160; nseq 16 225; nseq 16 34; nseq 16 99].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_full_level0 merkle_full_level1 merkle_full_level2 merkle_full_level3 merkle_full_level4 merkle_full_level5 merkle_full_level6 merkle_full_level7 merkle_full_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_full_auth511 : tree_auth_values toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 511 = [nseq 16 225; nseq 16 165; nseq 16 116; nseq 16 29; nseq 16 158; nseq 16 175; nseq 16 152; nseq 16 173; nseq 16 216].
proof.
  rewrite /tree_auth_values /mkseq build_indices9 /=.
  rewrite merkle_full_level0 merkle_full_level1 merkle_full_level2 merkle_full_level3 merkle_full_level4 merkle_full_level5 merkle_full_level6 merkle_full_level7 merkle_full_level8.
  rewrite ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?IntID.expr0 /=.
  by do ! (rewrite nth_mkseq 1:// /=).
qed.
lemma merkle_full_auth512 : tree_auth_values toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 512 = nseq 9 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 512);
    rewrite /build_leaves ?size_mkseq ?tree_pow9; smt().
qed.
lemma merkle_full_auth4294967295 : tree_auth_values toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 4294967295 = nseq 9 (nseq 16 0).
proof.
  apply (functional_auth_outside toy (nseq 32 0) 4294967295 18446744073709551615 2 0 9 (build_leaves 9) 4294967295);
    rewrite /build_leaves ?size_mkseq ?tree_pow9; smt().
qed.
