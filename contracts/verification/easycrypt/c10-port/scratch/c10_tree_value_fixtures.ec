(* Generated independent functional tree examples. *)
require import AllCore List IntDiv Ring C10Representation C10FunctionalTreeValue.
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
lemma merkle_zero_step0 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 3).
proof. by rewrite functional_path_zero. qed.
lemma merkle_zero_step1 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 159).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// merkle_zero_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step2 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 123).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// merkle_zero_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step3 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 23).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// merkle_zero_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step4 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 243).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// merkle_zero_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step5 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 143).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// merkle_zero_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step6 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 107).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// merkle_zero_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step7 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 7).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// merkle_zero_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step8 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 227).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// merkle_zero_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_step9 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 127).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// merkle_zero_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_zero_complete : merkle_recover_value toy (nseq 32 0) 0 0 (nseq 16 3) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 127).
proof.
  by rewrite /merkle_recover_value merkle_zero_step9.
qed.
lemma merkle_odd_step0 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 3).
proof. by rewrite functional_path_zero. qed.
lemma merkle_odd_step1 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 111).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// merkle_odd_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step2 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 43).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// merkle_odd_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step3 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 231).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// merkle_odd_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step4 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 163).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// merkle_odd_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step5 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 95).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// merkle_odd_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step6 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 27).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// merkle_odd_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step7 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 215).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// merkle_odd_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step8 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 147).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// merkle_odd_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_step9 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 79).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// merkle_odd_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_odd_complete : merkle_recover_value toy (nseq 32 0) 0 0 (nseq 16 3) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 79).
proof.
  by rewrite /merkle_recover_value merkle_odd_step9.
qed.
lemma merkle_full_step0 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 3).
proof. by rewrite functional_path_zero. qed.
lemma merkle_full_step1 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 194).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// merkle_full_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step2 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 211).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// merkle_full_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step3 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 78).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// merkle_full_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step4 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 219).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// merkle_full_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step5 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 250).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// merkle_full_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step6 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 231).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// merkle_full_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step7 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 76).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// merkle_full_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step8 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 90).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// merkle_full_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_step9 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 158).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// merkle_full_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma merkle_full_complete : merkle_recover_value toy (nseq 32 0) 4294967295 18446744073709551615 (nseq 16 3) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 158).
proof.
  by rewrite /merkle_recover_value merkle_full_step9.
qed.
lemma fors_zero_step0 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 90).
proof. by rewrite functional_path_zero. qed.
lemma fors_zero_step1 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 119).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// fors_zero_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step2 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 234).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// fors_zero_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step3 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 23).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// fors_zero_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step4 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 250).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// fors_zero_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step5 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 55).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// fors_zero_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step6 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 138).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// fors_zero_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step7 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 215).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// fors_zero_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step8 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 154).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// fors_zero_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step9 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 247).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// fors_zero_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step10 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 42).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// fors_zero_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_step11 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 151).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// fors_zero_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_zero_complete : fors_recover_value toy (nseq 32 0) 0 0 0 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 151).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 0 0 (nseq 16 3) = (nseq 16 90).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf fors_zero_step11.
qed.
lemma fors_odd_step0 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 109).
proof. by rewrite functional_path_zero. qed.
lemma fors_odd_step1 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 120).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// fors_odd_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step2 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 1).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// fors_odd_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step3 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 40).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// fors_odd_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step4 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 129).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// fors_odd_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step5 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 88).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// fors_odd_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step6 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 129).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// fors_odd_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step7 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 8).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// fors_odd_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step8 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 1).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// fors_odd_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step9 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 56).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// fors_odd_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step10 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 1).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// fors_odd_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_step11 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 109) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 232).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// fors_odd_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_odd_complete : fors_recover_value toy (nseq 32 0) 0 0 1 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 232).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 0 1 (nseq 16 3) = (nseq 16 109).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf fors_odd_step11.
qed.
lemma fors_outside_step0 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 227).
proof. by rewrite functional_path_zero. qed.
lemma fors_outside_step1 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 79).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// fors_outside_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step2 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 219).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// fors_outside_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step3 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 71).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// fors_outside_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step4 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 83).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// fors_outside_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step5 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 127).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// fors_outside_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step6 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 235).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// fors_outside_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step7 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 71).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// fors_outside_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step8 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 203).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// fors_outside_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step9 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 51).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// fors_outside_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step10 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 61).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// fors_outside_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_step11 : tree_path_value toy (nseq 32 0) 0 1 3 12 (nseq 16 227) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 232).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// fors_outside_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_outside_complete : fors_recover_value toy (nseq 32 0) 1 12 2048 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 232).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 1 12 2048 (nseq 16 3) = (nseq 16 227).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf fors_outside_step11.
qed.
lemma fors_full_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 38).
proof. by rewrite functional_path_zero. qed.
lemma fors_full_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 185).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// fors_full_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 206).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// fors_full_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 189).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// fors_full_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 110).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// fors_full_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 161).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// fors_full_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 210).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// fors_full_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 235).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// fors_full_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 93).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// fors_full_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 245).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// fors_full_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 219).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// fors_full_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4294967295 (nseq 16 38) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 151).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// fors_full_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma fors_full_complete : fors_recover_value toy (nseq 32 0) 4294967295 4294967295 4294967295 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 151).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 4294967295 4294967295 (nseq 16 3) = (nseq 16 38).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf fors_full_step11.
qed.
