require import AllCore List IntDiv Ring C10Representation C10FunctionalTreeValue.
op layer_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (merkle_recover_value hash_fn seed layer tree (wots_recover_value hash_fn seed layer tree kp message values nonce) (kp+1) auth).
(* Generated independent functional tree examples. *)
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
lemma forest_zero_0_step0 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 90).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_0_step1 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 119).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_0_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step2 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 234).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_0_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step3 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 23).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_0_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step4 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 250).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_0_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step5 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 55).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_0_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step6 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 138).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_0_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step7 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 215).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_0_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step8 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 154).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_0_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step9 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 247).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_0_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step10 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 42).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_0_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_step11 : tree_path_value toy (nseq 32 0) 0 0 3 0 (nseq 16 90) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 151).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_0_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_0_complete : fors_recover_value toy (nseq 32 0) 0 0 0 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 151).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 0 0 (nseq 16 3) = (nseq 16 90).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_0_step11.
qed.
lemma forest_zero_1_step0 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 120).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_1_step1 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 194).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_1_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step2 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 178).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_1_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step3 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 26).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_1_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step4 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 74).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_1_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step5 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 114).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_1_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step6 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 226).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_1_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step7 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 202).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_1_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step8 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 122).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_1_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step9 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 34).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_1_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step10 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 18).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_1_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_step11 : tree_path_value toy (nseq 32 0) 0 0 3 1 (nseq 16 120) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 122).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_1_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_1_complete : fors_recover_value toy (nseq 32 0) 0 1 1 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 122).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 1 1 (nseq 16 3) = (nseq 16 120).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_1_step11.
qed.
lemma forest_zero_2_step0 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 93).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_2_step1 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 171).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_2_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step2 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 47).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_2_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step3 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 209).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_2_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step4 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 89).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_2_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step5 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 175).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_2_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step6 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 187).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_2_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step7 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 149).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_2_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step8 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 93).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_2_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step9 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 103).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_2_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step10 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 17).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_2_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_step11 : tree_path_value toy (nseq 32 0) 0 0 3 2 (nseq 16 93) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 238).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_2_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_2_complete : fors_recover_value toy (nseq 32 0) 0 2 2047 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 238).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 2 2047 (nseq 16 3) = (nseq 16 93).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_2_step11.
qed.
lemma forest_zero_3_step0 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 123).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_3_step1 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 143).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_3_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step2 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 51).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_3_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step3 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 199).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_3_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step4 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 107).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_3_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step5 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 63).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_3_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step6 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 195).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_3_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step7 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 71).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_3_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step8 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 99).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_3_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step9 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 115).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_3_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step10 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 149).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_3_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_step11 : tree_path_value toy (nseq 32 0) 0 0 3 3 (nseq 16 123) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 104).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_3_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_3_complete : fors_recover_value toy (nseq 32 0) 0 3 2048 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 104).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 3 2048 (nseq 16 3) = (nseq 16 123).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_3_step11.
qed.
lemma forest_zero_4_step0 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 98).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_4_step1 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 193).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_4_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step2 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 242).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_4_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step3 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 13).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_4_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step4 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 186).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_4_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step5 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 121).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_4_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step6 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 134).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_4_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step7 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 139).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_4_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step8 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 185).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_4_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step9 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 157).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_4_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step10 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 31).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_4_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_step11 : tree_path_value toy (nseq 32 0) 0 0 3 4 (nseq 16 98) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 135).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_4_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_4_complete : fors_recover_value toy (nseq 32 0) 0 4 4294967295 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 135).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 4 4294967295 (nseq 16 3) = (nseq 16 98).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_4_step11.
qed.
lemma forest_zero_5_step0 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 212).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_5_step1 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 242).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_5_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step2 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 122).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_5_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step3 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 100).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_5_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step4 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 47).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_5_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step5 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 97).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_5_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step6 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 135).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_5_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step7 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 201).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_5_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step8 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 143).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_5_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step9 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 49).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_5_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step10 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 151).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_5_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_step11 : tree_path_value toy (nseq 32 0) 0 0 3 5 (nseq 16 212) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 153).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_5_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_5_complete : fors_recover_value toy (nseq 32 0) 0 5 17 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 153).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 5 17 (nseq 16 3) = (nseq 16 212).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_5_step11.
qed.
lemma forest_zero_6_step0 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 233).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_6_step1 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 227).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_6_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step2 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 75).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_6_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step3 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 117).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_6_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step4 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 191).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_6_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step5 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 188).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_6_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step6 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 191).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_6_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step7 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 220).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_6_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step8 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 79).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_6_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step9 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 124).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_6_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step10 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 95).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_6_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_step11 : tree_path_value toy (nseq 32 0) 0 0 3 6 (nseq 16 233) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 156).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_6_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_6_complete : fors_recover_value toy (nseq 32 0) 0 6 31 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 156).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 6 31 (nseq 16 3) = (nseq 16 233).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_6_step11.
qed.
lemma forest_zero_7_step0 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 148).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_7_step1 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 29).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_7_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step2 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 208).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_7_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step3 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 5).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_7_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step4 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 84).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_7_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step5 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 197).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_7_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step6 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 168).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_7_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step7 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 193).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_7_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step8 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 30).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_7_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step9 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 66).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_7_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step10 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 52).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_7_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_step11 : tree_path_value toy (nseq 32 0) 0 0 3 7 (nseq 16 148) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 202).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_7_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_7_complete : fors_recover_value toy (nseq 32 0) 0 7 511 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 202).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 7 511 (nseq 16 3) = (nseq 16 148).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_7_step11.
qed.
lemma forest_zero_8_step0 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 178).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_8_step1 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 183).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_8_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step2 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 130).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_8_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step3 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 215).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_8_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step4 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 242).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_8_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step5 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 7).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_8_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step6 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 42).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_8_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step7 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 219).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_8_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step8 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 116).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_8_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step9 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 248).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_8_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step10 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 173).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_8_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_step11 : tree_path_value toy (nseq 32 0) 0 0 3 8 (nseq 16 178) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 180).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_8_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_8_complete : fors_recover_value toy (nseq 32 0) 0 8 512 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 180).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 8 512 (nseq 16 3) = (nseq 16 178).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_8_step11.
qed.
lemma forest_zero_9_step0 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 170).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_9_step1 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 177).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_9_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step2 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 42).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_9_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step3 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 13).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_9_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step4 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 178).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_9_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step5 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 177).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_9_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step6 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 18).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_9_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step7 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 37).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_9_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step8 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 174).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_9_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step9 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 187).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_9_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step10 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 207).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_9_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_step11 : tree_path_value toy (nseq 32 0) 0 0 3 9 (nseq 16 170) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 205).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_9_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_9_complete : fors_recover_value toy (nseq 32 0) 0 9 1023 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 205).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 9 1023 (nseq 16 3) = (nseq 16 170).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_9_step11.
qed.
lemma forest_zero_10_step0 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 200).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_10_step1 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 199).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_10_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step2 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 136).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_10_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step3 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 55).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_10_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step4 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 8).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_10_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step5 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 71).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_10_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step6 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 152).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_10_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step7 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 31).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_10_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step8 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 204).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_10_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step9 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 9).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_10_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step10 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 73).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_10_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_step11 : tree_path_value toy (nseq 32 0) 0 0 3 10 (nseq 16 200) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 158).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_10_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_10_complete : fors_recover_value toy (nseq 32 0) 0 10 1024 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 158).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 10 1024 (nseq 16 3) = (nseq 16 200).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_10_step11.
qed.
lemma forest_zero_11_step0 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 173).
proof. by rewrite functional_path_zero. qed.
lemma forest_zero_11_step1 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 82).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_zero_11_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step2 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 125).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_zero_11_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step3 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 10).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_zero_11_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step4 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 49).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_zero_11_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step5 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 138).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_zero_11_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step6 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 237).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_zero_11_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step7 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 162).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_zero_11_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step8 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 57).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_zero_11_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step9 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 182).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_zero_11_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step10 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 103).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_zero_11_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_step11 : tree_path_value toy (nseq 32 0) 0 0 3 11 (nseq 16 173) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 15).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_zero_11_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_11_complete : fors_recover_value toy (nseq 32 0) 0 11 2046 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 15).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 0 11 2046 (nseq 16 3) = (nseq 16 173).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_zero_11_step11.
qed.
lemma forest_full_0_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 85).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_0_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 255).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_0_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 29).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_0_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 167).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_0_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 229).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_0_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 79).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_0_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 173).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_0_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 247).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_0_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 117).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_0_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 159).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_0_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 61).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_0_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 0 (nseq 16 85) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 71).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_0_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_0_complete : fors_recover_value toy (nseq 32 0) 4294967295 0 0 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 71).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 0 0 (nseq 16 3) = (nseq 16 85).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_0_step11.
qed.
lemma forest_full_1_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 115).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_1_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 44).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_1_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 51).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_1_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 172).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_1_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 99).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_1_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 172).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_1_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 19).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_1_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 44).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_1_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 67).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_1_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 44).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_1_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 243).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_1_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 1 (nseq 16 115) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 172).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_1_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_1_complete : fors_recover_value toy (nseq 32 0) 4294967295 1 1 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 172).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 1 1 (nseq 16 3) = (nseq 16 115).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_1_step11.
qed.
lemma forest_full_2_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 88).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_2_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 21).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_2_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 44).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_2_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 117).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_2_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 232).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_2_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 221).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_2_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 236).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_2_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 29).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_2_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 192).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_2_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 153).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_2_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 182).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_2_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 2 (nseq 16 88) 2047 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 154).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_2_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_2_complete : fors_recover_value toy (nseq 32 0) 4294967295 2 2047 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 154).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 2 2047 (nseq 16 3) = (nseq 16 88).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_2_step11.
qed.
lemma forest_full_3_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 118).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_3_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 23).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_3_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 102).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_3_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 87).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_3_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 86).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_3_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 87).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_3_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 230).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_3_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 103).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_3_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 62).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_3_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 27).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_3_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 168).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_3_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 3 (nseq 16 118) 2048 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 24).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_3_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_3_complete : fors_recover_value toy (nseq 32 0) 4294967295 3 2048 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 24).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 3 2048 (nseq 16 3) = (nseq 16 118).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_3_step11.
qed.
lemma forest_full_4_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 93).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_4_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 43).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_4_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 239).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_4_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 177).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_4_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 73).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_4_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 167).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_4_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 183).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_4_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 19).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_4_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 28).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_4_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 207).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_4_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 196).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_4_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 4 (nseq 16 93) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 51).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_4_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_4_complete : fors_recover_value toy (nseq 32 0) 4294967295 4 4294967295 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 51).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 4 4294967295 (nseq 16 3) = (nseq 16 93).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_4_step11.
qed.
lemma forest_full_5_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 207).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_5_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 92).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_5_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 251).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_5_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 246).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_5_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 72).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_5_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 49).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_5_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 50).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_5_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 33).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_5_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 114).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_5_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 145).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_5_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 50).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_5_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 5 (nseq 16 207) 17 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 129).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_5_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_5_complete : fors_recover_value toy (nseq 32 0) 4294967295 5 17 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 129).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 5 17 (nseq 16 3) = (nseq 16 207).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_5_step11.
qed.
lemma forest_full_6_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 228).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_6_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 77).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_6_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 72).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_6_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 25).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_6_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 78).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_6_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 234).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_6_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 220).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_6_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 114).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_6_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 196).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_6_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 250).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_6_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 172).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_6_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 6 (nseq 16 228) 31 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 130).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_6_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_6_complete : fors_recover_value toy (nseq 32 0) 4294967295 6 31 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 130).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 6 31 (nseq 16 3) = (nseq 16 228).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_6_step11.
qed.
lemma forest_full_7_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 143).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_7_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 135).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_7_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 205).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_7_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 169).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_7_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 227).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_7_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 243).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_7_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 217).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_7_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 73).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_7_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 129).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_7_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 116).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_7_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 173).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_7_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 7 (nseq 16 143) 511 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 164).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_7_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_7_complete : fors_recover_value toy (nseq 32 0) 4294967295 7 511 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 164).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 7 511 (nseq 16 3) = (nseq 16 143).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_7_step11.
qed.
lemma forest_full_8_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 173).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_8_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 63).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_8_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 181).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_8_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 103).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_8_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 221).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_8_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 31).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_8_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 77).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_8_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 251).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_8_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 79).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_8_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 160).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_8_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 176).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_8_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 8 (nseq 16 173) 512 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 244).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_8_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_8_complete : fors_recover_value toy (nseq 32 0) 4294967295 8 512 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 244).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 8 512 (nseq 16 3) = (nseq 16 173).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_8_step11.
qed.
lemma forest_full_9_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 165).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_9_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 27).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_9_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 39).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_9_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 177).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_9_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 65).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_9_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 223).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_9_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 67).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_9_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 173).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_9_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 17).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_9_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 237).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_9_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 116).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_9_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 9 (nseq 16 165) 1023 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 155).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_9_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_9_complete : fors_recover_value toy (nseq 32 0) 4294967295 9 1023 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 155).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 9 1023 (nseq 16 3) = (nseq 16 165).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_9_step11.
qed.
lemma forest_full_10_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 195).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_10_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 79).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_10_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 187).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_10_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 199).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_10_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 243).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_10_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 95).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_10_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 187).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_10_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 63).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_10_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 167).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_10_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 177).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_10_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 92).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_10_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 10 (nseq 16 195) 1024 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 192).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_10_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_10_complete : fors_recover_value toy (nseq 32 0) 4294967295 10 1024 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 192).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 10 1024 (nseq 16 3) = (nseq 16 195).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_10_step11.
qed.
lemma forest_full_11_step0 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 0 = (nseq 16 168).
proof. by rewrite functional_path_zero. qed.
lemma forest_full_11_step1 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 1 = (nseq 16 218).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// forest_full_11_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step2 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 2 = (nseq 16 224).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// forest_full_11_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step3 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 3 = (nseq 16 60).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// forest_full_11_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step4 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 4 = (nseq 16 214).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// forest_full_11_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step5 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 5 = (nseq 16 54).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// forest_full_11_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step6 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 6 = (nseq 16 100).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// forest_full_11_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step7 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 7 = (nseq 16 24).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// forest_full_11_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step8 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 8 = (nseq 16 146).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// forest_full_11_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step9 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 9 = (nseq 16 198).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// forest_full_11_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step10 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 10 = (nseq 16 50).
proof.
  rewrite (_: 10=9+1) 1:// functional_path_next 1:// forest_full_11_step9.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_step11 : tree_path_value toy (nseq 32 0) 0 4294967295 3 11 (nseq 16 168) 2046 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] 11 = (nseq 16 9).
proof.
  rewrite (_: 11=10+1) 1:// functional_path_next 1:// forest_full_11_step10.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_11_complete : fors_recover_value toy (nseq 32 0) 4294967295 11 2046 (nseq 16 3) [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)] = (nseq 16 9).
proof.
  have leaf : fors_leaf_value toy (nseq 32 0) 4294967295 11 2046 (nseq 16 3) = (nseq 16 168).
  + by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
  by rewrite /fors_recover_value leaf forest_full_11_step11.
qed.

lemma caller_indices12 : iota_ 0 12 = [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11].
proof. by rewrite (iotaS 0 11) 1:// (iotaS 1 10) 1:// (iotaS 2 9) 1:// (iotaS 3 8) 1:// (iotaS 4 7) 1:// (iotaS 5 6) 1:// (iotaS 6 5) 1:// (iotaS 7 4) 1:// (iotaS 8 3) 1:// (iotaS 9 2) 1:// (iotaS 10 1) 1:// (iotaS 11 0) 1:// iota0 1://. qed.
lemma forest_zero_roots : forest_recover_roots toy (nseq 32 0) 0 [0; 1; 2047; 2048; 4294967295; 17; 31; 511; 512; 1023; 1024; 2046; 123456] (nseq 13 (nseq 16 3)) (nseq 12 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)]) = [(nseq 16 151); (nseq 16 122); (nseq 16 238); (nseq 16 104); (nseq 16 135); (nseq 16 153); (nseq 16 156); (nseq 16 202); (nseq 16 180); (nseq 16 205); (nseq 16 158); (nseq 16 15); (nseq 16 222)].
proof.
  rewrite /forest_recover_roots /mkseq caller_indices12 /=.
  do ! (rewrite nth_nseq 1:// /=).
  rewrite forest_zero_0_complete forest_zero_1_complete forest_zero_2_complete forest_zero_3_complete forest_zero_4_complete forest_zero_5_complete forest_zero_6_complete forest_zero_7_complete forest_zero_8_complete forest_zero_9_complete forest_zero_10_complete forest_zero_11_complete.
  by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_zero_complete : forest_recover_value toy (nseq 32 0) 0 [0; 1; 2047; 2048; 4294967295; 17; 31; 511; 512; 1023; 1024; 2046; 123456] (nseq 13 (nseq 16 3)) (nseq 12 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)]) = (nseq 16 127).
proof.
  rewrite /forest_recover_value forest_zero_roots /forest_compress_value /hash_bytes_node
    /toy /multi_preimage /pad_node /address_words /u32_bytes /u64_bytes
    !tree_repeat16 !tree_repeat32 /mkseq tree_indices4 tree_indices8 /=.
  by rewrite ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
    ?IntID.expr0 !rev_cons !rev_nil /= ?tree_repeat16 ?tree_repeat32 /=.
qed.
lemma forest_full_roots : forest_recover_roots toy (nseq 32 0) 4294967295 [0; 1; 2047; 2048; 4294967295; 17; 31; 511; 512; 1023; 1024; 2046; 123456] (nseq 13 (nseq 16 3)) (nseq 12 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)]) = [(nseq 16 71); (nseq 16 172); (nseq 16 154); (nseq 16 24); (nseq 16 51); (nseq 16 129); (nseq 16 130); (nseq 16 164); (nseq 16 244); (nseq 16 155); (nseq 16 192); (nseq 16 9); (nseq 16 217)].
proof.
  rewrite /forest_recover_roots /mkseq caller_indices12 /=.
  do ! (rewrite nth_nseq 1:// /=).
  rewrite forest_full_0_complete forest_full_1_complete forest_full_2_complete forest_full_3_complete forest_full_4_complete forest_full_5_complete forest_full_6_complete forest_full_7_complete forest_full_8_complete forest_full_9_complete forest_full_10_complete forest_full_11_complete.
  by rewrite /fors_leaf_value (tree_toy_leaf _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma forest_full_complete : forest_recover_value toy (nseq 32 0) 4294967295 [0; 1; 2047; 2048; 4294967295; 17; 31; 511; 512; 1023; 1024; 2046; 123456] (nseq 13 (nseq 16 3)) (nseq 12 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67); (nseq 16 74); (nseq 16 81)]) = (nseq 16 244).
proof.
  rewrite /forest_recover_value forest_full_roots /forest_compress_value /hash_bytes_node
    /toy /multi_preimage /pad_node /address_words /u32_bytes /u64_bytes
    !tree_repeat16 !tree_repeat32 /mkseq tree_indices4 tree_indices8 /=.
  by rewrite ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
    ?IntID.expr0 !rev_cons !rev_nil /= ?tree_repeat16 ?tree_repeat32 /=.
qed.
lemma caller_indices9 : iota_ 0 9 = [0; 1; 2; 3; 4; 5; 6; 7; 8].
proof. by rewrite (iotaS 0 8) 1:// (iotaS 1 7) 1:// (iotaS 2 6) 1:// (iotaS 3 5) 1:// (iotaS 4 4) 1:// (iotaS 5 3) 1:// (iotaS 6 2) 1:// (iotaS 7 1) 1:// (iotaS 8 0) 1:// iota0 1://. qed.
lemma caller_indices43 : iota_ 0 43 = [0; 1; 2; 3; 4; 5; 6; 7; 8; 9; 10; 11; 12; 13; 14; 15; 16; 17; 18; 19; 20; 21; 22; 23; 24; 25; 26; 27; 28; 29; 30; 31; 32; 33; 34; 35; 36; 37; 38; 39; 40; 41; 42].
proof. by rewrite (iotaS 0 42) 1:// (iotaS 1 41) 1:// (iotaS 2 40) 1:// (iotaS 3 39) 1:// (iotaS 4 38) 1:// (iotaS 5 37) 1:// (iotaS 6 36) 1:// (iotaS 7 35) 1:// (iotaS 8 34) 1:// (iotaS 9 33) 1:// (iotaS 10 32) 1:// (iotaS 11 31) 1:// (iotaS 12 30) 1:// (iotaS 13 29) 1:// (iotaS 14 28) 1:// (iotaS 15 27) 1:// (iotaS 16 26) 1:// (iotaS 17 25) 1:// (iotaS 18 24) 1:// (iotaS 19 23) 1:// (iotaS 20 22) 1:// (iotaS 21 21) 1:// (iotaS 22 20) 1:// (iotaS 23 19) 1:// (iotaS 24 18) 1:// (iotaS 25 17) 1:// (iotaS 26 16) 1:// (iotaS 27 15) 1:// (iotaS 28 14) 1:// (iotaS 29 13) 1:// (iotaS 30 12) 1:// (iotaS 31 11) 1:// (iotaS 32 10) 1:// (iotaS 33 9) 1:// (iotaS 34 8) 1:// (iotaS 35 7) 1:// (iotaS 36 6) 1:// (iotaS 37 5) 1:// (iotaS 38 4) 1:// (iotaS 39 3) 1:// (iotaS 40 2) 1:// (iotaS 41 1) 1:// (iotaS 42 0) 1:// iota0 1://. qed.
lemma caller_repeat28 (x : int) : nseq 28 x = [x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x; x].
proof. by rewrite (nseqS 27 x) 1:// (nseqS 26 x) 1:// (nseqS 25 x) 1:// (nseqS 24 x) 1:// (nseqS 23 x) 1:// (nseqS 22 x) 1:// (nseqS 21 x) 1:// (nseqS 20 x) 1:// (nseqS 19 x) 1:// (nseqS 18 x) 1:// (nseqS 17 x) 1:// (nseqS 16 x) 1:// (nseqS 15 x) 1:// (nseqS 14 x) 1:// (nseqS 13 x) 1:// (nseqS 12 x) 1:// (nseqS 11 x) 1:// (nseqS 10 x) 1:// (nseqS 9 x) 1:// (nseqS 8 x) 1:// (nseqS 7 x) 1:// (nseqS 6 x) 1:// (nseqS 5 x) 1:// (nseqS 4 x) 1:// (nseqS 3 x) 1:// (nseqS 2 x) 1:// (nseqS 1 x) 1:// (nseqS 0 x) 1:// nseq0. qed.
lemma caller_digit_pow0 : 2^0 = 1.
proof. by rewrite  IntID.expr0. qed.
lemma caller_digit_pow3 : 2^3 = 8.
proof. by rewrite (IntID.exprS 2 2) 1:// (IntID.exprS 2 1) 1:// (IntID.exprS 2 0) 1:// caller_digit_pow0. qed.
lemma caller_digit_pow6 : 2^6 = 64.
proof. by rewrite (IntID.exprS 2 5) 1:// (IntID.exprS 2 4) 1:// (IntID.exprS 2 3) 1:// caller_digit_pow3. qed.
lemma caller_digit_pow9 : 2^9 = 512.
proof. by rewrite (IntID.exprS 2 8) 1:// (IntID.exprS 2 7) 1:// (IntID.exprS 2 6) 1:// caller_digit_pow6. qed.
lemma caller_digit_pow12 : 2^12 = 4096.
proof. by rewrite (IntID.exprS 2 11) 1:// (IntID.exprS 2 10) 1:// (IntID.exprS 2 9) 1:// caller_digit_pow9. qed.
lemma caller_digit_pow15 : 2^15 = 32768.
proof. by rewrite (IntID.exprS 2 14) 1:// (IntID.exprS 2 13) 1:// (IntID.exprS 2 12) 1:// caller_digit_pow12. qed.
lemma caller_digit_pow18 : 2^18 = 262144.
proof. by rewrite (IntID.exprS 2 17) 1:// (IntID.exprS 2 16) 1:// (IntID.exprS 2 15) 1:// caller_digit_pow15. qed.
lemma caller_digit_pow21 : 2^21 = 2097152.
proof. by rewrite (IntID.exprS 2 20) 1:// (IntID.exprS 2 19) 1:// (IntID.exprS 2 18) 1:// caller_digit_pow18. qed.
lemma caller_digit_pow24 : 2^24 = 16777216.
proof. by rewrite (IntID.exprS 2 23) 1:// (IntID.exprS 2 22) 1:// (IntID.exprS 2 21) 1:// caller_digit_pow21. qed.
lemma caller_digit_pow27 : 2^27 = 134217728.
proof. by rewrite (IntID.exprS 2 26) 1:// (IntID.exprS 2 25) 1:// (IntID.exprS 2 24) 1:// caller_digit_pow24. qed.
lemma caller_digit_pow30 : 2^30 = 1073741824.
proof. by rewrite (IntID.exprS 2 29) 1:// (IntID.exprS 2 28) 1:// (IntID.exprS 2 27) 1:// caller_digit_pow27. qed.
lemma caller_digit_pow33 : 2^33 = 8589934592.
proof. by rewrite (IntID.exprS 2 32) 1:// (IntID.exprS 2 31) 1:// (IntID.exprS 2 30) 1:// caller_digit_pow30. qed.
lemma caller_digit_pow36 : 2^36 = 68719476736.
proof. by rewrite (IntID.exprS 2 35) 1:// (IntID.exprS 2 34) 1:// (IntID.exprS 2 33) 1:// caller_digit_pow33. qed.
lemma caller_digit_pow39 : 2^39 = 549755813888.
proof. by rewrite (IntID.exprS 2 38) 1:// (IntID.exprS 2 37) 1:// (IntID.exprS 2 36) 1:// caller_digit_pow36. qed.
lemma caller_digit_pow42 : 2^42 = 4398046511104.
proof. by rewrite (IntID.exprS 2 41) 1:// (IntID.exprS 2 40) 1:// (IntID.exprS 2 39) 1:// caller_digit_pow39. qed.
lemma caller_digit_pow45 : 2^45 = 35184372088832.
proof. by rewrite (IntID.exprS 2 44) 1:// (IntID.exprS 2 43) 1:// (IntID.exprS 2 42) 1:// caller_digit_pow42. qed.
lemma caller_digit_pow48 : 2^48 = 281474976710656.
proof. by rewrite (IntID.exprS 2 47) 1:// (IntID.exprS 2 46) 1:// (IntID.exprS 2 45) 1:// caller_digit_pow45. qed.
lemma caller_digit_pow51 : 2^51 = 2251799813685248.
proof. by rewrite (IntID.exprS 2 50) 1:// (IntID.exprS 2 49) 1:// (IntID.exprS 2 48) 1:// caller_digit_pow48. qed.
lemma caller_digit_pow54 : 2^54 = 18014398509481984.
proof. by rewrite (IntID.exprS 2 53) 1:// (IntID.exprS 2 52) 1:// (IntID.exprS 2 51) 1:// caller_digit_pow51. qed.
lemma caller_digit_pow57 : 2^57 = 144115188075855872.
proof. by rewrite (IntID.exprS 2 56) 1:// (IntID.exprS 2 55) 1:// (IntID.exprS 2 54) 1:// caller_digit_pow54. qed.
lemma caller_digit_pow60 : 2^60 = 1152921504606846976.
proof. by rewrite (IntID.exprS 2 59) 1:// (IntID.exprS 2 58) 1:// (IntID.exprS 2 57) 1:// caller_digit_pow57. qed.
lemma caller_digit_pow63 : 2^63 = 9223372036854775808.
proof. by rewrite (IntID.exprS 2 62) 1:// (IntID.exprS 2 61) 1:// (IntID.exprS 2 60) 1:// caller_digit_pow60. qed.
lemma caller_digit_pow66 : 2^66 = 73786976294838206464.
proof. by rewrite (IntID.exprS 2 65) 1:// (IntID.exprS 2 64) 1:// (IntID.exprS 2 63) 1:// caller_digit_pow63. qed.
lemma caller_digit_pow69 : 2^69 = 590295810358705651712.
proof. by rewrite (IntID.exprS 2 68) 1:// (IntID.exprS 2 67) 1:// (IntID.exprS 2 66) 1:// caller_digit_pow66. qed.
lemma caller_digit_pow72 : 2^72 = 4722366482869645213696.
proof. by rewrite (IntID.exprS 2 71) 1:// (IntID.exprS 2 70) 1:// (IntID.exprS 2 69) 1:// caller_digit_pow69. qed.
lemma caller_digit_pow75 : 2^75 = 37778931862957161709568.
proof. by rewrite (IntID.exprS 2 74) 1:// (IntID.exprS 2 73) 1:// (IntID.exprS 2 72) 1:// caller_digit_pow72. qed.
lemma caller_digit_pow78 : 2^78 = 302231454903657293676544.
proof. by rewrite (IntID.exprS 2 77) 1:// (IntID.exprS 2 76) 1:// (IntID.exprS 2 75) 1:// caller_digit_pow75. qed.
lemma caller_digit_pow81 : 2^81 = 2417851639229258349412352.
proof. by rewrite (IntID.exprS 2 80) 1:// (IntID.exprS 2 79) 1:// (IntID.exprS 2 78) 1:// caller_digit_pow78. qed.
lemma caller_digit_pow84 : 2^84 = 19342813113834066795298816.
proof. by rewrite (IntID.exprS 2 83) 1:// (IntID.exprS 2 82) 1:// (IntID.exprS 2 81) 1:// caller_digit_pow81. qed.
lemma caller_digit_pow87 : 2^87 = 154742504910672534362390528.
proof. by rewrite (IntID.exprS 2 86) 1:// (IntID.exprS 2 85) 1:// (IntID.exprS 2 84) 1:// caller_digit_pow84. qed.
lemma caller_digit_pow90 : 2^90 = 1237940039285380274899124224.
proof. by rewrite (IntID.exprS 2 89) 1:// (IntID.exprS 2 88) 1:// (IntID.exprS 2 87) 1:// caller_digit_pow87. qed.
lemma caller_digit_pow93 : 2^93 = 9903520314283042199192993792.
proof. by rewrite (IntID.exprS 2 92) 1:// (IntID.exprS 2 91) 1:// (IntID.exprS 2 90) 1:// caller_digit_pow90. qed.
lemma caller_digit_pow96 : 2^96 = 79228162514264337593543950336.
proof. by rewrite (IntID.exprS 2 95) 1:// (IntID.exprS 2 94) 1:// (IntID.exprS 2 93) 1:// caller_digit_pow93. qed.
lemma caller_digit_pow99 : 2^99 = 633825300114114700748351602688.
proof. by rewrite (IntID.exprS 2 98) 1:// (IntID.exprS 2 97) 1:// (IntID.exprS 2 96) 1:// caller_digit_pow96. qed.
lemma caller_digit_pow102 : 2^102 = 5070602400912917605986812821504.
proof. by rewrite (IntID.exprS 2 101) 1:// (IntID.exprS 2 100) 1:// (IntID.exprS 2 99) 1:// caller_digit_pow99. qed.
lemma caller_digit_pow105 : 2^105 = 40564819207303340847894502572032.
proof. by rewrite (IntID.exprS 2 104) 1:// (IntID.exprS 2 103) 1:// (IntID.exprS 2 102) 1:// caller_digit_pow102. qed.
lemma caller_digit_pow108 : 2^108 = 324518553658426726783156020576256.
proof. by rewrite (IntID.exprS 2 107) 1:// (IntID.exprS 2 106) 1:// (IntID.exprS 2 105) 1:// caller_digit_pow105. qed.
lemma caller_digit_pow111 : 2^111 = 2596148429267413814265248164610048.
proof. by rewrite (IntID.exprS 2 110) 1:// (IntID.exprS 2 109) 1:// (IntID.exprS 2 108) 1:// caller_digit_pow108. qed.
lemma caller_digit_pow114 : 2^114 = 20769187434139310514121985316880384.
proof. by rewrite (IntID.exprS 2 113) 1:// (IntID.exprS 2 112) 1:// (IntID.exprS 2 111) 1:// caller_digit_pow111. qed.
lemma caller_digit_pow117 : 2^117 = 166153499473114484112975882535043072.
proof. by rewrite (IntID.exprS 2 116) 1:// (IntID.exprS 2 115) 1:// (IntID.exprS 2 114) 1:// caller_digit_pow114. qed.
lemma caller_digit_pow120 : 2^120 = 1329227995784915872903807060280344576.
proof. by rewrite (IntID.exprS 2 119) 1:// (IntID.exprS 2 118) 1:// (IntID.exprS 2 117) 1:// caller_digit_pow117. qed.
lemma caller_digit_pow123 : 2^123 = 10633823966279326983230456482242756608.
proof. by rewrite (IntID.exprS 2 122) 1:// (IntID.exprS 2 121) 1:// (IntID.exprS 2 120) 1:// caller_digit_pow120. qed.
lemma caller_digit_pow126 : 2^126 = 85070591730234615865843651857942052864.
proof. by rewrite (IntID.exprS 2 125) 1:// (IntID.exprS 2 124) 1:// (IntID.exprS 2 123) 1:// caller_digit_pow123. qed.
lemma layer_zero_query : wots_preimage (nseq 32 0) (address_words 0 0 0 0 0 0 0) (pad_node (nseq 16 3)) 0 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_zero_digest : toy (wots_preimage (nseq 32 0) (address_words 0 0 0 0 0 0 0) (pad_node (nseq 16 3)) 0) = (nseq 32 69).
proof. by rewrite layer_zero_query /toy /=. qed.
lemma layer_zero_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 0 0 0 0 0 0 0) (pad_node (nseq 16 3)) 0)) = 115.
proof. rewrite layer_zero_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_zero_step0 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_zero_step1 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 90).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_zero_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step2 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 72).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_zero_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step3 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 130).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_zero_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step4 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 144).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_zero_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step5 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 170).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_zero_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step6 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 216).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_zero_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step7 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 210).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_zero_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step8 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 32).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_zero_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_step9 : tree_path_value toy (nseq 32 0) 0 0 2 0 (nseq 16 0) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 250).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_zero_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_zero_complete : layer_recover_value toy (nseq 32 0) 0 0 0 (nseq 16 3) (nseq 43 (nseq 16 5)) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 250).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_zero_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_zero_step9. qed.
lemma layer_odd_query : wots_preimage (nseq 32 0) (address_words 1 512 0 1 0 0 0) (pad_node (nseq 16 3)) 9999999 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 1; 0; 0; 0; 0; 0; 0; 2; 0; 0; 0; 0; 0; 0; 0; 0; 1; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 152; 150; 127].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_odd_digest : toy (wots_preimage (nseq 32 0) (address_words 1 512 0 1 0 0 0) (pad_node (nseq 16 3)) 9999999) = (nseq 32 80).
proof. by rewrite layer_odd_query /toy /=. qed.
lemma layer_odd_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 1 512 0 1 0 0 0) (pad_node (nseq 16 3)) 9999999)) = 73.
proof. rewrite layer_odd_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_odd_step0 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_odd_step1 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 24).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_odd_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step2 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 90).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_odd_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step3 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 32).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_odd_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step4 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 194).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_odd_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step5 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 40).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_odd_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step6 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 42).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_odd_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step7 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 48).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_odd_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step8 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 146).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_odd_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_step9 : tree_path_value toy (nseq 32 0) 1 512 2 0 (nseq 16 0) 1 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 56).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_odd_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_odd_complete : layer_recover_value toy (nseq 32 0) 1 512 1 (nseq 16 3) (nseq 43 (nseq 16 5)) 9999999 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 56).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_odd_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_odd_step9. qed.
lemma layer_full_0_query : wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 0 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 0; 0; 0; 0; 255; 255; 255; 255; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_full_0_digest : toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 0) = (nseq 32 49).
proof. by rewrite layer_full_0_query /toy /=. qed.
lemma layer_full_0_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 0)) = 116.
proof. rewrite layer_full_0_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_full_0_step0 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_full_0_step1 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 107).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_full_0_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step2 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 248).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_full_0_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step3 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 127).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_full_0_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step4 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 104).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_full_0_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step5 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 243).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_full_0_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step6 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 28).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_full_0_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step7 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 77).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_full_0_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step8 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 119).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_full_0_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_step9 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 231).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_full_0_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_0_complete : layer_recover_value toy (nseq 32 0) 4294967295 18446744073709551615 4294967295 (nseq 16 3) (nseq 43 (nseq 16 5)) 0 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 231).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_full_0_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_full_0_step9. qed.
lemma layer_full_9999999_query : wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 9999999 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 0; 0; 0; 0; 255; 255; 255; 255; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 152; 150; 127].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_full_9999999_digest : toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 9999999) = (nseq 32 49).
proof. by rewrite layer_full_9999999_query /toy /=. qed.
lemma layer_full_9999999_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 9999999)) = 116.
proof. rewrite layer_full_9999999_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_full_9999999_step0 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_full_9999999_step1 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 107).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_full_9999999_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step2 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 248).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_full_9999999_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step3 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 127).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_full_9999999_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step4 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 104).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_full_9999999_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step5 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 243).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_full_9999999_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step6 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 28).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_full_9999999_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step7 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 77).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_full_9999999_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step8 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 119).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_full_9999999_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_step9 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 231).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_full_9999999_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_9999999_complete : layer_recover_value toy (nseq 32 0) 4294967295 18446744073709551615 4294967295 (nseq 16 3) (nseq 43 (nseq 16 5)) 9999999 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 231).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_full_9999999_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_full_9999999_step9. qed.
lemma layer_full_10000000_query : wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 10000000 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 0; 0; 0; 0; 255; 255; 255; 255; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 152; 150; 128].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_full_10000000_digest : toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 10000000) = (nseq 32 49).
proof. by rewrite layer_full_10000000_query /toy /=. qed.
lemma layer_full_10000000_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 10000000)) = 116.
proof. rewrite layer_full_10000000_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_full_10000000_step0 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_full_10000000_step1 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 107).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_full_10000000_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step2 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 248).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_full_10000000_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step3 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 127).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_full_10000000_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step4 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 104).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_full_10000000_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step5 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 243).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_full_10000000_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step6 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 28).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_full_10000000_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step7 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 77).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_full_10000000_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step8 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 119).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_full_10000000_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_step9 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 231).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_full_10000000_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_10000000_complete : layer_recover_value toy (nseq 32 0) 4294967295 18446744073709551615 4294967295 (nseq 16 3) (nseq 43 (nseq 16 5)) 10000000 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 231).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_full_10000000_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_full_10000000_step9. qed.
lemma layer_full_4294967295_query : wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 4294967295 = [0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 255; 0; 0; 0; 0; 255; 255; 255; 255; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 3; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 0; 255; 255; 255; 255].
proof. by rewrite /wots_preimage /pad_node /address_words /u32_bytes /u64_bytes
  !tree_repeat16 !tree_repeat32 caller_repeat28 /mkseq tree_indices4 tree_indices8 /=
  ?tree_pow8 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56
  ?IntID.expr0 !rev_cons !rev_nil /=. qed.
lemma layer_full_4294967295_digest : toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 4294967295) = (nseq 32 49).
proof. by rewrite layer_full_4294967295_query /toy /=. qed.
lemma layer_full_4294967295_rejected : wots_sum (toy (wots_preimage (nseq 32 0) (address_words 4294967295 18446744073709551615 0 4294967295 0 0 0) (pad_node (nseq 16 3)) 4294967295)) = 116.
proof. rewrite layer_full_4294967295_digest /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=.
  by rewrite ?caller_digit_pow0 ?caller_digit_pow3 ?caller_digit_pow6 ?caller_digit_pow9 ?caller_digit_pow12 ?caller_digit_pow15 ?caller_digit_pow18 ?caller_digit_pow21 ?caller_digit_pow24 ?caller_digit_pow27 ?caller_digit_pow30 ?caller_digit_pow33 ?caller_digit_pow36 ?caller_digit_pow39 ?caller_digit_pow42 ?caller_digit_pow45 ?caller_digit_pow48 ?caller_digit_pow51 ?caller_digit_pow54 ?caller_digit_pow57 ?caller_digit_pow60 ?caller_digit_pow63 ?caller_digit_pow66 ?caller_digit_pow69 ?caller_digit_pow72 ?caller_digit_pow75 ?caller_digit_pow78 ?caller_digit_pow81 ?caller_digit_pow84 ?caller_digit_pow87 ?caller_digit_pow90 ?caller_digit_pow93 ?caller_digit_pow96 ?caller_digit_pow99 ?caller_digit_pow102 ?caller_digit_pow105 ?caller_digit_pow108 ?caller_digit_pow111 ?caller_digit_pow114 ?caller_digit_pow117 ?caller_digit_pow120 ?caller_digit_pow123 ?caller_digit_pow126 /=. qed.
lemma layer_full_4294967295_step0 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 0 = (nseq 16 0).
proof. by rewrite functional_path_zero. qed.
lemma layer_full_4294967295_step1 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 1 = (nseq 16 107).
proof.
  rewrite (_: 1=0+1) 1:// functional_path_next 1:// layer_full_4294967295_step0.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step2 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 2 = (nseq 16 248).
proof.
  rewrite (_: 2=1+1) 1:// functional_path_next 1:// layer_full_4294967295_step1.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step3 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 3 = (nseq 16 127).
proof.
  rewrite (_: 3=2+1) 1:// functional_path_next 1:// layer_full_4294967295_step2.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step4 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 4 = (nseq 16 104).
proof.
  rewrite (_: 4=3+1) 1:// functional_path_next 1:// layer_full_4294967295_step3.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step5 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 5 = (nseq 16 243).
proof.
  rewrite (_: 5=4+1) 1:// functional_path_next 1:// layer_full_4294967295_step4.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step6 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 6 = (nseq 16 28).
proof.
  rewrite (_: 6=5+1) 1:// functional_path_next 1:// layer_full_4294967295_step5.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step7 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 7 = (nseq 16 77).
proof.
  rewrite (_: 7=6+1) 1:// functional_path_next 1:// layer_full_4294967295_step6.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step8 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 8 = (nseq 16 119).
proof.
  rewrite (_: 8=7+1) 1:// functional_path_next 1:// layer_full_4294967295_step7.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_step9 : tree_path_value toy (nseq 32 0) 4294967295 18446744073709551615 2 0 (nseq 16 0) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] 9 = (nseq 16 231).
proof.
  rewrite (_: 9=8+1) 1:// functional_path_next 1:// layer_full_4294967295_step8.
  rewrite /tree_path_step ?tree_pow1 ?tree_pow2 ?tree_pow3 ?tree_pow4 ?tree_pow5 ?tree_pow6 ?tree_pow7 ?tree_pow8 ?tree_pow9 ?tree_pow10 ?tree_pow11 ?tree_pow16 ?tree_pow24 ?tree_pow32 ?tree_pow40 ?tree_pow48 ?tree_pow56 ?IntID.expr0 /=.
  by rewrite (tree_toy_pair _ _ _ (tree_address_size _ _ _ _ _ _)) tree_address_score /=.
qed.
lemma layer_full_4294967295_complete : layer_recover_value toy (nseq 32 0) 4294967295 18446744073709551615 4294967295 (nseq 16 3) (nseq 43 (nseq 16 5)) 4294967295 [(nseq 16 11); (nseq 16 18); (nseq 16 25); (nseq 16 32); (nseq 16 39); (nseq 16 46); (nseq 16 53); (nseq 16 60); (nseq 16 67)] = (nseq 16 231).
proof.
  rewrite /layer_recover_value /wots_recover_value layer_full_4294967295_rejected /wots_target /=.
  try rewrite /merkle_recover_value.
  by rewrite ?layer_full_4294967295_step9. qed.

op zero_backend (_ : int list) = nseq 32 0.
lemma caller_zero_sum : wots_sum (nseq 32 0) = 0.
proof. by rewrite /wots_sum /wots_field /word_window /byte_word /byte_word_le
  tree_repeat32 /mkseq caller_indices43 /=. qed.
lemma layer_rejected_0 : layer_recover_value zero_backend (nseq 32 0) 4294967295 18446744073709551615 4294967295
  (nseq 16 3) [] 0 [] = (nseq 16 0).
proof.
  rewrite /layer_recover_value /wots_recover_value /zero_backend caller_zero_sum /wots_target /=.
  by rewrite /merkle_recover_value /tree_path_value /mkseq caller_indices9 /=
    /tree_path_step /tree_pair_value /hash_bytes_node /zero_backend !tree_repeat32 !tree_repeat16 /=.
qed.
lemma layer_rejected_9999999 : layer_recover_value zero_backend (nseq 32 0) 4294967295 18446744073709551615 4294967295
  (nseq 16 3) [] 9999999 [] = (nseq 16 0).
proof.
  rewrite /layer_recover_value /wots_recover_value /zero_backend caller_zero_sum /wots_target /=.
  by rewrite /merkle_recover_value /tree_path_value /mkseq caller_indices9 /=
    /tree_path_step /tree_pair_value /hash_bytes_node /zero_backend !tree_repeat32 !tree_repeat16 /=.
qed.
lemma layer_rejected_10000000 : layer_recover_value zero_backend (nseq 32 0) 4294967295 18446744073709551615 4294967295
  (nseq 16 3) [] 10000000 [] = (nseq 16 0).
proof.
  rewrite /layer_recover_value /wots_recover_value /zero_backend caller_zero_sum /wots_target /=.
  by rewrite /merkle_recover_value /tree_path_value /mkseq caller_indices9 /=
    /tree_path_step /tree_pair_value /hash_bytes_node /zero_backend !tree_repeat32 !tree_repeat16 /=.
qed.
lemma layer_rejected_4294967295 : layer_recover_value zero_backend (nseq 32 0) 4294967295 18446744073709551615 4294967295
  (nseq 16 3) [] 4294967295 [] = (nseq 16 0).
proof.
  rewrite /layer_recover_value /wots_recover_value /zero_backend caller_zero_sum /wots_target /=.
  by rewrite /merkle_recover_value /tree_path_value /mkseq caller_indices9 /=
    /tree_path_step /tree_pair_value /hash_bytes_node /zero_backend !tree_repeat32 !tree_repeat16 /=.
qed.
