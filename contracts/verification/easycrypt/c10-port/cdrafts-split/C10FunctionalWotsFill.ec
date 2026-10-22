(* Positional WOTS outputs from the actual shuffled visitation order. *)
require import AllCore List FMap RadixEncoding.
require import C10Bytes C10Representation C10RawOracle RawKeygen RawWots RawWotsFill KeygenPrefixes.
require import C10CallerInputBridge C10PrivateCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWotsValue C10FunctionalWotsChain C10FunctionalWotsKeygen C10FunctionalWotsShuffle.

op functional_sign_node f key seed layer tree kp d i =
  wots_chain_value (interpreted_backend f) seed (address_words layer tree 0 kp i 0 0)
    (functional_private_value f key layer tree kp i) 0 (digit 3 d i).
op functional_fill_queries f key seed layer tree kp d i =
  functional_private_query key layer tree kp i ::
    mkseq (functional_chain_query f seed layer tree kp i
      (functional_private_value f key layer tree kp i) 0) (digit 3 d i).
op functional_fill_history f h key seed layer tree kp d order n =
  foldl (fun table i => backend_history f table (functional_fill_queries f key seed layer tree kp d i)) h (take n order).
op functional_fill_cost d order n =
  foldl (fun total i => total+1+digit 3 d i) 0 (take n order).
op functional_fill_covered (order : int list) (sigma : raw_input list) (value : int -> raw_input) n =
  size sigma = 43 /\ forall j, j \in take n order => nth (nseq 16 0) sigma j = value j.

lemma functional_sign_nodes f key seed layer tree kp d : size d = 256 =>
  wots_sign_values (interpreted_backend f) seed key layer tree kp (bits_to_bytes d) =
    mkseq (functional_sign_node f key seed layer tree kp d) 43.
proof.
  move=> hd; rewrite /wots_sign_values /functional_sign_node /functional_private_value.
  apply eq_in_mkseq => i hi; rewrite /= -(functional_digit_bits d i hd hi).
  have hb := raw_digit_bounds d i.
  by rewrite (_ : max 0 (digit 3 d i) = digit 3 d i) 1:/#.
qed.

lemma functional_fill_covered_zero order value :
  functional_fill_covered order (nseq 43 (nseq 16 0)) value 0.
proof. by rewrite /functional_fill_covered size_nseq take0; smt(). qed.

lemma functional_fill_covered_next order sigma value n :
  perm_eq order (range 0 43) => 0 <= n < 43 => functional_fill_covered order sigma value n =>
  functional_fill_covered order (put sigma (nth 0 order n) (value (nth 0 order n))) value (n+1).
proof.
  move=> hp hn [hsize hv].
  have hlen : size order = 43 by smt(perm_eq_size size_range).
  have hi := caller_shuffle_index order n hp hn.
  rewrite /functional_fill_covered size_put hsize /= (take_nth 0 n order) 1:/#.
  move=> j hj; rewrite nth_put 1:/#; move: hj; rewrite mem_rcons; smt().
qed.

lemma functional_fill_covered_complete order sigma value :
  perm_eq order (range 0 43) => functional_fill_covered order sigma value 43 => sigma = mkseq value 43.
proof.
  move=> hp [hs hv].
  have hlen : size order = 43 by smt(perm_eq_size size_range).
  have he : take 43 order = order by rewrite -hlen take_size.
  apply (eq_from_nth (nseq 16 0)); first by rewrite hs size_mkseq.
  move=> i hi; rewrite nth_mkseq 1:/#; apply hv; rewrite he.
  smt(perm_eq_mem mem_range).
qed.

lemma functional_fill_history_zero f h key seed layer tree kp d order :
  functional_fill_history f h key seed layer tree kp d order 0 = h.
proof. by rewrite /functional_fill_history take0. qed.

lemma functional_fill_history_next f h key seed layer tree kp d order n : 0 <= n < size order =>
  functional_fill_history f h key seed layer tree kp d order (n+1) =
    backend_history f
      (remember (functional_fill_history f h key seed layer tree kp d order n)
        (functional_private_query key layer tree kp (nth 0 order n))
        (f (functional_private_query key layer tree kp (nth 0 order n))))
      (mkseq (functional_chain_query f seed layer tree kp (nth 0 order n)
        (functional_private_value f key layer tree kp (nth 0 order n)) 0) (digit 3 d (nth 0 order n))).
proof.
  move=> hn; rewrite /functional_fill_history (take_nth 0 n order hn) foldl_rcons.
  by rewrite /functional_fill_queries /backend_history /=.
qed.

lemma functional_fill_cost_zero d order : functional_fill_cost d order 0 = 0.
proof. by rewrite /functional_fill_cost take0. qed.

lemma functional_fill_cost_next d order n : 0 <= n < size order =>
  functional_fill_cost d order (n+1) = functional_fill_cost d order n + 1 + digit 3 d (nth 0 order n).
proof. by move=> hn; rewrite /functional_fill_cost (take_nth 0 n order hn) foldl_rcons. qed.

op functional_fill_initial_history f h shuffle =
  backend_history f h (mkseq (shuffle_block_preimage shuffle) (functional_shuffle_steps shuffle)).

lemma fixed_functional_fill f h c key0 seed0 layer0 tree0 kp0 d0 shuffle0 :
  hoare[CommonPrivateWots(FixedPrefix).fill :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ accepted = d0 /\ shuffle = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ size d0 = 256 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\ backend_width f /\
    FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    let order = functional_shuffle_order f shuffle0 in
    res = wots_sign_values (interpreted_backend f) seed0 key0 layer0 tree0 kp0 (bits_to_bytes d0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_fill_history f (functional_fill_initial_history f h shuffle0)
      key0 seed0 layer0 tree0 kp0 d0 order 43 /\
    FixedBackend.calls = c+functional_shuffle_steps shuffle0+functional_fill_cost d0 order 43].
proof.
  proc; seq 2 : (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ accepted = d0 /\ shuffle = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ size d0 = 256 /\ backend_width f /\
    sigma = nseq 43 (nseq 16 0) /\ order = functional_shuffle_order f shuffle0 /\ perm_eq order (range 0 43) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_fill_initial_history f h shuffle0 /\
    FixedBackend.calls = c+functional_shuffle_steps shuffle0).
  + call (fixed_functional_shuffle f h c key0 shuffle0).
    by auto; rewrite /functional_fill_initial_history.
  while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ accepted = d0 /\
    caller_fields layer0 tree0 kp0 /\ size d0 = 256 /\ backend_width f /\ 0 <= step <= 43 /\
    order = functional_shuffle_order f shuffle0 /\ perm_eq order (range 0 43) /\
    functional_fill_covered order sigma (functional_sign_node f key0 seed0 layer0 tree0 kp0 d0) step /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_fill_history f (functional_fill_initial_history f h shuffle0)
      key0 seed0 layer0 tree0 kp0 d0 order step /\
    FixedBackend.calls = c+functional_shuffle_steps shuffle0+functional_fill_cost d0 order step).
  + exists* step, order; elim* => step0 order0; wp.
    call (fixed_functional_chain f
      (remember (functional_fill_history f (functional_fill_initial_history f h shuffle0)
        key0 seed0 layer0 tree0 kp0 d0 order0 step0)
        (functional_private_query key0 layer0 tree0 kp0 (nth 0 order0 step0))
        (f (functional_private_query key0 layer0 tree0 kp0 (nth 0 order0 step0))))
      (c+functional_shuffle_steps shuffle0+functional_fill_cost d0 order0 step0+1)
      key0 seed0 layer0 tree0 kp0 (nth 0 order0 step0)
      (functional_private_value f key0 layer0 tree0 kp0 (nth 0 order0 step0)) 0 (digit 3 d0 (nth 0 order0 step0))).
    call (fixed_derive f
      (functional_fill_history f (functional_fill_initial_history f h shuffle0) key0 seed0 layer0 tree0 kp0 d0 order0 step0)
      (wots_private_preimage [] layer0 tree0 kp0 (nth 0 order0 step0))
      (c+functional_shuffle_steps shuffle0+functional_fill_cost d0 order0 step0) key0).
    auto => />; rewrite functional_private_prefix.
    move=> &hr hl0 hl ht0 ht hk0 hk hd hf hs0 hs hp hsize hv hc hlt hc2 hc3.
    have hn : 0 <= step0 < 43 by smt().
    have hlen : size (functional_shuffle_order f shuffle0) = 43 by smt(perm_eq_size size_range).
    have hi := caller_shuffle_index (functional_shuffle_order f shuffle0) step0 hp hn.
    have hdigit := raw_digit_bounds d0 (nth 0 (functional_shuffle_order f shuffle0) step0).
    have hnode := functional_private_node f key0 layer0 tree0 kp0
      (nth 0 (functional_shuffle_order f shuffle0) step0) hf.
    have hcover := functional_fill_covered_next (functional_shuffle_order f shuffle0) sigma{hr}
      (functional_sign_node f key0 seed0 layer0 tree0 kp0 d0) step0 hp hn _.
    - by rewrite /functional_fill_covered; smt().
    have hhist := functional_fill_history_next f (functional_fill_initial_history f h shuffle0)
      key0 seed0 layer0 tree0 kp0 d0 (functional_shuffle_order f shuffle0) step0 _; first smt().
    have hcost := functional_fill_cost_next d0 (functional_shuffle_order f shuffle0) step0 _; first smt().
    move: hcover; rewrite /functional_fill_covered /functional_sign_node.
    smt(caller_u32_size).
  auto => />; rewrite functional_fill_history_zero functional_fill_cost_zero.
  move=> hl0 hl ht0 ht hk0 hk hd hf hp hc; split.
  + by rewrite size_nseq take0; smt().
  move=> sigma0 step0 he hs0 hs hsize hv hc2.
  have hstep : step0 = 43 by smt().
  move: hv; rewrite hstep => hv.
  have hcover : functional_fill_covered (functional_shuffle_order f shuffle0) sigma0
    (functional_sign_node f key0 seed0 layer0 tree0 kp0 d0) 43
    by rewrite /functional_fill_covered; smt().
  have hout := functional_fill_covered_complete (functional_shuffle_order f shuffle0) sigma0
    (functional_sign_node f key0 seed0 layer0 tree0 kp0 d0) hp hcover.
  by rewrite hout (functional_sign_nodes f key0 seed0 layer0 tree0 kp0 d0 hd).
qed.

lemma fixed_functional_fill_lossless : islossless CommonPrivateWots(FixedPrefix).fill.
proof.
  proc; while true (43-step).
  + move=> z; wp; call fixed_functional_chain_lossless; call fixed_derive_ll; auto; smt().
  wp; call fixed_functional_shuffle_lossless; auto; smt().
qed.
