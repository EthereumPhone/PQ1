(* Native WOTS verification retains full counters, rejection, history and cost. *)
require import AllCore List FMap RadixEncoding.
require import C10Bytes C10Representation C10RawOracle C10RawGrind RawKeygen RawWots KeygenPrefixes.
require import C10CallerInputBridge C10FixedBackend C10FixedCallerBridge C10SearchAcceptance.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalWotsChain.

op functional_recover_node f seed layer tree kp d sigma i =
  wots_chain_value (interpreted_backend f) seed (address_words layer tree 0 kp i 0 0)
    (nth (nseq 16 0) sigma i) (digit 3 d i) (7-digit 3 d i).
op functional_recover_queries f seed layer tree kp d sigma i =
  mkseq (functional_chain_query f seed layer tree kp i (nth (nseq 16 0) sigma i) (digit 3 d i))
    (7-digit 3 d i).
op functional_recover_history f h seed layer tree kp d sigma n =
  foldl (fun table i => backend_history f table (functional_recover_queries f seed layer tree kp d sigma i))
    h (mkseq (fun i => i) n).
op functional_recover_cost d n = foldl (fun total i => total + (7-digit 3 d i)) 0 (mkseq (fun i => i) n).
op functional_recover_compression f seed layer tree kp d sigma =
  multi_preimage seed (address_words layer tree 1 kp 0 0 0)
    (mkseq (functional_recover_node f seed layer tree kp d sigma) 43).

lemma functional_recover_nodes f seed layer tree kp d sigma : size d = 256 =>
  wots_recover_nodes (interpreted_backend f) seed layer tree kp (bits_to_bytes d) sigma =
    mkseq (functional_recover_node f seed layer tree kp d sigma) 43.
proof.
  move=> hd; rewrite /wots_recover_nodes /functional_recover_node.
  apply eq_in_mkseq => i hi.
  rewrite /= -(functional_digit_bits d i hd hi).
  have hb := raw_digit_bounds d i.
  by rewrite (_ : max 0 (7-digit 3 d i) = 7-digit 3 d i) 1:/#.
qed.

lemma functional_recover_value f seed layer tree kp message sigma nonce : backend_width f =>
  wots_recover_value (interpreted_backend f) seed layer tree kp message sigma nonce =
    if count_accepts (f (functional_wots_query seed layer tree kp message nonce)) then
      hash_bytes_node (interpreted_backend f) (functional_recover_compression f seed layer tree kp
        (f (functional_wots_query seed layer tree kp message nonce)) sigma)
    else nseq 16 0.
proof.
  move=> hf.
  have hd := functional_digest_width f (functional_wots_query seed layer tree kp message nonce) hf.
  move: hd; rewrite /functional_wots_query => hd.
  rewrite /wots_recover_value /interpreted_backend /functional_wots_query subr_eq0
    -(wots_accept_bits _ hd) (functional_recover_nodes f seed layer tree kp _ sigma hd).
  by rewrite /functional_recover_compression /interpreted_backend.
qed.

lemma functional_recover_history_zero f h seed layer tree kp d sigma :
  functional_recover_history f h seed layer tree kp d sigma 0 = h.
proof. by rewrite /functional_recover_history mkseq0. qed.

lemma functional_recover_history_next f h seed layer tree kp d sigma i : 0 <= i =>
  functional_recover_history f h seed layer tree kp d sigma (i+1) =
    backend_history f (functional_recover_history f h seed layer tree kp d sigma i)
      (functional_recover_queries f seed layer tree kp d sigma i).
proof. by move=> hi; rewrite /functional_recover_history mkseqS 1:hi foldl_rcons. qed.

lemma functional_recover_cost_zero d : functional_recover_cost d 0 = 0.
proof. by rewrite /functional_recover_cost mkseq0. qed.

lemma functional_recover_cost_next d i : 0 <= i =>
  functional_recover_cost d (i+1) = functional_recover_cost d i + (7-digit 3 d i).
proof. by move=> hi; rewrite /functional_recover_cost mkseqS 1:hi foldl_rcons. qed.

lemma fixed_functional_recover f h c key0 seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  hoare[CommonInputWots(PreparationView(FixedPrefix)).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\ sigma = sigma0 /\ count = count0 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    let q = functional_wots_query seed0 layer0 tree0 kp0 message0 count0 in
    let d = f q in let h1 = remember h q d in
    let comp = functional_recover_compression f seed0 layer0 tree0 kp0 d sigma0 in
    res = wots_recover_value (interpreted_backend f) seed0 layer0 tree0 kp0 message0 sigma0 count0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = (if count_accepts d then
      remember (functional_recover_history f h1 seed0 layer0 tree0 kp0 d sigma0 43) comp (f comp) else h1) /\
    FixedBackend.calls = c + (if count_accepts d then 2+functional_recover_cost d 43 else 1)].
proof.
  proc; seq 1 : (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\ sigma = sigma0 /\ count = count0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\
    d = f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = remember h (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)
      (f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)) /\ FixedBackend.calls = c+1).
  + call (fixed_hash f h (functional_wots_query seed0 layer0 tree0 kp0 message0 count0) c).
    by auto; rewrite /functional_wots_query.
  sp 1; if.
  + wp; call (fixed_hash f
      (functional_recover_history f
        (remember h (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)
          (f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)))
        seed0 layer0 tree0 kp0 (f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)) sigma0 43)
      (functional_recover_compression f seed0 layer0 tree0 kp0
        (f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)) sigma0)
      (c+1+functional_recover_cost (f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0)) 43)).
    while (
      seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ sigma = sigma0 /\
      caller_fields layer0 tree0 kp0 /\ backend_width f /\ 0 <= i <= 43 /\
      d = f (functional_wots_query seed0 layer0 tree0 kp0 message0 count0) /\ count_accepts d /\
      elements = mkseq (functional_recover_node f seed0 layer0 tree0 kp0 d sigma0) i /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
      FixedBackend.history = functional_recover_history f
        (remember h (functional_wots_query seed0 layer0 tree0 kp0 message0 count0) d)
        seed0 layer0 tree0 kp0 d sigma0 i /\ FixedBackend.calls = c+1+functional_recover_cost d i).
    - exists* i, d; elim* => i0 d0; wp.
      call (fixed_functional_chain f
        (functional_recover_history f (remember h (functional_wots_query seed0 layer0 tree0 kp0 message0 count0) d0)
          seed0 layer0 tree0 kp0 d0 sigma0 i0)
        (c+1+functional_recover_cost d0 i0) key0 seed0 layer0 tree0 kp0 i0
        (nth (nseq 16 0) sigma0 i0) (digit 3 d0 i0) 7).
      auto => />; rewrite /functional_recover_queries /functional_recover_node;
        smt(raw_digit_bounds caller_u32_size functional_recover_history_next functional_recover_cost_next mkseqS).
    auto => />; rewrite functional_recover_history_zero functional_recover_cost_zero mkseq0
      /functional_recover_compression /wots_recover_value /interpreted_backend /functional_wots_query;
      smt(functional_digest_width interpreted_node functional_recover_nodes wots_accept_bits).
  auto => />; rewrite /wots_recover_value /interpreted_backend /functional_wots_query;
    smt(functional_digest_width wots_accept_bits).
qed.

lemma fixed_functional_recover_lossless :
  islossless CommonInputWots(PreparationView(FixedPrefix)).recover.
proof.
  proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call fixed_hash_ll; auto.
  sp 1; if; last by auto.
  wp; call fixed_hash_ll; while true (43-i).
  + move=> z; wp; call fixed_functional_chain_lossless; auto; smt().
  auto; smt().
qed.

lemma raw_functional_recover f h c key0 seed0 layer0 tree0 kp0 message0 sigma0 count0 :
  equiv[RawWots(PreparationView(FixedPrefix)).recover ~ CommonInputWots(PreparationView(FixedPrefix)).recover :
    ={seed,layer,tree,kp,message,sigma,count,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\
    message{1} = message0 /\ sigma{1} = sigma0 /\ count{1} = count0 /\ 0 <= count0 < 4294967296 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    let q = functional_wots_query seed0 layer0 tree0 kp0 message0 count0 in
    let d = f q in let h1 = remember h q d in
    let comp = functional_recover_compression f seed0 layer0 tree0 kp0 d sigma0 in
    res{1} = wots_recover_value (interpreted_backend f) seed0 layer0 tree0 kp0 message0 sigma0 count0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = (if count_accepts d then
      remember (functional_recover_history f h1 seed0 layer0 tree0 kp0 d sigma0 43) comp (f comp) else h1) /\
    FixedBackend.calls{1} = c + (if count_accepts d then 2+functional_recover_cost d 43 else 1)].
proof.
  conseq (caller_wots_recover (PreparationView(FixedPrefix))) (_ : true ==> true)
    (fixed_functional_recover f h c key0 seed0 layer0 tree0 kp0 message0 sigma0 count0) => //; smt().
qed.

lemma raw_functional_recover_lossless : islossless RawWots(PreparationView(FixedPrefix)).recover.
proof. exact (raw_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.
