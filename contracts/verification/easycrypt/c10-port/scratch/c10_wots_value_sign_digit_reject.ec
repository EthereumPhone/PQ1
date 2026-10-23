require import AllCore List BitEncoding C10Bytes C10RawOracle C10RawGrind C10Randomizer RawKeygen C10Representation C10AddressInputBridge C10CallerInputBridge C10FixedCallerBridge C10RepresentationBridge ShuffleBytes RadixEncoding FMap RawWots KeygenPrefixes C10FixedBackend C10FunctionalWots C10PrivateCallerBridge C10SearchAcceptance C10ShuffleBridge ShuffleSwap RawWotsFill C10Counter.

op hash_bytes_node (hash_fn : (int list -> int list)) (bs : (int list)) : (int list) =
  (take 16 (hash_fn bs)).

op wots_secret_value (hash_fn : (int list -> int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) (ci : int) : (int list) =
  (hash_bytes_node hash_fn (wots_private_preimage secret layer tree kp ci)).

op wots_chain_value (hash_fn : (int list -> int list)) (seed : (int list)) (address : (int list)) (value : (int list)) (start : int) (steps : int) : (int list) =
  (foldr (fun i current => (hash_bytes_node hash_fn (th_preimage seed (chain_position_words address (start + (i))) (pad_node current)))) value (rev (mkseq (fun i => i) steps))).

op wots_keygen_nodes (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) : ((int list) list) =
  (mkseq (fun i => (wots_chain_value hash_fn seed (address_words layer tree 0 kp (i) 0 0) (wots_secret_value hash_fn secret layer tree kp (i)) 0 7)) 43).

op wots_keygen_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) : (int list) =
  (hash_bytes_node hash_fn (multi_preimage seed (address_words layer tree 1 kp 0 0 0) (wots_keygen_nodes hash_fn seed secret layer tree kp))).

op wots_sign_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) (bs : (int list)) : ((int list) list) =
  (mkseq (fun i => (wots_chain_value hash_fn seed (address_words layer tree 0 kp (i) 0 0) (wots_secret_value hash_fn secret layer tree kp (i)) 0 (max 0 (7 - (wots_field bs i))))) 43).

op wots_recover_nodes (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (bs : (int list)) (values : ((int list) list)) : ((int list) list) =
  (mkseq (fun i => (wots_chain_value hash_fn seed (address_words layer tree 0 kp (i) 0 0) (nth (nseq 16 0) values i) (wots_field bs i) (max 0 (7 - (wots_field bs i))))) 43).

op wots_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) : (int list) =
  (if ((wots_sum (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce))) - (wots_target )) = 0 then (hash_bytes_node hash_fn (multi_preimage seed (address_words layer tree 1 kp 0 0 0) (wots_recover_nodes hash_fn seed layer tree kp (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce)) values))) else (nseq 16 0)).

(* Pure WOTS values under the disclosed deterministic backend interpretation.
   These laws do not identify that function with the sampled Shared oracle. *)





import BitChunking.

op interpreted_backend (f : raw_input -> digest) (x : raw_input) = bits_to_bytes (f x).

lemma functional_digest_width f x : backend_width f => size (f x) = 256.
proof. by rewrite /backend_width; smt(). qed.

lemma interpreted_backend_width f x : backend_width f => size (interpreted_backend f x) = 32.
proof. by move=> hf; rewrite /interpreted_backend bits_to_bytes_size; move: hf; rewrite /backend_width; smt(). qed.

lemma node_bytes_common d : size d = 256 => node d = take 16 (bits_to_bytes d).
proof.
  move=> hd.
  have hlo : size (take 128 d) = 128 by rewrite size_take 1:// hd.
  have hhi : size (bits_to_bytes (drop 128 d)) = 16
    by rewrite bits_to_bytes_size size_drop 1:// hd.
  have hcat : bits_to_bytes d = bits_to_bytes (drop 128 d) ++ bits_to_bytes (take 128 d).
  + rewrite -{1}(cat_take_drop 128 d) /bits_to_bytes chunk_cat 1:hlo 1://.
    by rewrite map_cat rev_cat.
  by rewrite (node_exact d hd) /compact_r /truncate_r hcat take_cat hhi /= take0 cats0.
qed.

lemma functional_digit_bits d i : size d = 256 => 0 <= i < 43 =>
  digit 3 d i = wots_field (bits_to_bytes d) i.
proof.
  move=> hd hi.
  have hb := shuffle_bytes_valid d.
  have hs : size (bits_to_bytes d) = 32 by rewrite bits_to_bytes_size hd.
  have he := wots_common (bits_to_bytes d) i hs hi hb.
  by move: he; rewrite bits_bytes_roundtrip 1:hd.
qed.

lemma interpreted_node f x : backend_width f =>
  node (f x) = hash_bytes_node (interpreted_backend f) x.
proof. move=> hf; rewrite /hash_bytes_node /interpreted_backend; apply node_bytes_common; move: hf; rewrite /backend_width; smt(). qed.

lemma functional_chain_fold f seed adr value start steps :
  wots_chain_value f seed adr value start steps =
    foldl (fun current i => hash_bytes_node f
      (th_preimage seed (chain_position_words adr (start+i)) (pad_node current)))
      value (mkseq (fun i => i) steps).
proof. by rewrite /wots_chain_value -foldl_rev revK. qed.

lemma functional_chain_zero f seed adr value start :
  wots_chain_value f seed adr value start 0 = value.
proof. by rewrite functional_chain_fold mkseq0. qed.

lemma functional_chain_next f seed adr value start n : 0 <= n =>
  wots_chain_value f seed adr value start (n+1) =
    hash_bytes_node f (th_preimage seed (chain_position_words adr (start+n))
      (pad_node (wots_chain_value f seed adr value start n))).
proof. by move=> hn; rewrite !functional_chain_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_chain_address layer tree kp index pos :
  caller_fields layer tree kp => 0 <= index < 2^32 => 0 <= pos < 2^32 =>
  chain_position_words (address_words layer tree 0 kp index 0 0) pos =
    address_words layer tree 0 kp index pos 0.
proof.
  move=> [hl [ht hk]] hi hp.
  have hz : 0 <= 0 < 2^32 by rewrite caller_u32_size.
  by rewrite -(address_common layer tree 0 kp index 0 0 hl ht hz hk hi hz hz)
    (chain_position_common layer tree 0 kp index 0 0 pos hp)
    (address_common layer tree 0 kp index pos 0 hl ht hz hk hi hp hz).
qed.

(* Ordered WOTS chains with arbitrary consistent backend prehistory.
   Query history and calls describe the actual imperative loop, not evaluation
   cost of the generated mathematical expression. *)





op functional_chain_query f seed layer tree kp index value start i =
  th_preimage seed (address_words layer tree 0 kp index (start+i) 0)
    (pad_node (wots_chain_value (interpreted_backend f) seed
      (address_words layer tree 0 kp index 0 0) value start i)).

lemma functional_chain_step f seed layer tree kp index value start i :
  backend_width f => caller_fields layer tree kp => 0 <= index < 2^32 =>
  0 <= i => 0 <= start+i < 2^32 =>
  node (f (functional_chain_query f seed layer tree kp index value start i)) =
    wots_chain_value (interpreted_backend f) seed
      (address_words layer tree 0 kp index 0 0) value start (i+1).
proof.
  move=> hf ha hi hn hp.
  by rewrite functional_chain_next 1:hn
    (functional_chain_address layer tree kp index (start+i) ha hi hp)
    /functional_chain_query interpreted_node 1:hf.
qed.

lemma fixed_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0 :
  hoare[CommonInputWots(PreparationView(FixedPrefix)).chain :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    current = value0 /\ start = start0 /\ stop = stop0 /\
    caller_fields layer0 tree0 kp0 /\ 0 <= index0 < 2^32 /\ 0 <= start0 <= stop0 /\ stop0 <= 2^32 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (stop0-start0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (stop0-start0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+(stop0-start0)].
proof.
  proc; while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ index = index0 /\
    start = start0 /\ stop = stop0 /\ caller_fields layer0 tree0 kp0 /\
    0 <= index0 < 2^32 /\ 0 <= start0 <= j <= stop0 /\ stop0 <= 2^32 /\ backend_width f /\
    current = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (j-start0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (j-start0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+(j-start0)).
  + exists* j; elim* => j0; wp.
    call (fixed_hash f
      (backend_history f h (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (j0-start0)))
      (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0 (j0-start0)) (c+(j0-start0))).
    auto => />; rewrite /functional_chain_query;
      smt(functional_chain_step backend_history_mkseqS).
  auto => />; rewrite functional_chain_zero mkseq0 backend_history_nil; smt().
qed.

lemma fixed_functional_chain_lossless :
  islossless CommonInputWots(PreparationView(FixedPrefix)).chain.
proof.
  proc; while true (max 0 (stop-j)).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

lemma raw_functional_chain_lossless :
  islossless RawWots(PreparationView(FixedPrefix)).chain.
proof. exact (raw_chain_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma raw_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0 :
  equiv[RawWots(PreparationView(FixedPrefix)).chain ~
    CommonInputWots(PreparationView(FixedPrefix)).chain :
    ={seed,layer,tree,kp,index,current,start,stop,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ index{1} = index0 /\
    current{1} = value0 /\ start{1} = start0 /\ stop{1} = stop0 /\
    caller_fields layer0 tree0 kp0 /\ 0 <= index0 < 2^32 /\ 0 <= start0 <= stop0 /\ stop0 <= 2^32 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = wots_chain_value (interpreted_backend f) seed0
      (address_words layer0 tree0 0 kp0 index0 0 0) value0 start0 (stop0-start0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = backend_history f h
      (mkseq (functional_chain_query f seed0 layer0 tree0 kp0 index0 value0 start0) (stop0-start0)) /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+(stop0-start0)].
proof.
  conseq (caller_wots_chain (PreparationView(FixedPrefix))) (_ : true ==> true)
    (fixed_functional_chain f h c key0 seed0 layer0 tree0 kp0 index0 value0 start0 stop0) => //; smt().
qed.

(* Complete WOTS public-key computation under the fixed backend. *)





op functional_private_query key layer tree kp i = wots_private_preimage key layer tree kp i.
op functional_private_value f key layer tree kp i =
  wots_secret_value (interpreted_backend f) key layer tree kp i.
op functional_keygen_node f key seed layer tree kp i =
  wots_chain_value (interpreted_backend f) seed (address_words layer tree 0 kp i 0 0)
    (functional_private_value f key layer tree kp i) 0 7.
op functional_keygen_queries f key seed layer tree kp i =
  functional_private_query key layer tree kp i ::
    mkseq (functional_chain_query f seed layer tree kp i
      (functional_private_value f key layer tree kp i) 0) 7.
op functional_keygen_history f h key seed layer tree kp n =
  foldl (fun table i => backend_history f table (functional_keygen_queries f key seed layer tree kp i))
    h (mkseq (fun i => i) n).
op functional_keygen_compression f key seed layer tree kp =
  multi_preimage seed (address_words layer tree 1 kp 0 0 0)
    (wots_keygen_nodes (interpreted_backend f) seed key layer tree kp).

lemma functional_private_prefix key layer tree kp i :
  key ++ wots_private_preimage [] layer tree kp i = functional_private_query key layer tree kp i.
proof. by rewrite /functional_private_query /wots_private_preimage -!catA. qed.

lemma functional_private_node f key layer tree kp i : backend_width f =>
  node (f (functional_private_query key layer tree kp i)) = functional_private_value f key layer tree kp i.
proof. by move=> hf; rewrite interpreted_node 1:hf /functional_private_value /wots_secret_value /functional_private_query. qed.

lemma functional_keygen_nodes f key seed layer tree kp :
  wots_keygen_nodes (interpreted_backend f) seed key layer tree kp =
    mkseq (functional_keygen_node f key seed layer tree kp) 43.
proof. by rewrite /wots_keygen_nodes /functional_keygen_node /functional_private_value. qed.

lemma functional_keygen_value f key seed layer tree kp :
  wots_keygen_value (interpreted_backend f) seed key layer tree kp =
    hash_bytes_node (interpreted_backend f) (functional_keygen_compression f key seed layer tree kp).
proof. by rewrite /wots_keygen_value /functional_keygen_compression. qed.

lemma functional_keygen_history_zero f h key seed layer tree kp :
  functional_keygen_history f h key seed layer tree kp 0 = h.
proof. by rewrite /functional_keygen_history mkseq0. qed.

lemma functional_keygen_history_next f h key seed layer tree kp i : 0 <= i =>
  functional_keygen_history f h key seed layer tree kp (i+1) =
    backend_history f
      (remember (functional_keygen_history f h key seed layer tree kp i)
        (functional_private_query key layer tree kp i) (f (functional_private_query key layer tree kp i)))
      (mkseq (functional_chain_query f seed layer tree kp i
        (functional_private_value f key layer tree kp i) 0) 7).
proof.
  move=> hi; rewrite /functional_keygen_history mkseqS 1:hi foldl_rcons.
  by rewrite /functional_keygen_queries /backend_history /=.
qed.

lemma fixed_functional_keygen f h c key0 seed0 layer0 tree0 kp0 :
  hoare[CommonPrivateWots(FixedPrefix).leaf :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ caller_fields layer0 tree0 kp0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
      (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)
      (f (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+345].
proof.
  proc; call (fixed_hash f (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
    (functional_keygen_compression f key0 seed0 layer0 tree0 kp0) (c+344)).
  while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ caller_fields layer0 tree0 kp0 /\
    0 <= i <= 43 /\ backend_width f /\
    elements = mkseq (functional_keygen_node f key0 seed0 layer0 tree0 kp0) i /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+8*i).
  + exists* i; elim* => i0; wp.
    call (fixed_functional_chain f
      (remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i0)
        (functional_private_query key0 layer0 tree0 kp0 i0) (f (functional_private_query key0 layer0 tree0 kp0 i0)))
      (c+8*i0+1) key0 seed0 layer0 tree0 kp0 i0 (functional_private_value f key0 layer0 tree0 kp0 i0) 0 7).
    call (fixed_derive f (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 i0)
      (wots_private_preimage [] layer0 tree0 kp0 i0) (c+8*i0) key0).
    auto => />; rewrite functional_private_prefix;
      smt(functional_private_node functional_keygen_history_next mkseqS caller_u32_size).
  auto => />; rewrite functional_keygen_history_zero mkseq0 /functional_keygen_compression
    functional_keygen_nodes /wots_keygen_value;
    smt(interpreted_node functional_keygen_nodes).
qed.

lemma fixed_functional_keygen_lossless : islossless CommonPrivateWots(FixedPrefix).leaf.
proof.
  proc; call fixed_hash_ll; while true (43-i).
  + move=> z; wp; call fixed_functional_chain_lossless; call fixed_derive_ll; auto; smt().
  auto; smt().
qed.

lemma raw_functional_keygen f h c key0 seed0 layer0 tree0 kp0 :
  equiv[RawKeygen(PreparationView(FixedPrefix)).leaf ~ CommonPrivateWots(FixedPrefix).leaf :
    ={seed,layer,tree,kp,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ caller_fields layer0 tree0 kp0 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = wots_keygen_value (interpreted_backend f) seed0 key0 layer0 tree0 kp0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = remember (functional_keygen_history f h key0 seed0 layer0 tree0 kp0 43)
      (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)
      (f (functional_keygen_compression f key0 seed0 layer0 tree0 kp0)) /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+345].
proof.
  conseq (caller_keygen_leaf FixedPrefix) (_ : true ==> true)
    (fixed_functional_keygen f h c key0 seed0 layer0 tree0 kp0) => //; smt().
qed.

lemma raw_functional_keygen_lossless : islossless RawKeygen(PreparationView(FixedPrefix)).leaf.
proof.
  have hw : islossless PreparationView(FixedPrefix).wots by proc; call fixed_derive_ll; auto.
  proc; call fixed_hash_ll; while true (43-i).
  + move=> z; wp; while true (7-j).
    - move=> k; wp; call fixed_hash_ll; auto; smt().
    wp; call hw; auto; smt().
  auto; smt().
qed.

(* Native WOTS verification retains full counters, rejection, history and cost. *)





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

(* Exact four-block shuffle interpretation used by actual WOTS signing. *)




op functional_shuffle_stream f seed n =
  flatten (mkseq (fun i => bits_to_bytes (f (shuffle_block_preimage seed i))) n).
op functional_shuffle_steps seed = if seed = nseq 32 0 then 0 else 4.
op functional_shuffle_order f seed = if seed = nseq 32 0 then range 0 43
  else shuffle_order 43 (functional_shuffle_stream f seed 4).

lemma functional_shuffle_stream_zero f seed : functional_shuffle_stream f seed 0 = [].
proof. by rewrite /functional_shuffle_stream mkseq0. qed.

lemma functional_shuffle_stream_next f seed i : 0 <= i =>
  functional_shuffle_stream f seed (i+1) =
    functional_shuffle_stream f seed i ++ bits_to_bytes (f (shuffle_block_preimage seed i)).
proof. by move=> hi; rewrite /functional_shuffle_stream mkseqS 1:hi flatten_rcons. qed.

lemma functional_shuffle_stream_valid f seed n :
  all (fun b => 0 <= b < 256) (functional_shuffle_stream f seed n).
proof.
  rewrite /functional_shuffle_stream /mkseq; apply/allP => x /flatten_mapP [i [hi hx]].
  have hb := shuffle_bytes_valid (f (shuffle_block_preimage seed i)).
  move: hb => /allP; smt().
qed.

op functional_shuffle_fold stream indices order =
  foldr (fun i out => shuffle_swap out i
    (shuffle_choice (nth 0 stream (2 * max 0 (42-i)))
      (nth 0 stream (2 * max 0 (42-i)+1)) (i+1))) order indices.

lemma functional_shuffle_fold_perm stream indices order :
  all (fun b => 0 <= b < 256) stream =>
  all (fun i => 0 <= i < 43) indices => perm_eq order (range 0 43) =>
  perm_eq (functional_shuffle_fold stream indices order) (range 0 43).
proof.
  move=> hs; elim: indices => [|i indices ih] /=; first by rewrite /functional_shuffle_fold.
  move=> [hi hi'] ho.
  have hp := ih hi' ho.
  have hlen : size (functional_shuffle_fold stream indices order) = 43
    by smt(perm_eq_size size_range).
  have hlo := shuffle_nth_byte stream (2*max 0 (42-i)) hs.
  have hhi := shuffle_nth_byte stream (2*max 0 (42-i)+1) hs.
  have hj := shuffle_mulhi_range _ _ i hlo hhi _; first smt().
  have hswap := swap_put_permutation 0 (functional_shuffle_fold stream indices order) i
    (shuffle_choice (nth 0 stream (2*max 0 (42-i))) (nth 0 stream (2*max 0 (42-i)+1)) (i+1)) _ _.
  + smt().
  + move: hj; rewrite /shuffle_choice; smt().
  have he : functional_shuffle_fold stream (i::indices) order =
    shuffle_swap (functional_shuffle_fold stream indices order) i
      (shuffle_choice (nth 0 stream (2*max 0 (42-i)))
        (nth 0 stream (2*max 0 (42-i)+1)) (i+1)) by rewrite /functional_shuffle_fold.
  rewrite he /shuffle_swap.
  exact (perm_eq_trans _ _ _ hswap hp).
qed.

lemma functional_shuffle_order_perm f seed :
  perm_eq (functional_shuffle_order f seed) (range 0 43).
proof.
  rewrite /functional_shuffle_order; case (seed = nseq 32 0) => hs /=; first exact (perm_eq_refl _).
  have hi : all (fun i => 0 <= i < 43) (mkseq (fun i => i+1) 42).
  + apply/allP => i /mapP [j [hj ->]]; move: hj; rewrite mem_iota; smt().
  have hp := functional_shuffle_fold_perm (functional_shuffle_stream f seed 4)
    (mkseq (fun i => i+1) 42) (range 0 43) (functional_shuffle_stream_valid f seed 4) hi (perm_eq_refl _).
  by move: hp; rewrite /functional_shuffle_fold /shuffle_order /range /mkseq /= map_id.
qed.

lemma fixed_functional_shuffle f h c key0 seed0 :
  hoare[PairedShuffle(PreparationView(FixedPrefix)).permutation :
    seed = seed0 /\ n = 43 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_shuffle_order f seed0 /\ perm_eq res (range 0 43) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) (functional_shuffle_steps seed0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+functional_shuffle_steps seed0].
proof.
  proc; sp 1; if.
  + wp; while (
      seed = seed0 /\ n = 43 /\ seed0 <> nseq 32 0 /\ 0 <= blk <= 4 /\
      stream = functional_shuffle_stream f seed0 blk /\
      FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
      FixedBackend.history = backend_history f h (mkseq (shuffle_block_preimage seed0) blk) /\
      backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+blk).
    - exists* blk; elim* => b; wp.
      call (fixed_hash f (backend_history f h (mkseq (shuffle_block_preimage seed0) b))
        (shuffle_block_preimage seed0 b) (c+b)).
      auto; smt(functional_shuffle_stream_next backend_history_mkseqS).
    auto => />; rewrite functional_shuffle_stream_zero mkseq0 backend_history_nil
      /functional_shuffle_steps /functional_shuffle_order;
      smt(functional_shuffle_order_perm).
  auto => />; rewrite /functional_shuffle_steps /functional_shuffle_order mkseq0 backend_history_nil;
    smt(perm_eq_refl).
qed.

lemma fixed_functional_shuffle_lossless :
  islossless PairedShuffle(PreparationView(FixedPrefix)).permutation.
proof.
  proc; sp 1; if; last by auto.
  wp; while true (4-blk).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

(* Positional WOTS outputs from the actual shuffled visitation order. *)





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

(* Complete bounded native signing under the explicit fixed interpretation. *)






lemma common_functional_count_prefix f h c key0 seed0 layer0 tree0 kp0 message0 :
  hoare[CommonInputWots(PreparationView(FixedPrefix)).count :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\ backend_width f /\
    FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    exists i, 0 <= i <= signing_budget /\ FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+i /\
    wots_prefix_result f (functional_wots_query seed0 layer0 tree0 kp0 message0) res i /\
    (res = None => i = signing_budget)].
proof.
  proc; while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    0 <= i <= signing_budget /\ backend_width f /\ FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f h (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+i /\
    wots_prefix_result f (functional_wots_query seed0 layer0 tree0 kp0 message0) result i).
  + exists* i; elim* => i0; wp.
    call (fixed_hash f (backend_history f h (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) i0))
      (functional_wots_query seed0 layer0 tree0 kp0 message0 i0) (c+i0)).
    auto => />; rewrite /functional_wots_query /wots_prefix_result /wots_rejected;
      smt(backend_history_mkseqS functional_digest_width wots_accept_bits).
  auto => />; rewrite /wots_prefix_result /wots_rejected /signing_budget mkseq0 backend_history_nil; smt().
qed.

lemma common_functional_count f h c key0 seed0 layer0 tree0 kp0 message0 :
  hoare[CommonInputWots(PreparationView(FixedPrefix)).count :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\ backend_width f /\
    FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    let slot = wots_first_slot (functional_wots_digests f seed0 layer0 tree0 kp0 message0) in
    let steps = if slot = 0 then signing_budget else slot in
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+steps /\
    FixedBackend.history = backend_history f h (mkseq (functional_wots_query seed0 layer0 tree0 kp0 message0) steps) /\
    res = (if slot = 0 then None else Some (slot-1,
      f (functional_wots_query seed0 layer0 tree0 kp0 message0 (slot-1))))].
proof.
  conseq (common_functional_count_prefix f h c key0 seed0 layer0 tree0 kp0 message0) => //.
  rewrite /functional_wots_digests; smt(wots_prefix_finish).
qed.

lemma common_functional_count_lossless : islossless CommonInputWots(PreparationView(FixedPrefix)).count.
proof.
  proc; while true (signing_budget-i).
  + move=> z; wp; call fixed_hash_ll; auto; smt().
  auto; smt().
qed.

op functional_sign_slot f seed layer tree kp message =
  wots_first_slot (functional_wots_digests f seed layer tree kp message).
op functional_sign_search_steps f seed layer tree kp message =
  let slot = functional_sign_slot f seed layer tree kp message in if slot = 0 then signing_budget else slot.
op functional_sign_search_history f h seed layer tree kp message =
  backend_history f h (mkseq (functional_wots_query seed layer tree kp message)
    (functional_sign_search_steps f seed layer tree kp message)).
op functional_sign_digest f seed layer tree kp message =
  f (functional_wots_query seed layer tree kp message (functional_sign_slot f seed layer tree kp message - 1)).
op functional_sign_result f key seed layer tree kp message =
  let slot = functional_sign_slot f seed layer tree kp message in
  if slot = 0 then None else Some
    (wots_sign_values (interpreted_backend f) seed key layer tree kp
      (bits_to_bytes (functional_sign_digest f seed layer tree kp message)), slot-1).
op functional_sign_history f h key seed layer tree kp message shuffle =
  let searched = functional_sign_search_history f h seed layer tree kp message in
  if functional_sign_slot f seed layer tree kp message = 0 then searched else
    functional_fill_history f (functional_fill_initial_history f searched shuffle) key seed layer tree kp
      (functional_sign_digest f seed layer tree kp message) (functional_shuffle_order f shuffle) 43.
op functional_sign_cost f seed layer tree kp message shuffle =
  functional_sign_search_steps f seed layer tree kp message +
    (if functional_sign_slot f seed layer tree kp message = 0 then 0 else
      functional_shuffle_steps shuffle + functional_fill_cost (functional_sign_digest f seed layer tree kp message)
        (functional_shuffle_order f shuffle) 43).

lemma fixed_functional_sign f h c key0 seed0 layer0 tree0 kp0 message0 shuffle0 :
  hoare[CommonPrivateWots(FixedPrefix).sign :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\ shuffle = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn = f /\ FixedBackend.history = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_sign_result f key0 seed0 layer0 tree0 kp0 message0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_sign_history f h key0 seed0 layer0 tree0 kp0 message0 shuffle0 /\
    FixedBackend.calls = c+functional_sign_cost f seed0 layer0 tree0 kp0 message0 shuffle0].
proof.
  proc; seq 1 : (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ kp = kp0 /\ message = message0 /\ shuffle = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ backend_width f /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.history = functional_sign_search_history f h seed0 layer0 tree0 kp0 message0 /\
    FixedBackend.calls = c+functional_sign_search_steps f seed0 layer0 tree0 kp0 message0 /\
    accepted = (if functional_sign_slot f seed0 layer0 tree0 kp0 message0 = 0 then None else
      Some (functional_sign_slot f seed0 layer0 tree0 kp0 message0 - 1,
        functional_sign_digest f seed0 layer0 tree0 kp0 message0))).
  + call (common_functional_count f h c key0 seed0 layer0 tree0 kp0 message0).
    by auto; rewrite /functional_sign_slot /functional_sign_search_steps /functional_sign_search_history /functional_sign_digest.
  sp 1; if.
  + wp; call (fixed_functional_fill f (functional_sign_search_history f h seed0 layer0 tree0 kp0 message0)
      (c+functional_sign_search_steps f seed0 layer0 tree0 kp0 message0) key0 seed0 layer0 tree0 kp0
      (functional_sign_digest f seed0 layer0 tree0 kp0 message0) shuffle0).
    auto => />; rewrite /functional_sign_result /functional_sign_history /functional_sign_cost;
      smt(functional_digest_width).
  auto => />; rewrite /functional_sign_result /functional_sign_history /functional_sign_cost; smt().
qed.

lemma fixed_functional_sign_lossless : islossless CommonPrivateWots(FixedPrefix).sign.
proof.
  proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call common_functional_count_lossless; auto.
  sp 1; if; last by auto.
  wp; call fixed_functional_fill_lossless; auto.
qed.

lemma raw_functional_sign f h c key0 seed0 layer0 tree0 kp0 message0 shuffle0 :
  equiv[RawWots(PreparationView(FixedPrefix)).sign ~ CommonPrivateWots(FixedPrefix).sign :
    ={seed,layer,tree,kp,message,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ message{1} = message0 /\ shuffle{1} = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\ res{1} = functional_sign_result f key0 seed0 layer0 tree0 kp0 message0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_sign_history f h key0 seed0 layer0 tree0 kp0 message0 shuffle0 /\
    FixedBackend.calls{1} = c+functional_sign_cost f seed0 layer0 tree0 kp0 message0 shuffle0].
proof.
  conseq (caller_wots_sign FixedPrefix) (_ : true ==> true)
    (fixed_functional_sign f h c key0 seed0 layer0 tree0 kp0 message0 shuffle0) => //; smt().
qed.

lemma raw_functional_sign_lossless : islossless RawWots(PreparationView(FixedPrefix)).sign.
proof.
  have hw : islossless PreparationView(FixedPrefix).wots by proc; call fixed_derive_ll; auto.
  exact (raw_sign_lossless (PreparationView(FixedPrefix)) fixed_hash_ll hw).
qed.

lemma factored_functional_sign f h c key0 seed0 layer0 tree0 kp0 message0 shuffle0 :
  equiv[RawWotsFill(PreparationView(FixedPrefix)).sign ~ CommonPrivateWots(FixedPrefix).sign :
    ={seed,layer,tree,kp,message,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ kp{1} = kp0 /\ message{1} = message0 /\ shuffle{1} = shuffle0 /\
    caller_fields layer0 tree0 kp0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\ res{1} = functional_sign_result f key0 seed0 layer0 tree0 kp0 message0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.history{1} = functional_sign_history f h key0 seed0 layer0 tree0 kp0 message0 shuffle0 /\
    FixedBackend.calls{1} = c+functional_sign_cost f seed0 layer0 tree0 kp0 message0 shuffle0].
proof.
  conseq (caller_wots_sign_factored FixedPrefix) (_ : true ==> true)
    (fixed_functional_sign f h c key0 seed0 layer0 tree0 kp0 message0 shuffle0) => //; smt().
qed.
