require import AllCore List IntDiv StdOrder C10Representation C10RawOracle C10RawGrind RawKeygen C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue FMap KeygenPrefixes RawMerkle C10TreeCallerBridge C10FunctionalWots RawFors.

op fors_secret_value (hash_fn : (int list -> int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : (int list) =
  (hash_bytes_node hash_fn (fors_private_preimage secret ht tree leaf)).

op fors_leaf_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (tree : int) (leaf : int) (value : (int list)) : (int list) =
  (hash_bytes_node hash_fn (th_preimage seed (address_words 0 ht 3 tree 0 0 leaf) (pad_node value))).

op tree_pair_value (hash_fn : (int list -> int list)) (seed : (int list)) (address : (int list)) (left : (int list)) (right : (int list)) : (int list) =
  (hash_bytes_node hash_fn (pair_preimage seed address (pad_node left) (pad_node right))).

op tree_path_step (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (auth : ((int list) list)) (index0 : int) (current : (int list)) (height : int) : (int list) =
  (tree_pair_value hash_fn seed (address_words layer tree kind kp 0 ((height + 1)) ((index0 %/ (2 ^ height)) %/ 2)) (if ((index0 %/ (2 ^ height)) %% 2) = 0 then current else (nth (nseq 16 0) auth height)) (if ((index0 %/ (2 ^ height)) %% 2) = 0 then (nth (nseq 16 0) auth height) else current)).

op tree_path_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (value : (int list)) (index0 : int) (auth : ((int list) list)) (steps : int) : (int list) =
  (foldr (fun i current => (tree_path_step hash_fn seed layer tree kind kp auth index0 current i)) value (rev (mkseq (fun i => i) steps))).

op fors_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (tree : int) (leaf : int) (value : (int list)) (auth : ((int list) list)) : (int list) =
  (tree_path_value hash_fn seed 0 ht 3 tree (fors_leaf_value hash_fn seed ht tree leaf value) leaf auth 11).

op merkle_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (value : (int list)) (index0 : int) (auth : ((int list) list)) : (int list) =
  (tree_path_value hash_fn seed layer tree 3 0 value index0 auth 9).

(* Common functional FORS/Merkle values; no sampled-oracle interpretation. *)

import IntOrder.



lemma functional_path_fold f seed layer tree kind kp value index auth steps :
  tree_path_value f seed layer tree kind kp value index auth steps =
    foldl (fun current i => tree_path_step f seed layer tree kind kp auth index current i)
      value (mkseq (fun i => i) steps).
proof. by rewrite /tree_path_value -foldl_rev revK. qed.

lemma functional_path_zero f seed layer tree kind kp value index auth :
  tree_path_value f seed layer tree kind kp value index auth 0 = value.
proof. by rewrite functional_path_fold mkseq0. qed.

lemma functional_path_next f seed layer tree kind kp value index auth n : 0 <= n =>
  tree_path_value f seed layer tree kind kp value index auth (n+1) =
    tree_path_step f seed layer tree kind kp auth index
      (tree_path_value f seed layer tree kind kp value index auth n) n.
proof. by move=> hn; rewrite !functional_path_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_path_parent index h : 0 <= h =>
  (index %/ 2^h) %/ 2 = index %/ 2^(h+1).
proof.
  move=> hh; have hp : 0 <= 2^h by smt(expr_gt0).
  have he : 2^(h+1) = 2^h * 2 by rewrite exprS 1:hh; ring.
  have hd := divz_mul index (2^h) 2 hp.
  by smt().
qed.

lemma functional_fors_recovery_value f seed ht tree target secret auth :
  fors_recover_value f seed ht tree target secret auth =
    tree_path_value f seed 0 ht 3 tree (fors_leaf_value f seed ht tree target secret) target auth 11.
proof. by rewrite /fors_recover_value. qed.

lemma functional_merkle_recovery_value f seed layer tree leaf index auth :
  merkle_recover_value f seed layer tree leaf index auth =
    tree_path_value f seed layer tree 2 0 leaf index auth 9.
proof. by rewrite /merkle_recover_value. qed.

op functional_tree_query f seed layer tree kind kp value index auth h =
  let current = tree_path_value (interpreted_backend f) seed layer tree kind kp value index auth h in
  let sibling = nth (nseq 16 0) auth h in
  let idx = index %/ 2^h in
  pair_preimage seed (address_words layer tree kind kp 0 (h+1) (idx %/ 2))
    (pad_node (if idx %% 2 = 0 then current else sibling))
    (pad_node (if idx %% 2 = 0 then sibling else current)).

lemma functional_tree_step f seed layer tree kind kp value index auth h :
  backend_width f => 0 <= h =>
  node (f (functional_tree_query f seed layer tree kind kp value index auth h)) =
    tree_path_value (interpreted_backend f) seed layer tree kind kp value index auth (h+1).
proof.
  move=> hf hh; rewrite functional_path_next 1:hh /tree_path_step /tree_pair_value.
  by rewrite /functional_tree_query interpreted_node 1:hf.
qed.

(* The actual nine-level recovery retains arbitrary consistent prehistory. *)





lemma fixed_functional_merkle f hist c key0 seed0 layer0 tree0 leaf0 index0 auth0 :
  hoare[CommonInputMerkle(FixedPrefix).recover :
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ leaf = leaf0 /\
    index = index0 /\ auth = auth0 /\
    FixedBackend.fn = f /\ FixedBackend.history = hist /\ backend_consistent hist f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = merkle_recover_value (interpreted_backend f) seed0 layer0 tree0 leaf0 index0 auth0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f hist
      (mkseq (functional_tree_query f seed0 layer0 tree0 2 0 leaf0 index0 auth0) 9) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+9].
proof.
  proc; while (
    seed = seed0 /\ layer = layer0 /\ tree = tree0 /\ auth = auth0 /\
    0 <= h <= 9 /\ idx = index0 %/ 2^h /\ backend_width f /\
    current = tree_path_value (interpreted_backend f) seed0 layer0 tree0 2 0 leaf0 index0 auth0 h /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = backend_history f hist
      (mkseq (functional_tree_query f seed0 layer0 tree0 2 0 leaf0 index0 auth0) h) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+h).
  + exists* h; elim* => h0; wp.
    call (fixed_hash f
      (backend_history f hist (mkseq (functional_tree_query f seed0 layer0 tree0 2 0 leaf0 index0 auth0) h0))
      (functional_tree_query f seed0 layer0 tree0 2 0 leaf0 index0 auth0 h0) (c+h0)).
    auto => />; rewrite /functional_tree_query;
      smt(functional_tree_step functional_path_parent backend_history_mkseqS).
  auto => />; rewrite functional_merkle_recovery_value functional_path_zero expr0 divz1 mkseq0 backend_history_nil; smt().
qed.

lemma raw_functional_merkle_lossless :
  islossless RawMerkle(PreparationView(FixedPrefix)).recover.
proof. exact (merkle_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma raw_functional_merkle f hist c key0 seed0 layer0 tree0 leaf0 index0 auth0 :
  equiv[RawMerkle(PreparationView(FixedPrefix)).recover ~ CommonInputMerkle(FixedPrefix).recover :
    ={seed,layer,tree,leaf,index,auth,glob FixedPrefix} /\
    seed{1} = seed0 /\ layer{1} = layer0 /\ tree{1} = tree0 /\ leaf{1} = leaf0 /\
    index{1} = index0 /\ auth{1} = auth0 /\ tree_fields layer0 tree0 /\ 0 <= index0 < 2^32 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = hist /\ backend_consistent hist f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = merkle_recover_value (interpreted_backend f) seed0 layer0 tree0 leaf0 index0 auth0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = backend_history f hist
      (mkseq (functional_tree_query f seed0 layer0 tree0 2 0 leaf0 index0 auth0) 9) /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+9].
proof.
  conseq (caller_merkle_recover FixedPrefix) (_ : true ==> true)
    (fixed_functional_merkle f hist c key0 seed0 layer0 tree0 leaf0 index0 auth0) => //; smt().
qed.

(* Actual FORS recovery: one leaf query followed by eleven ordered pair queries. *)





op functional_fors_leaf_query seed ht tree target secret =
  th_preimage seed (address_words 0 ht 3 tree 0 0 target) (pad_node secret).

lemma functional_fors_leaf f seed ht tree target secret : backend_width f =>
  node (f (functional_fors_leaf_query seed ht tree target secret)) =
    fors_leaf_value (interpreted_backend f) seed ht tree target secret.
proof. by move=> hf; rewrite /functional_fors_leaf_query /fors_leaf_value interpreted_node 1:hf. qed.

lemma functional_fors_private_prefix key ht tree target :
  key ++ fors_private_preimage [] ht tree target = fors_private_preimage key ht tree target.
proof. by rewrite /fors_private_preimage -!catA. qed.

lemma functional_fors_private f key ht tree target : backend_width f =>
  node (f (fors_private_preimage key ht tree target)) =
    fors_secret_value (interpreted_backend f) key ht tree target.
proof. by move=> hf; rewrite /fors_secret_value interpreted_node 1:hf. qed.

lemma fixed_functional_fors_private f hist c key0 ht0 tree0 target0 :
  hoare[FixedPrefix.derive :
    tail = fors_private_preimage [] ht0 tree0 target0 /\
    FixedBackend.fn = f /\ FixedBackend.history = hist /\ backend_consistent hist f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    node res = fors_secret_value (interpreted_backend f) key0 ht0 tree0 target0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = remember hist (fors_private_preimage key0 ht0 tree0 target0)
      (f (fors_private_preimage key0 ht0 tree0 target0)) /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+1].
proof.
  conseq (fixed_derive f hist (fors_private_preimage [] ht0 tree0 target0) c key0) => //.
  move=> &m; rewrite functional_fors_private_prefix; smt(functional_fors_private).
qed.

op functional_fors_recovery_history f hist seed ht tree target secret auth n =
  backend_history f
    (remember hist (functional_fors_leaf_query seed ht tree target secret)
      (f (functional_fors_leaf_query seed ht tree target secret)))
    (mkseq (functional_tree_query f seed 0 ht 3 tree
      (fors_leaf_value (interpreted_backend f) seed ht tree target secret) target auth) n).

lemma functional_fors_recovery_history_order f hist seed ht tree target secret auth n :
  functional_fors_recovery_history f hist seed ht tree target secret auth n =
    backend_history f hist (functional_fors_leaf_query seed ht tree target secret ::
      mkseq (functional_tree_query f seed 0 ht 3 tree
        (fors_leaf_value (interpreted_backend f) seed ht tree target secret) target auth) n).
proof. by rewrite /functional_fors_recovery_history /backend_history. qed.

lemma fixed_functional_fors f hist c key0 seed0 ht0 tree0 target0 secret0 auth0 :
  hoare[CommonInputFors(FixedPrefix).recover :
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ target = target0 /\ secret = secret0 /\ auth = auth0 /\
    FixedBackend.fn = f /\ FixedBackend.history = hist /\ backend_consistent hist f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = fors_recover_value (interpreted_backend f) seed0 ht0 tree0 target0 secret0 auth0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = functional_fors_recovery_history f hist seed0 ht0 tree0 target0 secret0 auth0 11 /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+12].
proof.
  proc; while (
    seed = seed0 /\ ht = ht0 /\ tree = tree0 /\ auth = auth0 /\
    0 <= h <= 11 /\ idx = target0 %/ 2^h /\ backend_width f /\
    current = tree_path_value (interpreted_backend f) seed0 0 ht0 3 tree0
      (fors_leaf_value (interpreted_backend f) seed0 ht0 tree0 target0 secret0) target0 auth0 h /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\
    FixedBackend.history = functional_fors_recovery_history f hist seed0 ht0 tree0 target0 secret0 auth0 h /\
    backend_consistent FixedBackend.history f /\ FixedBackend.calls = c+1+h).
  + exists* h; elim* => h0; wp.
    call (fixed_hash f
      (functional_fors_recovery_history f hist seed0 ht0 tree0 target0 secret0 auth0 h0)
      (functional_tree_query f seed0 0 ht0 3 tree0
        (fors_leaf_value (interpreted_backend f) seed0 ht0 tree0 target0 secret0) target0 auth0 h0)
      (c+1+h0)).
    auto => />; rewrite /functional_tree_query /functional_fors_recovery_history;
      smt(functional_tree_step functional_path_parent backend_history_mkseqS).
  wp; call (fixed_hash f hist (functional_fors_leaf_query seed0 ht0 tree0 target0 secret0) c).
  auto => />; rewrite functional_fors_recovery_value /functional_fors_recovery_history functional_path_zero
    expr0 divz1 mkseq0 backend_history_nil /functional_fors_leaf_query;
    smt(functional_fors_leaf).
qed.

lemma raw_functional_fors_lossless :
  islossless RawFors(PreparationView(FixedPrefix)).recover.
proof. exact (fors_recover_lossless (PreparationView(FixedPrefix)) fixed_hash_ll). qed.

lemma raw_functional_fors f hist c key0 seed0 ht0 tree0 target0 secret0 auth0 :
  equiv[RawFors(PreparationView(FixedPrefix)).recover ~ CommonInputFors(FixedPrefix).recover :
    ={seed,ht,tree,target,secret,auth,glob FixedPrefix} /\
    seed{1} = seed0 /\ ht{1} = ht0 /\ tree{1} = tree0 /\ target{1} = target0 /\
    secret{1} = secret0 /\ auth{1} = auth0 /\ fors_fields ht0 tree0 /\ 0 <= target0 < 2^32 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = hist /\ backend_consistent hist f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = fors_recover_value (interpreted_backend f) seed0 ht0 tree0 target0 secret0 auth0 /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\
    FixedBackend.history{1} = functional_fors_recovery_history f hist seed0 ht0 tree0 target0 secret0 auth0 11 /\
    backend_consistent FixedBackend.history{1} f /\ FixedBackend.calls{1} = c+12].
proof.
  conseq (caller_fors_recover FixedPrefix) (_ : true ==> true)
    (fixed_functional_fors f hist c key0 seed0 ht0 tree0 target0 secret0 auth0) => //; smt().
qed.
