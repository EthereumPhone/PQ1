(* Actual FORS recovery: one leaf query followed by eleven ordered pair queries. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen RawFors KeygenPrefixes C10Representation.
require import C10TreeCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalTreeValue.

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
