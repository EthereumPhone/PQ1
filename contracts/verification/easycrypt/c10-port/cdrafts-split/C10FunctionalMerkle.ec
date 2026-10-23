(* The actual nine-level recovery retains arbitrary consistent prehistory. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle KeygenPrefixes RawMerkle C10Representation.
require import C10TreeCallerBridge C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue C10FunctionalTreeValue.

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
