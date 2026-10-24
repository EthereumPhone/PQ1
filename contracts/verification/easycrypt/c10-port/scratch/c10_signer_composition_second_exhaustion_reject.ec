require import AllCore List IntDiv C10Bytes C10RawOracle C10RawGrind C10Representation RawSigner RawLayer RawForest C10FixedBackend C10FixedCallerBridge C10FunctionalWotsValue C10FunctionalLayerSign C10FunctionalForestRecover C10FunctionalVerifierValue C10CallerInputBridge C10OuterCallerBridge C10DigestCallers FMap C10FunctionalForestSign C10FunctionalBuildHistory C10FunctionalMerkleBuildHistory KeygenPrefixes SignerCoordinates RoleGrind RawSignature C10Counter C10SearchAcceptance C10FunctionalFors C10FunctionalSearch C10FunctionalSignerHeader.

(* Complete signer values, with zero selectors retained as exhaustion.
   Pure calls here specify values, not a count of executed hash queries. *)






op paired_layer_result fn key seed layer tree leaf message =
  let slot = layer_sign_slot fn seed layer tree leaf message in
  let sig = layer_sign_values fn seed key layer tree leaf message (slot-1) in
  if slot = 0 then None else Some
    (sig,layer_recover_value fn seed layer tree leaf message sig.`1 sig.`2 sig.`3).
op paired_finish_result fn key seed (randomizer : raw_input) d =
  let ht = ht_field d in
  let forest = forest_sign_value fn seed key ht (digest_fors_indices d) in
  let first = paired_layer_result fn key seed 0 (ht %/ 512) (ht %% 512) forest.`3 in
  if first = None then None else
  let second = first in
  if second = None then None else Some (randomizer,forest.`1,forest.`2,[(oget first).`1;(oget second).`1]).

op functional_signer_forest f key seed d =
  forest_sign_value (interpreted_backend f) seed key (hypertree_index d) (functional_forest_indices d).
op functional_signer_layer0 f key seed d =
  functional_layer_result f key seed 0 (hypertree_index d %/ 512) (hypertree_index d %% 512)
    (functional_signer_forest f key seed d).`3.
op functional_signer_layer1 f key seed d =
  functional_layer_result f key seed 1 (hypertree_index d %/ 512 %/ 512) (hypertree_index d %/ 512 %% 512)
    (oget (functional_signer_layer0 f key seed d)).`2.
op functional_signer_current f key seed d i =
  if i = 0 then (functional_signer_forest f key seed d).`3 else
  if functional_signer_layer0 f key seed d = None then (functional_signer_forest f key seed d).`3 else
  if i = 1 \/ functional_signer_layer1 f key seed d = None then (oget (functional_signer_layer0 f key seed d)).`2
  else (oget (functional_signer_layer1 f key seed d)).`2.
op functional_signer_layers f key seed d i =
  if i = 0 \/ functional_signer_layer0 f key seed d = None then [] else
  if i = 1 \/ functional_signer_layer1 f key seed d = None then [(oget (functional_signer_layer0 f key seed d)).`1]
  else [(oget (functional_signer_layer0 f key seed d)).`1;(oget (functional_signer_layer1 f key seed d)).`1].
op functional_signer_ok f key seed d i =
  i = 0 \/ (functional_signer_layer0 f key seed d <> None /\
    (i = 1 \/ functional_signer_layer1 f key seed d <> None)).
op functional_signer_iterations f key seed d =
  if functional_signer_layer0 f key seed d = None then 1 else 2.
op functional_signer_layer f key seed d i =
  functional_layer_result f key seed i
    (functional_verifier_index (hypertree_index d) i %/ 512)
    (functional_verifier_index (hypertree_index d) i %% 512)
    (functional_signer_current f key seed d i).

lemma functional_layer_result_shared f key seed layer tree leaf message :
  functional_layer_result f key seed layer tree leaf message =
    paired_layer_result (interpreted_backend f) key seed layer tree leaf message.
proof.
  by rewrite /functional_layer_result /functional_layer_signature /paired_layer_result
    functional_layer_slot_shared.
qed.

lemma functional_signer_forest_shared f key seed d : size d = 256 =>
  functional_signer_forest f key seed d =
    forest_sign_value (interpreted_backend f) seed key (ht_field (bits_to_bytes d))
      (digest_fors_indices (bits_to_bytes d)).
proof.
  move=> hd; rewrite /functional_signer_forest (functional_digest_indices d hd) (digest_ht_field d hd); trivial.
qed.

lemma functional_signer_layer_step f key seed d i :
  0 <= i < 2 => functional_signer_ok f key seed d i =>
  let signed = functional_signer_layer f key seed d i in
  functional_signer_ok f key seed d (i+1) = (signed <> None) /\
  functional_signer_current f key seed d (i+1) =
    (if signed = None then functional_signer_current f key seed d i else (oget signed).`2) /\
  functional_signer_layers f key seed d (i+1) =
    (if signed = None then functional_signer_layers f key seed d i else
      rcons (functional_signer_layers f key seed d i) (oget signed).`1).
proof.
  move=> hi hok; have hc : i = 0 \/ i = 1 by smt().
  case: hc => he; subst i;
    move: hok; rewrite /functional_signer_layer /functional_verifier_index
      /functional_signer_current /functional_signer_layers /functional_signer_ok
      /functional_signer_layer0 /functional_signer_layer1 /=; smt().
qed.

lemma functional_signer_finish_value f key seed randomizer d i :
  size d = 256 => 0 <= i <= 2 =>
  (i = 2 \/ !functional_signer_ok f key seed d i) =>
  (i = 2 => functional_signer_layer0 f key seed d <> None) =>
  i = functional_signer_iterations f key seed d /\
  (if functional_signer_ok f key seed d i then Some
    (randomizer,(functional_signer_forest f key seed d).`1,(functional_signer_forest f key seed d).`2,
      functional_signer_layers f key seed d i) else None) =
    paired_finish_result (interpreted_backend f) key seed randomizer (bits_to_bytes d).
proof.
  move=> hd hi he hp.
  rewrite /paired_finish_result /= -(functional_signer_forest_shared f key seed d hd)
    -(digest_ht_field d hd) -!functional_layer_result_shared.
  move: he hp; rewrite /functional_signer_iterations /functional_signer_layers /functional_signer_ok
    /functional_signer_layer0 /functional_signer_layer1; smt().
qed.

lemma functional_signer_next_reachable f key seed d i :
  functional_signer_ok f key seed d i => i+1 = 2 =>
    functional_signer_layer0 f key seed d <> None.
proof. rewrite /functional_signer_ok; smt(). qed.

(* Exact finite state and cost composition for signer layers. The trace
   contains only the executed prefix and preserves every intermediate map. *)







op functional_signer_step_cost f key seed d shuffle i =
  functional_layer_sign_cost f key seed i
    (functional_verifier_index (hypertree_index d) i %/ 512)
    (functional_verifier_index (hypertree_index d) i %% 512)
    (functional_signer_current f key seed d i) shuffle.
op functional_signer_layers_cost f key seed d shuffle n =
  if n = 0 then 0 else functional_signer_step_cost f key seed d shuffle 0 +
    (if n = 1 then 0 else functional_signer_step_cost f key seed d shuffle 1).
op functional_signer_step_state f initial final key seed d shuffle i =
  let idx = functional_verifier_index (hypertree_index d) i in
  exists built, functional_history_exact f initial built
    (functional_tree_queried (functional_merkle_build_queries f key seed i (idx %/ 512)) 9) /\
    final = functional_layer_sign_history f built key seed i (idx %/ 512) (idx %% 512)
      (functional_signer_current f key seed d i) shuffle.
op functional_signer_layers_state f initial final key seed d shuffle n =
  exists (histories : int -> (raw_input,digest) fmap),
    histories 0 = initial /\ histories n = final /\
    forall i, 0 <= i < n =>
      functional_signer_step_state f (histories i) (histories (i+1)) key seed d shuffle i.
op functional_finish_cost f key seed d shuffle =
  functional_forest_initial_cost f shuffle + 80017 +
    functional_signer_layers_cost f key seed d shuffle (functional_signer_iterations f key seed d).
op functional_finish_state f initial final key seed d shuffle =
  exists forest, functional_forest_sign_state f initial forest key seed (hypertree_index d) d shuffle /\
    functional_signer_layers_state f forest final key seed d shuffle (functional_signer_iterations f key seed d).

lemma functional_signer_layers_state_zero f h key seed d shuffle :
  functional_signer_layers_state f h h key seed d shuffle 0.
proof.
  rewrite /functional_signer_layers_state; exists (fun i => h); smt().
qed.

lemma functional_signer_layers_state_step f h mid final key seed d shuffle n : 0 <= n =>
  functional_signer_layers_state f h mid key seed d shuffle n =>
  functional_signer_step_state f mid final key seed d shuffle n =>
  functional_signer_layers_state f h final key seed d shuffle (n+1).
proof.
  move=> hn; rewrite /functional_signer_layers_state => [[histories [hzero [hend hsteps]]] hnew].
  exists (fun i => if i = n+1 then final else histories i); split; first smt().
  split; first smt().
  move=> i hi; case (i = n) => he; smt().
qed.

lemma functional_signer_layers_cost_step f key seed d shuffle n : 0 <= n < 2 =>
  functional_signer_layers_cost f key seed d shuffle (n+1) =
    functional_signer_layers_cost f key seed d shuffle n + functional_signer_step_cost f key seed d shuffle n.
proof.
  move=> hn; have hc : n = 0 \/ n = 1 by smt().
  case: hc => ->; by rewrite /functional_signer_layers_cost /=.
qed.

lemma functional_signer_initial f h key seed d shuffle :
  functional_signer_current f key seed d 0 = (functional_signer_forest f key seed d).`3 /\
  functional_signer_layers f key seed d 0 = [] /\ functional_signer_ok f key seed d 0 /\
  functional_verifier_index (hypertree_index d) 0 = hypertree_index d /\
  functional_signer_layers_cost f key seed d shuffle 0 = 0 /\
  functional_signer_layers_state f h h key seed d shuffle 0.
proof.
  by rewrite /functional_signer_current /functional_signer_layers /functional_signer_ok
    /functional_verifier_index /functional_signer_layers_cost /= functional_signer_layers_state_zero.
qed.

lemma functional_signer_complete f h forest final key seed randomizer d shuffle i :
  size d = 256 => 0 <= i <= 2 =>
  (i = 2 \/ !functional_signer_ok f key seed d i) =>
  (i = 2 => functional_signer_layer0 f key seed d <> None) =>
  functional_forest_sign_state f h forest key seed (hypertree_index d) d shuffle =>
  functional_signer_layers_state f forest final key seed d shuffle i =>
  (if functional_signer_ok f key seed d i then Some
    (randomizer,(functional_signer_forest f key seed d).`1,(functional_signer_forest f key seed d).`2,
      functional_signer_layers f key seed d i) else None) =
    paired_finish_result (C10FunctionalWotsValue.interpreted_backend f) key seed randomizer (C10Bytes.bits_to_bytes d) /\
  functional_forest_initial_cost f shuffle + 80017 + functional_signer_layers_cost f key seed d shuffle i =
    functional_finish_cost f key seed d shuffle /\
  functional_finish_state f h final key seed d shuffle.
proof.
  move=> hd hi he hp hf hs.
  have [hi' hr] := functional_signer_finish_value f key seed randomizer d i hd hi he hp.
  rewrite hr /functional_finish_cost /functional_finish_state hi' /=; smt().
qed.

(* Actual complete forest/two-layer caller, retaining state on exhaustion. *)








lemma fixed_functional_signer_layer f h c key0 seed0 d0 shuffle0 i0 :
  hoare[CommonInputLayer(FixedPrefix).sign :
    0 <= i0 < 2 /\ size d0 = 256 /\ seed = seed0 /\ layer = i0 /\
    tree = functional_verifier_index (hypertree_index d0) i0 %/ 512 /\
    leaf = functional_verifier_index (hypertree_index d0) i0 %% 512 /\
    message = functional_signer_current f key0 seed0 d0 i0 /\ shuffle = shuffle0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = functional_signer_layer f key0 seed0 d0 i0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_signer_step_cost f key0 seed0 d0 shuffle0 i0 /\
    functional_signer_step_state f h FixedBackend.history key0 seed0 d0 shuffle0 i0].
proof.
  conseq (fixed_functional_layer_sign f h c key0 seed0 i0
    (functional_verifier_index (hypertree_index d0) i0 %/ 512)
    (functional_verifier_index (hypertree_index d0) i0 %% 512)
    (functional_signer_current f key0 seed0 d0 i0) shuffle0) => //.
  + smt(functional_verifier_coordinates).
  rewrite /functional_signer_layer /functional_signer_step_cost /functional_signer_step_state; smt().
qed.

lemma fixed_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 : size d0 = 256 =>
  hoare[CommonInputSigner(FixedPrefix).finish :
    seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    FixedBackend.fn = f /\ FixedBackend.history = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls = c /\ FixedPrefix.key = key0 ==>
    res = paired_finish_result (interpreted_backend f) key0 seed0 randomizer0 (bits_to_bytes d0) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c + functional_finish_cost f key0 seed0 d0 shuffle0 /\
    functional_finish_state f h FixedBackend.history key0 seed0 d0 shuffle0].
proof.
  move=> hd; proc.
  seq 2 : (seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    ht = hypertree_index d0 /\ forest = functional_signer_forest f key0 seed0 d0 /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017 /\
    functional_forest_sign_state f h FixedBackend.history key0 seed0 (hypertree_index d0) d0 shuffle0).
  + call (fixed_functional_forest_sign f h c key0 seed0 (hypertree_index d0) d0 shuffle0).
    auto; rewrite /functional_signer_forest; smt(hypertree_index_range caller_u32_size).
  exists* FixedBackend.history; elim* => forest0.
  wp; while (seed = seed0 /\ randomizer = randomizer0 /\ digest = d0 /\ shuffle = shuffle0 /\
    ht = hypertree_index d0 /\ forest = functional_signer_forest f key0 seed0 d0 /\
    0 <= layer <= 2 /\ idx_tree = functional_verifier_index (hypertree_index d0) layer /\
    current = functional_signer_current f key0 seed0 d0 layer /\
    layers = functional_signer_layers f key0 seed0 d0 layer /\
    ok = functional_signer_ok f key0 seed0 d0 layer /\
    (layer = 2 => functional_signer_layer0 f key0 seed0 d0 <> None) /\
    FixedBackend.fn = f /\ FixedPrefix.key = key0 /\ backend_width f /\
    backend_consistent FixedBackend.history f /\
    FixedBackend.calls = c+functional_forest_initial_cost f shuffle0+80017+
      functional_signer_layers_cost f key0 seed0 d0 shuffle0 layer /\
    functional_forest_sign_state f h forest0 key0 seed0 (hypertree_index d0) d0 shuffle0 /\
    functional_signer_layers_state f forest0 FixedBackend.history key0 seed0 d0 shuffle0 layer).
  + exists* layer, FixedBackend.history; elim* => i0 history0; wp.
    call (fixed_functional_signer_layer f history0
      (c+functional_forest_initial_cost f shuffle0+80017+functional_signer_layers_cost f key0 seed0 d0 shuffle0 i0)
      key0 seed0 d0 shuffle0 i0).
    auto; smt(functional_signer_layer_step functional_verifier_index_step
      functional_signer_layers_cost_step functional_signer_layers_state_step functional_signer_next_reachable).
  auto; move=> &m hpre; split.
  + have hi := functional_signer_initial f forest0 key0 seed0 d0 shuffle0; smt().
  move=> calls history current0 idx0 layer0 layers0 ok0 hexit hpost.
  have hb : 0 <= layer0 <= 2 by smt().
  have he : layer0 = 2 \/ !functional_signer_ok f key0 seed0 d0 layer0 by smt().
  have hp : layer0 = 2 => functional_signer_layer0 f key0 seed0 d0 <> None by smt().
  have hf : functional_forest_sign_state f h forest0 key0 seed0 (hypertree_index d0) d0 shuffle0 by smt().
  have hs : functional_signer_layers_state f forest0 history key0 seed0 d0 shuffle0 layer0 by smt().
  have hc := functional_signer_complete f h forest0 history key0 seed0 randomizer0 d0 shuffle0 layer0
    hd hb he hp hf hs.
  smt().
qed.

lemma raw_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 :
  equiv[RawSigner(FixedPrefix).finish ~ CommonInputSigner(FixedPrefix).finish :
    size d0 = 256 /\ ={seed,randomizer,digest,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ randomizer{1} = randomizer0 /\ digest{1} = d0 /\ shuffle{1} = shuffle0 /\
    FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\ backend_consistent h f /\
    backend_width f /\ FixedBackend.calls{1} = c /\ FixedPrefix.key{1} = key0 ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_finish_result (interpreted_backend f) key0 seed0 randomizer0 (bits_to_bytes d0) /\
    FixedBackend.fn{1} = f /\ FixedPrefix.key{1} = key0 /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c + functional_finish_cost f key0 seed0 d0 shuffle0 /\
    functional_finish_state f h FixedBackend.history{1} key0 seed0 d0 shuffle0].
proof.
  case (size d0 = 256) => hd; last by exfalso; smt().
  conseq (caller_signer_finish FixedPrefix) (_ : true ==> true)
    (fixed_functional_signer_finish f h c key0 seed0 randomizer0 d0 shuffle0 hd) => //; smt().
qed.

lemma fixed_functional_signer_finish_lossless : islossless CommonInputSigner(FixedPrefix).finish.
proof.
  proc; wp; while true (2-layer).
  + move=> z; wp; call fixed_functional_layer_sign_lossless; auto; smt().
  wp; call fixed_functional_forest_sign_lossless; auto; smt().
qed.

lemma raw_functional_signer_finish_lossless : islossless RawSigner(FixedPrefix).finish.
proof.
  exact (signer_finish_lossless FixedPrefix fixed_hash_ll fixed_derive_ll).
qed.

(* Complete release-style native signer: explicit nonce and layer exhaustion,
   one retained backend and exact executed-prefix state/cost. *)







op paired_signer_result fn key seed root random message =
  let slot = signer_nonce_slot fn seed root key random message in
  if slot = 0 then None else
    paired_finish_result fn key seed (signer_randomizer fn key random message (slot-1))
      (signer_digest fn seed root key random message (slot-1)).
op functional_signer_digest f key seed root random message =
  f (functional_fors_query f key random message seed root
    (functional_header_slot f key seed root random message-1)).
op functional_signer_cost f key seed root random message shuffle =
  2 * functional_header_steps f key seed root random message +
    (if functional_header_slot f key seed root random message = 0 then 0 else
      functional_finish_cost f key seed (functional_signer_digest f key seed root random message) shuffle).
op functional_signer_state f h final key seed root random message shuffle =
  let searched = functional_fors_history f h key random message seed root
    (functional_header_steps f key seed root random message) in
  if functional_header_slot f key seed root random message = 0 then final = searched else
    functional_finish_state f searched final key seed (functional_signer_digest f key seed root random message) shuffle.

lemma common_functional_signer_header f h c key0 random0 message0 seed0 root0 :
  equiv[RoleGrind(FixedPrefix).run ~ CommonInputGrind(FixedPrefix).run :
    ={random,message,seed,root,glob FixedPrefix} /\
    random{1} = random0 /\ message{1} = message0 /\ seed{1} = seed0 /\ root{1} = root0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\ res{1} = functional_header_result f key0 seed0 root0 random0 message0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+2*functional_header_steps f key0 seed0 root0 random0 message0 /\
    FixedBackend.history{1} = functional_fors_history f h key0 random0 message0 seed0 root0
      (functional_header_steps f key0 seed0 root0 random0 message0)].
proof.
  transitivity PairedAcceptanceGrind(FixedPrefix).run
    (={random,message,seed,root,glob FixedPrefix} /\
      random{1} = random0 /\ message{1} = message0 /\ seed{1} = seed0 /\ root{1} = root0 /\
      FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
      backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
      ={res,glob FixedPrefix} /\ res{1} = functional_header_result f key0 seed0 root0 random0 message0 /\
      FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
      FixedBackend.calls{1} = c+2*functional_header_steps f key0 seed0 root0 random0 message0 /\
      FixedBackend.history{1} = functional_fors_history f h key0 random0 message0 seed0 root0
        (functional_header_steps f key0 seed0 root0 random0 message0))
    (={random,message,seed,root,glob FixedPrefix} /\ FixedBackend.fn{1} = f /\
      backend_consistent FixedBackend.history{1} f /\ backend_width f ==> ={res,glob FixedPrefix}) => //.
  + smt().
  + exact (raw_functional_signer_header f h c key0 random0 message0 seed0 root0).
  symmetry; conseq (fixed_nonce_paired f) => //; smt().
qed.

lemma functional_signer_value f key seed root random message : backend_width f =>
  let accepted = functional_header_result f key seed root random message in
  (if accepted = None then None else
    paired_finish_result (interpreted_backend f) key seed (oget accepted).`1 (bits_to_bytes (oget accepted).`2)) =
    paired_signer_result (interpreted_backend f) key seed root random message.
proof.
  move=> hf; rewrite /functional_header_result /functional_header_slot /paired_signer_result /=.
  case (signer_nonce_slot (interpreted_backend f) seed root key random message = 0) => hs; first by trivial.
  by rewrite /= functional_fors_digest_shared 1:hf.
qed.

lemma functional_signer_accepted f key seed root random message : backend_width f =>
  functional_header_result f key seed root random message <> None =>
  functional_header_slot f key seed root random message <> 0 /\
  (oget (functional_header_result f key seed root random message)).`1 =
    signer_randomizer (interpreted_backend f) key random message
      (functional_header_slot f key seed root random message-1) /\
  (oget (functional_header_result f key seed root random message)).`2 =
    functional_signer_digest f key seed root random message /\
  size (functional_signer_digest f key seed root random message) = 256.
proof.
  move=> hf; rewrite /functional_header_result /functional_signer_digest /=.
  case (functional_header_slot f key seed root random message = 0) => hs /=;
    smt(functional_digest_width).
qed.

lemma functional_signer_success f h final key seed root random message shuffle :
  backend_width f => functional_header_slot f key seed root random message <> 0 =>
  paired_signer_result (interpreted_backend f) key seed root random message =
    paired_finish_result (interpreted_backend f) key seed
      (signer_randomizer (interpreted_backend f) key random message
        (functional_header_slot f key seed root random message-1))
      (bits_to_bytes (functional_signer_digest f key seed root random message)) /\
  functional_signer_cost f key seed root random message shuffle =
    2*functional_header_steps f key seed root random message+
      functional_finish_cost f key seed (functional_signer_digest f key seed root random message) shuffle /\
  functional_signer_state f h final key seed root random message shuffle =
    functional_finish_state f
      (functional_fors_history f h key random message seed root
        (functional_header_steps f key seed root random message)) final key seed
      (functional_signer_digest f key seed root random message) shuffle.
proof.
  move=> hf hs; rewrite /functional_signer_cost /functional_signer_state hs /=.
  rewrite /paired_signer_result /= -/(functional_header_slot f key seed root random message) hs /=
    /functional_signer_digest (functional_fors_digest_shared f key random message seed root _ hf); trivial.
qed.

lemma functional_signer_exhausted f h key seed root random message shuffle :
  functional_header_result f key seed root random message = None =>
  paired_signer_result (interpreted_backend f) key seed root random message = None /\
  functional_signer_cost f key seed root random message shuffle =
    2*functional_header_steps f key seed root random message /\
  functional_signer_state f h
    (functional_fors_history f h key random message seed root
      (functional_header_steps f key seed root random message)) key seed root random message shuffle.
proof.
  rewrite /functional_header_result /=.
  case (functional_header_slot f key seed root random message = 0) => hs /=; last by smt().
  rewrite /functional_signer_cost /functional_signer_state hs /=
    /paired_signer_result /= -/(functional_header_slot f key seed root random message) hs; trivial.
qed.

lemma raw_functional_signer f h c key0 seed0 root0 random0 message0 shuffle0 :
  equiv[RawSigner(FixedPrefix).sign ~ CommonInputSigner(FixedPrefix).sign :
    ={seed,root,random,message,shuffle,glob FixedPrefix} /\
    seed{1} = seed0 /\ root{1} = root0 /\ random{1} = random0 /\ message{1} = message0 /\ shuffle{1} = shuffle0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\
    res{1} = paired_signer_result (interpreted_backend f) key0 seed0 root0 random0 message0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+functional_signer_cost f key0 seed0 root0 random0 message0 shuffle0 /\
    functional_signer_state f h FixedBackend.history{1} key0 seed0 root0 random0 message0 shuffle0].
proof.
  proc.
  seq 1 1 : (={seed,root,random,message,shuffle,accepted,glob FixedPrefix} /\
    seed{1} = seed0 /\ root{1} = root0 /\ random{1} = random0 /\ message{1} = message0 /\ shuffle{1} = shuffle0 /\
    accepted{1} = functional_header_result f key0 seed0 root0 random0 message0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_width f /\
    backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c+2*functional_header_steps f key0 seed0 root0 random0 message0 /\
    FixedBackend.history{1} = functional_fors_history f h key0 random0 message0 seed0 root0
      (functional_header_steps f key0 seed0 root0 random0 message0)).
  + call (common_functional_signer_header f h c key0 random0 message0 seed0 root0); auto.
  sp 1 1; if; first by auto.
  + call (raw_functional_signer_finish f
      (functional_fors_history f h key0 random0 message0 seed0 root0
        (functional_header_steps f key0 seed0 root0 random0 message0))
      (c+2*functional_header_steps f key0 seed0 root0 random0 message0)
      key0 seed0
      (signer_randomizer (interpreted_backend f) key0 random0 message0
        (functional_header_slot f key0 seed0 root0 random0 message0-1))
      (functional_signer_digest f key0 seed0 root0 random0 message0) shuffle0).
    auto; smt(functional_signer_accepted functional_signer_success).
  auto; smt(functional_signer_exhausted).
qed.

lemma raw_functional_signer_lossless : islossless RawSigner(FixedPrefix).sign.
proof. exact (signer_sign_lossless FixedPrefix fixed_hash_ll fixed_derive_ll). qed.
