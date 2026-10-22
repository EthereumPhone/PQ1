(* Complete bounded native signing under the explicit fixed interpretation. *)
require import AllCore List FMap.
require import C10Bytes C10Counter C10Representation C10RawOracle C10RawGrind RawWots RawWotsFill KeygenPrefixes.
require import C10CallerInputBridge C10PrivateCallerBridge C10SearchAcceptance C10FixedBackend C10FixedCallerBridge.
require import C10FunctionalWots C10FunctionalWotsValue.
require import C10FunctionalWotsShuffle C10FunctionalWotsFill.

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
