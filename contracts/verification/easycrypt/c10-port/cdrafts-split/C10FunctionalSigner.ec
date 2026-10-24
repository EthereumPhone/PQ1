(* Complete release-style native signer: explicit nonce and layer exhaustion,
   one retained backend and exact executed-prefix state/cost. *)
require import AllCore List IntDiv FMap.
require import C10Bytes C10RawOracle C10RawGrind RoleGrind RawSigner RawSignature.
require import C10Representation C10Counter KeygenPrefixes C10FixedBackend C10FixedCallerBridge.
require import C10CallerInputBridge C10OuterCallerBridge C10SearchAcceptance.
require import C10FunctionalFors C10FunctionalSearch C10FunctionalWotsValue.
require import C10FunctionalSignerHeader C10FunctionalSignerValue C10FunctionalSignerState C10FunctionalSignerFinish.

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
