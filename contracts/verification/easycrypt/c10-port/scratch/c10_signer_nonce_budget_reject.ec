require import AllCore List.
require import C10Representation C10RawOracle C10RawGrind C10Randomizer C10Counter C10Bytes.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalFors C10FunctionalSearch.
require import C10FunctionalWotsValue.
require import RawKeygen.
require import RoleGrind C10SearchAcceptance.

op signer_randomizer (hash_fn : (int list -> int list)) (secret : (int list)) (random : (int list)) (message : (int list)) (nonce : int) : (int list) =
  (hash_bytes_node hash_fn (r_preimage secret random message nonce)).

op signer_digest (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) (nonce : int) : (int list) =
  (verifier_digest hash_fn seed root (signer_randomizer hash_fn secret random message nonce) message).

op signer_search_digests (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) : ((int list) list) =
  (mkseq (fun i => (signer_digest hash_fn seed root secret random message (i))) 9999999).

op signer_nonce_slot (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) : int =
  (fors_first_slot (signer_search_digests hash_fn seed root secret random message)).

(* The complete signer nonce header consumes the same paired expression.
   Arbitrary consistent prehistory and exhaustion effects are retained. *)







op functional_header_slot f key seed root random message =
  signer_nonce_slot (interpreted_backend f) seed root key random message.
op functional_header_steps f key seed root random message =
  let slot = functional_header_slot f key seed root random message in
  if slot = 0 then signing_budget else slot.
op functional_header_result f key seed root random message =
  let slot = functional_header_slot f key seed root random message in
  if slot = 0 then None else Some
    (signer_randomizer (interpreted_backend f) key random message (slot-1),
     f (functional_fors_query f key random message seed root (slot-1))).

lemma functional_randomizer_shared f key random message i : backend_width f =>
  functional_randomizer f key random message i =
    signer_randomizer (interpreted_backend f) key random message i.
proof.
  move=> hf; rewrite /functional_randomizer /functional_r_query /signer_randomizer
    -(node_exact _ (functional_digest_width f _ hf)) (interpreted_node f _ hf)
    /r_preimage /= -!catA /=; trivial.
qed.

lemma functional_fors_digest_shared f key random message seed root i : backend_width f =>
  bits_to_bytes (f (functional_fors_query f key random message seed root i)) =
    signer_digest (interpreted_backend f) seed root key random message i.
proof.
  move=> hf; rewrite /functional_fors_query (functional_randomizer_shared f key random message i hf)
    /signer_digest /verifier_digest /interpreted_backend; trivial.
qed.

lemma functional_fors_slot_shared f key random message seed root : backend_width f =>
  fors_first_slot (functional_fors_digests f key random message seed root) =
    functional_header_slot f key seed root random message.
proof.
  move=> hf; rewrite /functional_fors_digests /functional_header_slot
    /signer_nonce_slot /signer_search_digests /signing_budget.
  congr; apply eq_in_mkseq => i hi; exact (functional_fors_digest_shared f key random message seed root i hf).
qed.

lemma raw_functional_signer_header f h c key0 random0 message0 seed0 root0 :
  equiv[RoleGrind(FixedPrefix).run ~ PairedAcceptanceGrind(FixedPrefix).run :
    ={random,message,seed,root,glob FixedPrefix} /\
    random{1} = random0 /\ message{1} = message0 /\ seed{1} = seed0 /\ root{1} = root0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ FixedBackend.history{1} = h /\
    backend_consistent h f /\ backend_width f /\ FixedBackend.calls{1} = c ==>
    ={res,glob FixedPrefix} /\ res{1} = functional_header_result f key0 seed0 root0 random0 message0 /\
    FixedPrefix.key{1} = key0 /\ FixedBackend.fn{1} = f /\ backend_consistent FixedBackend.history{1} f /\
    FixedBackend.calls{1} = c + 2 * functional_header_steps f key0 seed0 root0 random0 message0 /\
    FixedBackend.history{1} = functional_fors_history f h key0 random0 message0 seed0 root0
      (functional_header_steps f key0 seed0 root0 random0 message0)].
proof.
  conseq (role_nonce_functional_selector f h c key0 random0 message0 seed0 root0) => //.
  rewrite /functional_header_result /functional_header_steps.
  smt(functional_fors_slot_shared functional_randomizer_shared).
qed.
