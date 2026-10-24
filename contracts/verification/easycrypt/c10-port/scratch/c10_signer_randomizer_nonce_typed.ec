require import AllCore List.
require import C10Representation C10RawOracle C10RawGrind C10Randomizer C10Counter C10Bytes.
require import C10FixedBackend C10FixedCallerBridge C10FunctionalFors C10FunctionalSearch.
require import C10FunctionalWotsValue.
require import RawKeygen.
require import RoleGrind C10SearchAcceptance.

op signer_randomizer (hash_fn : (int list -> int list)) (secret : (int list)) (random : (int list)) (message : (int list)) (nonce : int) : (int list) =
  (hash_bytes_node hash_fn (r_preimage secret random message (nonce+1))).

op signer_digest (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) (nonce : int) : (int list) =
  (verifier_digest hash_fn seed root (signer_randomizer hash_fn secret random message nonce) message).

op signer_search_digests (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) : ((int list) list) =
  (mkseq (fun i => (signer_digest hash_fn seed root secret random message (i))) 10000000).

op signer_nonce_slot (hash_fn : (int list -> int list)) (seed : (int list)) (root : (int list)) (secret : (int list)) (random : (int list)) (message : (int list)) : int =
  (fors_first_slot (signer_search_digests hash_fn seed root secret random message)).
