require import AllCore List IntDiv C10Representation.
op forest_sign_secrets (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : ((int list) list) =
  ((mkseq (fun i => (fors_secret_value hash_fn secret ht (i) (nth 0 forest_indices i))) 12) ++ [(fors_root_value hash_fn seed secret ht 12)]).

op forest_sign_paths (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : (((int list) list) list) =
  (mkseq (fun i => (fors_auth_values hash_fn seed secret ht (i) (nth 0 forest_indices i))) 12).

op forest_recover_roots (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (forest_indices : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : ((int list) list) =
  ((mkseq (fun i => (fors_recover_value hash_fn seed ht (i) (nth 0 forest_indices i) (nth (nseq 16 0) forest_secrets i) (nth [] forest_paths i))) 12) ++ [(fors_leaf_value hash_fn seed ht 12 0 (nth (nseq 16 0) forest_secrets 12))]).

op forest_compress_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (values : ((int list) list)) : (int list) =
  (hash_bytes_node hash_fn (multi_preimage seed (address_words 0 ht 3 0 0 0 0) values)).

op forest_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (forest_indices : (int list)) (forest_secrets : ((int list) list)) (forest_paths : (((int list) list) list)) : (int list) =
  (forest_compress_value hash_fn seed ht (forest_recover_roots hash_fn seed ht forest_indices forest_secrets forest_paths)).

op forest_sign_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (forest_indices : (int list)) : (((int list) list) * (((int list) list) list) * (int list)) =
  ((forest_sign_secrets hash_fn seed secret ht forest_indices), (forest_sign_paths hash_fn seed secret ht forest_indices), (forest_recover_value hash_fn seed ht forest_indices (forest_sign_secrets hash_fn seed secret ht forest_indices) (forest_sign_paths hash_fn seed secret ht forest_indices))).

op wots_search_digests (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) : ((int list) list) =
  (mkseq (fun i => (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) (i)))) 10000000).

op layer_sign_slot (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) : int =
  (wots_first_slot (wots_search_digests hash_fn seed layer tree kp message)).

op layer_sign_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (nonce : int) : (((int list) list) * int * ((int list) list)) =
  ((wots_sign_values hash_fn seed secret layer tree kp (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce))), nonce, (merkle_auth_values hash_fn seed secret layer tree kp)).

op layer_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (merkle_recover_value hash_fn seed layer tree (wots_recover_value hash_fn seed layer tree kp message values nonce) kp auth).
