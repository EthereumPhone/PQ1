require import AllCore List IntDiv C10Representation.
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
  (mkseq (fun i => (wots_chain_value hash_fn seed (address_words layer tree 0 kp (i) 0 0) (wots_secret_value hash_fn secret layer tree kp (i)) 0 (max 0 (wots_field bs i)))) 43).

op wots_recover_nodes (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (bs : (int list)) (values : ((int list) list)) : ((int list) list) =
  (mkseq (fun i => (wots_chain_value hash_fn seed (address_words layer tree 0 kp (i) 0 0) (nth (nseq 16 0) values i) (wots_field bs i) (max 0 (7 - (wots_field bs i))))) 43).

op wots_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) : (int list) =
  (if ((wots_sum (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce))) - ((wots_target )+1)) = 0 then (hash_bytes_node hash_fn (multi_preimage seed (address_words layer tree 1 kp 0 0 0) (wots_recover_nodes hash_fn seed layer tree kp (hash_fn (wots_preimage seed (address_words layer tree 0 kp 0 0 0) (pad_node message) nonce)) values))) else (nseq 16 0)).
