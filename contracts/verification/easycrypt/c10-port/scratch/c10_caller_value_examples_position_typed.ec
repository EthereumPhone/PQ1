require import AllCore List IntDiv C10Representation.
op layer_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kp : int) (message : (int list)) (values : ((int list) list)) (nonce : int) (auth : ((int list) list)) : (int list) =
  (merkle_recover_value hash_fn seed layer tree (wots_recover_value hash_fn seed layer tree kp message values nonce) (kp+1) auth).
