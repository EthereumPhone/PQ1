require import AllCore List IntDiv C10Representation.
op fors_secret_value (hash_fn : (int list -> int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : (int list) =
  (hash_bytes_node hash_fn (fors_private_preimage secret ht tree leaf)).

op fors_leaf_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (tree : int) (leaf : int) (value : (int list)) : (int list) =
  (hash_bytes_node hash_fn (th_preimage seed (address_words 0 ht 3 tree 0 0 leaf) (pad_node value))).

op tree_pair_value (hash_fn : (int list -> int list)) (seed : (int list)) (address : (int list)) (left : (int list)) (right : (int list)) : (int list) =
  (hash_bytes_node hash_fn (pair_preimage seed address (pad_node left) (pad_node right))).

op tree_path_step (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (auth : ((int list) list)) (index0 : int) (current : (int list)) (height : int) : (int list) =
  (tree_pair_value hash_fn seed (address_words layer tree kind kp 0 ((height + 1)) ((index0 %/ (2 ^ height)) %/ 2)) (if ((index0 %/ (2 ^ height)) %% 2) = 0 then current else (nth (nseq 16 0) auth height)) (if ((index0 %/ (2 ^ height)) %% 2) = 0 then (nth (nseq 16 0) auth height) else current)).

op tree_path_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (value : (int list)) (index0 : int) (auth : ((int list) list)) (steps : int) : (int list) =
  (foldr (fun i current => (tree_path_step hash_fn seed layer tree kind kp auth index0 current i)) value (rev (mkseq (fun i => i) steps))).

op fors_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (ht : int) (tree : int) (leaf : int) (value : (int list)) (auth : ((int list) list)) : (int list) =
  (tree_path_value hash_fn seed 0 ht 3 0 (fors_leaf_value hash_fn seed ht tree leaf value) leaf auth 11).

op merkle_recover_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (value : (int list)) (index0 : int) (auth : ((int list) list)) : (int list) =
  (tree_path_value hash_fn seed layer tree 2 0 value index0 auth 9).
