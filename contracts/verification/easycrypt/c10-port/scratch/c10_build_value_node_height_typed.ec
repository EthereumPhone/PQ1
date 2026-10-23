require import AllCore List IntDiv C10Representation.
op tree_level_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (height : int) (nodes : ((int list) list)) : ((int list) list) =
  (mkseq (fun i => (tree_pair_value hash_fn seed (address_words layer tree kind kp 0 (height+1) (i)) (nth (nseq 16 0) nodes (2 * i)) (nth (nseq 16 0) nodes ((2 * i) + 1)))) (2 ^ (max 0 (total_height - height)))).

op tree_nodes_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (rounds : int) (values : ((int list) list)) : ((int list) list) =
  (foldr (fun i nodes => (tree_level_value hash_fn seed layer tree kind kp total_height (i + 1) nodes)) values (rev (mkseq (fun i => i) rounds))).

op tree_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (values : ((int list) list)) : (int list) =
  (nth (nseq 16 0) (tree_nodes_value hash_fn seed layer tree kind kp total_height total_height values) 0).

op tree_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (layer : int) (tree : int) (kind : int) (kp : int) (total_height : int) (values : ((int list) list)) (index0 : int) : ((int list) list) =
  (mkseq (fun height => (nth (nseq 16 0) (tree_nodes_value hash_fn seed layer tree kind kp total_height height values) (max 0 (if ((index0 %/ (2 ^ height)) %% 2) = 0 then ((index0 %/ (2 ^ height)) + 1) else ((index0 %/ (2 ^ height)) - 1))))) total_height).

op fors_tree_leaves (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) : ((int list) list) =
  (mkseq (fun i => (fors_leaf_value hash_fn seed ht tree (i) (fors_secret_value hash_fn secret ht tree (i)))) 2048).

op fors_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) : (int list) =
  (tree_root_value hash_fn seed 0 ht 3 tree 11 (fors_tree_leaves hash_fn seed secret ht tree)).

op fors_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : ((int list) list) =
  (tree_auth_values hash_fn seed 0 ht 3 tree 11 (fors_tree_leaves hash_fn seed secret ht tree) leaf).

op fors_sign_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (ht : int) (tree : int) (leaf : int) : ((int list) * ((int list) list)) =
  ((fors_secret_value hash_fn secret ht tree leaf), (fors_auth_values hash_fn seed secret ht tree leaf)).

op merkle_tree_leaves (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) : ((int list) list) =
  (mkseq (fun i => (wots_keygen_value hash_fn seed secret layer tree (i))) 512).

op merkle_root_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) : (int list) =
  (tree_root_value hash_fn seed layer tree 2 0 9 (merkle_tree_leaves hash_fn seed secret layer tree)).

op merkle_auth_values (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (index0 : int) : ((int list) list) =
  (tree_auth_values hash_fn seed layer tree 2 0 9 (merkle_tree_leaves hash_fn seed secret layer tree) index0).

op merkle_build_value (hash_fn : (int list -> int list)) (seed : (int list)) (secret : (int list)) (layer : int) (tree : int) (index0 : int) : (((int list) list) * (int list)) =
  ((merkle_auth_values hash_fn seed secret layer tree index0), (merkle_root_value hash_fn seed secret layer tree)).
