(* A changed FORS secret at one fixed position changes its raw leaf input. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawForsPathReplay.

op fors_leaf_collision (h : (raw_input,digest) fmap) seed ht tree target =
  exists secret1 secret2,
    size secret1 = 16 /\ size secret2 = 16 /\
    fors_leaf_input seed ht tree target secret1 \in h /\
    fors_leaf_input seed ht tree target secret2 \in h /\
    fors_leaf_input seed ht tree target secret1 <> fors_leaf_input seed ht tree target secret2 /\
    node (oget h.[fors_leaf_input seed ht tree target secret1]) =
      node (oget h.[fors_leaf_input seed ht tree target secret2]).

lemma fors_leaf_input_injective seed ht tree target secret1 secret2 :
  fors_leaf_input seed ht tree target secret1 = fors_leaf_input seed ht tree target secret2 =>
  secret1 = secret2.
proof.
  rewrite /fors_leaf_input => he.
  have hp : pad secret1 = pad secret2 by smt(catsI).
  move: hp; rewrite /pad; smt(catIs).
qed.

lemma fors_leaf_equal_or_collision h seed ht tree target secret1 secret2 d1 d2 :
  size secret1 = 16 => size secret2 = 16 =>
  h.[fors_leaf_input seed ht tree target secret1] = Some d1 =>
  h.[fors_leaf_input seed ht tree target secret2] = Some d2 =>
  node d1 = node d2 =>
  secret1 = secret2 \/ fors_leaf_collision h seed ht tree target.
proof.
  move=> hw1 hw2 he1 he2 hn.
  case (secret1 = secret2) => equal; first by left.
  right; rewrite /fors_leaf_collision; exists secret1 secret2.
  smt(fors_leaf_input_injective domE).
qed.
