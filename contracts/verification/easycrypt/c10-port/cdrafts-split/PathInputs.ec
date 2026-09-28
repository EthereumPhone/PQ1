(* Fixed-width pair encoding turns a child-pair collision into two distinct
   raw inputs. The width requirement is explicit and has a concrete countermodel. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen PathReplay PathCollision RawPathReplay RawForsPathReplay.

op pair_input_injective (f : int -> int -> raw_input -> raw_input -> raw_input) =
  forall level parent left1 right1 left2 right2,
    size left1 = 16 => size right1 = 16 => size left2 = 16 => size right2 = 16 =>
    f level parent left1 right1 = f level parent left2 right2 =>
    (left1,right1) = (left2,right2).

op path_input_collision (h : (raw_input,digest) fmap)
  (f : int -> int -> raw_input -> raw_input -> raw_input) =
  exists level parent left1 right1 left2 right2,
    size left1 = 16 /\ size right1 = 16 /\ size left2 = 16 /\ size right2 = 16 /\
    f level parent left1 right1 \in h /\ f level parent left2 right2 \in h /\
    f level parent left1 right1 <> f level parent left2 right2 /\
    node (oget h.[f level parent left1 right1]) =
      node (oget h.[f level parent left2 right2]).

lemma padded_pair_injective prefix left1 right1 left2 right2 :
  size left1 = size left2 =>
  prefix ++ pad left1 ++ pad right1 = prefix ++ pad left2 ++ pad right2 =>
  (left1,right1) = (left2,right2).
proof.
  move=> hw; rewrite -!catA => he.
  have hp : pad left1 ++ pad right1 = pad left2 ++ pad right2 by smt(catsI).
  have hs : size (pad left1) = size (pad left2) by rewrite /pad !size_cat hw.
  have [hl hr] : pad left1 = pad left2 /\ pad right1 = pad right2 by smt(eqseq_cat).
  move: hl hr; rewrite /pad; smt(catIs).
qed.

lemma merkle_pair_injective seed layer tree :
  pair_input_injective (merkle_pair seed layer tree).
proof.
  rewrite /pair_input_injective /merkle_pair.
  smt(padded_pair_injective).
qed.

lemma fors_pair_injective seed ht tree :
  pair_input_injective (fors_pair seed ht tree).
proof.
  rewrite /pair_input_injective /fors_pair.
  smt(padded_pair_injective).
qed.

lemma path_pair_to_input_collision h f :
  pair_input_injective f => path_pair_collision h f => path_input_collision h f.
proof.
  rewrite /pair_input_injective /path_pair_collision /path_input_collision.
  move=> hi hc; elim hc => level parent left1 right1 left2 right2 [#]
    h1 h2 h3 h4 hx hy hn he.
  exists level parent left1 right1 left2 right2; smt().
qed.

lemma path_leaf_or_input_collision h f auth1 auth2 leaf1 leaf2 level index :
  pair_input_injective f =>
  size auth1 = size auth2 =>
  all (fun x => size x = 16) auth1 =>
  all (fun x => size x = 16) auth2 =>
  size leaf1 = 16 => size leaf2 = 16 =>
  path_recorded h f (leaf1,level,index) auth1 =>
  path_recorded h f (leaf2,level,index) auth2 =>
  (path_value h f (leaf1,level,index) auth1).`1 =
    (path_value h f (leaf2,level,index) auth2).`1 =>
  leaf1 = leaf2 \/ path_input_collision h f.
proof.
  move=> hi hs ha1 ha2 hl1 hl2 hr1 hr2 he.
  have hc := path_leaf_or_collision h f auth1 auth2 leaf1 leaf2 level index
    hs ha1 ha2 hl1 hl2 hr1 hr2 he.
  smt(path_pair_to_input_collision).
qed.

lemma padded_pair_without_width_alias prefix :
  prefix ++ pad [] ++ pad (nseq 16 0) = prefix ++ pad (nseq 16 0) ++ pad [] /\
  ([],nseq 16 0) <> (nseq 16 0,[]).
proof.
  split.
  + by rewrite /pad /= !catA.
  smt(size_nseq).
qed.
