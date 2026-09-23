(* Different leaves at the same position cannot meet without a recorded
   collision of node hashes at one common height and parent index. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle RawKeygen PathReplay.

op path_pair_collision (h : (raw_input,digest) fmap)
  (f : int -> int -> raw_input -> raw_input -> raw_input) =
  exists level parent left1 right1 left2 right2,
    size left1 = 16 /\ size right1 = 16 /\ size left2 = 16 /\ size right2 = 16 /\
    f level parent left1 right1 \in h /\ f level parent left2 right2 \in h /\
    (left1,right1) <> (left2,right2) /\
    node (oget h.[f level parent left1 right1]) =
      node (oget h.[f level parent left2 right2]).

lemma path_step_collision h f leaf1 leaf2 level index sibling1 sibling2 :
  size leaf1 = 16 => size leaf2 = 16 =>
  size sibling1 = 16 => size sibling2 = 16 =>
  path_input f (leaf1,level,index) sibling1 \in h =>
  path_input f (leaf2,level,index) sibling2 \in h =>
  (path_step h f (leaf1,level,index) sibling1).`1 =
    (path_step h f (leaf2,level,index) sibling2).`1 =>
  leaf1 <> leaf2 => path_pair_collision h f.
proof.
  rewrite /path_input /path_step /= /path_pair_collision.
  move=> hl1 hl2 hs1 hs2 hx hy he hn.
  case (index %% 2 = 0) => parity.
  + exists (level+1) (index %/ 2) leaf1 sibling1 leaf2 sibling2; smt().
  exists (level+1) (index %/ 2) sibling1 leaf1 sibling2 leaf2; smt().
qed.

lemma path_leaf_or_collision h f auth1 auth2 leaf1 leaf2 level index :
  size auth1 = size auth2 =>
  all (fun x => size x = 16) auth1 =>
  all (fun x => size x = 16) auth2 =>
  size leaf1 = 16 => size leaf2 = 16 =>
  path_recorded h f (leaf1,level,index) auth1 =>
  path_recorded h f (leaf2,level,index) auth2 =>
  (path_value h f (leaf1,level,index) auth1).`1 =
    (path_value h f (leaf2,level,index) auth2).`1 =>
  leaf1 = leaf2 \/ path_pair_collision h f.
proof.
  elim: auth1 auth2 leaf1 leaf2 level index =>
    [auth2 leaf1 leaf2 level index | sibling1 rest1 ih auth2 leaf1 leaf2 level index].
  + move=> hs.
    have -> : auth2 = [] by smt(size_eq0).
    by rewrite /path_value /=.
  case: auth2 => [|sibling2 rest2].
  + rewrite /=; smt(size_ge0).
  rewrite /= /path_value /=.
  move=> hs [hw1 ha1] [hw2 ha2] hl1 hl2 [hx hp1] [hy hp2] he.
  have hn := ih rest2
    (node (oget h.[path_input f (leaf1,level,index) sibling1]))
    (node (oget h.[path_input f (leaf2,level,index) sibling2]))
    (level+1) (index %/ 2) _ ha1 ha2 (node_width _) (node_width _) _ _ _.
  + smt().
  + exact hp1.
  + exact hp2.
  + exact he.
  case hn => [same | collision]; last by right.
  case (leaf1 = leaf2) => equal; first by left.
  right; apply (path_step_collision h f leaf1 leaf2 level index sibling1 sibling2)
    => //; exact same.
qed.
