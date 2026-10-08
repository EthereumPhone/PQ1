(* All actual top/bottom chain cuts have one bounded public coordinate. *)
require import AllCore List IntDiv.
require import C10RawOracle RawForest SignerCoordinates.

type wots_coordinate = int * int * int * int * int.
op wots_keys =
  map (fun ht => (0,ht %/512,ht %%512)) (range 0 262144) ++
  map (fun kp => (1,0,kp)) (range 0 512).
op key_cuts (key : int * int * int) : wots_coordinate list =
  flatten (map (fun i => map (fun cut => (key.`1,key.`2,key.`3,i,cut)) (range 0 7)) (range 0 43)).
op wots_coordinates = flatten (map key_cuts wots_keys).

lemma wots_keys_size : size wots_keys=262656.
proof. by rewrite /wots_keys size_cat !size_map !size_range /=. qed.
lemma key_cuts_size key : size (key_cuts key)=301.
proof.
  rewrite /key_cuts (size_flatten_ctt 7).
  + move=> row /mapP [i [hi ->]]; by rewrite size_map size_range /=.
  by rewrite size_map size_range /=.
qed.
lemma wots_coordinates_size : size wots_coordinates=79059456.
proof.
  rewrite /wots_coordinates (size_flatten_ctt 301).
  + move=> row /mapP [key [hk ->]]; exact (key_cuts_size key).
  by rewrite size_map wots_keys_size.
qed.
lemma key_cuts_mem key i cut :
  0<=i<43 => 0<=cut<7 => mem (key_cuts key) (key.`1,key.`2,key.`3,i,cut).
proof.
  move=> hi hc; rewrite /key_cuts -flattenP.
  exists (map (fun j => (key.`1,key.`2,key.`3,i,j)) (range 0 7)); split.
  + rewrite mapP; exists i; rewrite mem_range; smt().
  rewrite mapP; exists cut; rewrite mem_range; smt().
qed.
lemma wots_coordinate_mem key i cut :
  mem wots_keys key => 0<=i<43 => 0<=cut<7 =>
  mem wots_coordinates (key.`1,key.`2,key.`3,i,cut).
proof.
  move=> hk hi hc; rewrite /wots_coordinates -flattenP.
  exists (key_cuts key); split.
  + rewrite mapP; exists key; smt().
  exact (key_cuts_mem key i cut hi hc).
qed.
lemma bottom_output_coordinate d i cut :
  0<=i<43 => 0<=cut<7 =>
  mem wots_coordinates (0,hypertree_index d %/512,hypertree_index d %%512,i,cut).
proof.
  move=> hi hc; apply (wots_coordinate_mem (0,hypertree_index d %/512,hypertree_index d %%512) i cut) => //.
  rewrite /wots_keys mem_cat; left; rewrite mapP; exists (hypertree_index d).
  rewrite mem_range; smt(hypertree_index_range).
qed.
lemma top_output_coordinate d i cut :
  0<=i<43 => 0<=cut<7 => mem wots_coordinates (1,0,hypertree_index d %/512,i,cut).
proof.
  move=> hi hc; apply (wots_coordinate_mem (1,0,hypertree_index d %/512) i cut) => //.
  rewrite /wots_keys mem_cat; right; rewrite mapP; exists (hypertree_index d %/512).
  rewrite mem_range; smt(hypertree_index_range divz_ge0 ltz_divLR).
qed.
