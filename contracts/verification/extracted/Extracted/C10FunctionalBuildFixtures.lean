/- Generated complete-tree fold fixtures; arithmetic leaves, not a SHA claim. -/
import Extracted.C10FunctionalBuildValues
import Aeneas
open C10Representation Extracted.C10FunctionalBuildValues
set_option maxRecDepth 8192
set_option maxHeartbeats 3000000
namespace Extracted.C10FunctionalBuildFixtures
def toy (q : List Int) : List Int := List.replicate 32 ((1*(q.getD 32 0) + 3*(q.getD 36 0) + 5*(q.getD 43 0) + 7*(q.getD 47 0) + 11*(q.getD 51 0) + 13*(q.getD 59 0) + 17*(q.getD 60 0) + 19*(q.getD 63 0) + 23*(q.getD 64 0) + 29*(q.getD 96 0)) % 256)
theorem toy_pair (l t k kp h i x y : Int) :
  tree_pair_value toy (List.replicate 32 0) (address_words l t k kp 0 h i)
    (List.replicate 16 x) (List.replicate 16 y) =
  List.replicate 16 ((l / 16777216 % 256 + 3*(t / 72057594037927936 % 256) + 5*(t % 256) +
    7*(k % 256) + 11*(kp % 256) + 13*(h % 256) + 17*(i / 16777216 % 256) +
    19*(i % 256) + 23*x + 29*y) % 256) := by
  simp [tree_pair_value, hash_bytes_node, toy, pair_preimage, pad_node, address_words,
    u32_bytes, u64_bytes, List.range_succ, List.replicate_succ]
def leaves (total : Nat) := (List.range (2^total)).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256))
theorem affine_get (a b : Int) (n i : Nat) (hi : i < n) :
  ((List.range n).map (fun (j : Nat) => List.replicate 16 ((a*(j:Int)+b)%256))).getD i (List.replicate 16 0) =
    List.replicate 16 ((a*(i:Int)+b)%256) := by
  rw [List.getD_eq_getElem _ _ (by simpa only [List.length_map, List.length_range] using hi)]
  simp only [List.getElem_map, List.getElem_range]
theorem fors_zero_level0 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 0 (leaves 11) =
  (List.range 2048).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256)) := by
  rfl
theorem fors_zero_level1 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 1 (leaves 11) =
  (List.range 1024).map (fun (i : Nat) => List.replicate 16 ((251*(i:Int)+171)%256)) := by
  rw [show 1 = 0+1 from rfl, nodes_succ, fors_zero_level0]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1024 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 17 3 2048 (2*i) (by omega),
    affine_get 17 3 2048 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level2 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 2 (leaves 11) =
  (List.range 512).map (fun (i : Nat) => List.replicate 16 ((11*(i:Int)+90)%256)) := by
  rw [show 2 = 1+1 from rfl, nodes_succ, fors_zero_level1]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 512 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 251 171 1024 (2*i) (by omega),
    affine_get 251 171 1024 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level3 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 3 (leaves 11) =
  (List.range 256).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+195)%256)) := by
  rw [show 3 = 2+1 from rfl, nodes_succ, fors_zero_level2]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 256 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 11 90 512 (2*i) (by omega),
    affine_get 11 90 512 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level4 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 4 (leaves 11) =
  (List.range 128).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+164)%256)) := by
  rw [show 4 = 3+1 from rfl, nodes_succ, fors_zero_level3]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 128 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 195 256 (2*i) (by omega),
    affine_get 139 195 256 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level5 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 5 (leaves 11) =
  (List.range 64).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+101)%256)) := by
  rw [show 5 = 4+1 from rfl, nodes_succ, fors_zero_level4]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 64 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 164 128 (2*i) (by omega),
    affine_get 139 164 128 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level6 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 6 (leaves 11) =
  (List.range 32).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+166)%256)) := by
  rw [show 6 = 5+1 from rfl, nodes_succ, fors_zero_level5]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 32 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 101 64 (2*i) (by omega),
    affine_get 139 101 64 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level7 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 7 (leaves 11) =
  (List.range 16).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+231)%256)) := by
  rw [show 7 = 6+1 from rfl, nodes_succ, fors_zero_level6]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 16 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 166 32 (2*i) (by omega),
    affine_get 139 166 32 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level8 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 8 (leaves 11) =
  (List.range 8).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+40)%256)) := by
  rw [show 8 = 7+1 from rfl, nodes_succ, fors_zero_level7]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 8 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 231 16 (2*i) (by omega),
    affine_get 139 231 16 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level9 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 9 (leaves 11) =
  (List.range 4).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+105)%256)) := by
  rw [show 9 = 8+1 from rfl, nodes_succ, fors_zero_level8]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 4 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 40 8 (2*i) (by omega),
    affine_get 139 40 8 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level10 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 10 (leaves 11) =
  (List.range 2).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+170)%256)) := by
  rw [show 10 = 9+1 from rfl, nodes_succ, fors_zero_level9]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 2 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 105 4 (2*i) (by omega),
    affine_get 139 105 4 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_level11 : tree_nodes_value toy (List.replicate 32 0) 0 0 3 0 11 11 (leaves 11) =
  (List.range 1).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+235)%256)) := by
  rw [show 11 = 10+1 from rfl, nodes_succ, fors_zero_level10]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 170 2 (2*i) (by omega),
    affine_get 139 170 2 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_zero_root : tree_root_value toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) = List.replicate 16 235 := by
  rw [root_value, fors_zero_level11, affine_get 139 235 1 0 (by decide)]
  rfl
theorem fors_zero_auth0 : tree_auth_values toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 0 = [List.replicate 16 20, List.replicate 16 166, List.replicate 16 101, List.replicate 16 78, List.replicate 16 47, List.replicate 16 240, List.replicate 16 49, List.replicate 16 114, List.replicate 16 179, List.replicate 16 244, List.replicate 16 53] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_zero_level0, fors_zero_level1, fors_zero_level2, fors_zero_level3, fors_zero_level4, fors_zero_level5, fors_zero_level6, fors_zero_level7, fors_zero_level8, fors_zero_level9, fors_zero_level10]
  norm_num [affine_get]
theorem fors_zero_auth1 : tree_auth_values toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 1 = [List.replicate 16 3, List.replicate 16 166, List.replicate 16 101, List.replicate 16 78, List.replicate 16 47, List.replicate 16 240, List.replicate 16 49, List.replicate 16 114, List.replicate 16 179, List.replicate 16 244, List.replicate 16 53] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_zero_level0, fors_zero_level1, fors_zero_level2, fors_zero_level3, fors_zero_level4, fors_zero_level5, fors_zero_level6, fors_zero_level7, fors_zero_level8, fors_zero_level9, fors_zero_level10]
  norm_num [affine_get]
theorem fors_zero_auth2047 : tree_auth_values toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 2047 = [List.replicate 16 225, List.replicate 16 181, List.replicate 16 68, List.replicate 16 173, List.replicate 16 14, List.replicate 16 15, List.replicate 16 240, List.replicate 16 129, List.replicate 16 106, List.replicate 16 127, List.replicate 16 170] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_zero_level0, fors_zero_level1, fors_zero_level2, fors_zero_level3, fors_zero_level4, fors_zero_level5, fors_zero_level6, fors_zero_level7, fors_zero_level8, fors_zero_level9, fors_zero_level10]
  norm_num [affine_get]
theorem fors_zero_auth2048 : tree_auth_values toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 2048 = List.replicate 11 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 2048 (by simp [leaves]) (by decide)
theorem fors_zero_auth4294967295 : tree_auth_values toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 4294967295 = List.replicate 11 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 0 3 0 11 (leaves 11) 4294967295 (by simp [leaves]) (by decide)
theorem fors_full_level0 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 0 (leaves 11) =
  (List.range 2048).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256)) := by
  rfl
theorem fors_full_level1 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 1 (leaves 11) =
  (List.range 1024).map (fun (i : Nat) => List.replicate 16 ((251*(i:Int)+155)%256)) := by
  rw [show 1 = 0+1 from rfl, nodes_succ, fors_full_level0]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1024 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 17 3 2048 (2*i) (by omega),
    affine_get 17 3 2048 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level2 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 2 (leaves 11) =
  (List.range 512).map (fun (i : Nat) => List.replicate 16 ((11*(i:Int)+10)%256)) := by
  rw [show 2 = 1+1 from rfl, nodes_succ, fors_full_level1]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 512 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 251 155 1024 (2*i) (by omega),
    affine_get 251 155 1024 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level3 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 3 (leaves 11) =
  (List.range 256).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+115)%256)) := by
  rw [show 3 = 2+1 from rfl, nodes_succ, fors_full_level2]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 256 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 11 10 512 (2*i) (by omega),
    affine_get 11 10 512 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level4 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 4 (leaves 11) =
  (List.range 128).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+84)%256)) := by
  rw [show 4 = 3+1 from rfl, nodes_succ, fors_full_level3]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 128 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 115 256 (2*i) (by omega),
    affine_get 139 115 256 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level5 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 5 (leaves 11) =
  (List.range 64).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+21)%256)) := by
  rw [show 5 = 4+1 from rfl, nodes_succ, fors_full_level4]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 64 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 84 128 (2*i) (by omega),
    affine_get 139 84 128 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level6 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 6 (leaves 11) =
  (List.range 32).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+86)%256)) := by
  rw [show 6 = 5+1 from rfl, nodes_succ, fors_full_level5]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 32 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 21 64 (2*i) (by omega),
    affine_get 139 21 64 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level7 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 7 (leaves 11) =
  (List.range 16).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+151)%256)) := by
  rw [show 7 = 6+1 from rfl, nodes_succ, fors_full_level6]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 16 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 86 32 (2*i) (by omega),
    affine_get 139 86 32 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level8 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 8 (leaves 11) =
  (List.range 8).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+216)%256)) := by
  rw [show 8 = 7+1 from rfl, nodes_succ, fors_full_level7]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 8 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 151 16 (2*i) (by omega),
    affine_get 139 151 16 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level9 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 9 (leaves 11) =
  (List.range 4).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+25)%256)) := by
  rw [show 9 = 8+1 from rfl, nodes_succ, fors_full_level8]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 4 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 216 8 (2*i) (by omega),
    affine_get 139 216 8 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level10 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 10 (leaves 11) =
  (List.range 2).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+90)%256)) := by
  rw [show 10 = 9+1 from rfl, nodes_succ, fors_full_level9]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 2 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 25 4 (2*i) (by omega),
    affine_get 139 25 4 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_level11 : tree_nodes_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 11 (leaves 11) =
  (List.range 1).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+155)%256)) := by
  rw [show 11 = 10+1 from rfl, nodes_succ, fors_full_level10]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 90 2 (2*i) (by omega),
    affine_get 139 90 2 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem fors_full_root : tree_root_value toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) = List.replicate 16 155 := by
  rw [root_value, fors_full_level11, affine_get 139 155 1 0 (by decide)]
  rfl
theorem fors_full_auth0 : tree_auth_values toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 0 = [List.replicate 16 20, List.replicate 16 150, List.replicate 16 21, List.replicate 16 254, List.replicate 16 223, List.replicate 16 160, List.replicate 16 225, List.replicate 16 34, List.replicate 16 99, List.replicate 16 164, List.replicate 16 229] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_full_level0, fors_full_level1, fors_full_level2, fors_full_level3, fors_full_level4, fors_full_level5, fors_full_level6, fors_full_level7, fors_full_level8, fors_full_level9, fors_full_level10]
  norm_num [affine_get]
theorem fors_full_auth1 : tree_auth_values toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 1 = [List.replicate 16 3, List.replicate 16 150, List.replicate 16 21, List.replicate 16 254, List.replicate 16 223, List.replicate 16 160, List.replicate 16 225, List.replicate 16 34, List.replicate 16 99, List.replicate 16 164, List.replicate 16 229] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_full_level0, fors_full_level1, fors_full_level2, fors_full_level3, fors_full_level4, fors_full_level5, fors_full_level6, fors_full_level7, fors_full_level8, fors_full_level9, fors_full_level10]
  norm_num [affine_get]
theorem fors_full_auth2047 : tree_auth_values toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 2047 = [List.replicate 16 225, List.replicate 16 165, List.replicate 16 244, List.replicate 16 93, List.replicate 16 190, List.replicate 16 191, List.replicate 16 160, List.replicate 16 49, List.replicate 16 26, List.replicate 16 47, List.replicate 16 90] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [fors_full_level0, fors_full_level1, fors_full_level2, fors_full_level3, fors_full_level4, fors_full_level5, fors_full_level6, fors_full_level7, fors_full_level8, fors_full_level9, fors_full_level10]
  norm_num [affine_get]
theorem fors_full_auth2048 : tree_auth_values toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 2048 = List.replicate 11 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 2048 (by simp [leaves]) (by decide)
theorem fors_full_auth4294967295 : tree_auth_values toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 4294967295 = List.replicate 11 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 4294967295 3 4294967295 11 (leaves 11) 4294967295 (by simp [leaves]) (by decide)
theorem merkle_zero_level0 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 0 (leaves 9) =
  (List.range 512).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256)) := by
  rfl
theorem merkle_zero_level1 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 1 (leaves 9) =
  (List.range 256).map (fun (i : Nat) => List.replicate 16 ((251*(i:Int)+164)%256)) := by
  rw [show 1 = 0+1 from rfl, nodes_succ, merkle_zero_level0]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 256 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 17 3 512 (2*i) (by omega),
    affine_get 17 3 512 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level2 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 2 (leaves 9) =
  (List.range 128).map (fun (i : Nat) => List.replicate 16 ((11*(i:Int)+231)%256)) := by
  rw [show 2 = 1+1 from rfl, nodes_succ, merkle_zero_level1]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 128 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 251 164 256 (2*i) (by omega),
    affine_get 251 164 256 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level3 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 3 (leaves 9) =
  (List.range 64).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+96)%256)) := by
  rw [show 3 = 2+1 from rfl, nodes_succ, merkle_zero_level2]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 64 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 11 231 128 (2*i) (by omega),
    affine_get 11 231 128 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level4 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 4 (leaves 9) =
  (List.range 32).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+129)%256)) := by
  rw [show 4 = 3+1 from rfl, nodes_succ, merkle_zero_level3]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 32 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 96 64 (2*i) (by omega),
    affine_get 139 96 64 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level5 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 5 (leaves 9) =
  (List.range 16).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+66)%256)) := by
  rw [show 5 = 4+1 from rfl, nodes_succ, merkle_zero_level4]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 16 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 129 32 (2*i) (by omega),
    affine_get 139 129 32 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level6 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 6 (leaves 9) =
  (List.range 8).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+131)%256)) := by
  rw [show 6 = 5+1 from rfl, nodes_succ, merkle_zero_level5]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 8 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 66 16 (2*i) (by omega),
    affine_get 139 66 16 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level7 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 7 (leaves 9) =
  (List.range 4).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+196)%256)) := by
  rw [show 7 = 6+1 from rfl, nodes_succ, merkle_zero_level6]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 4 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 131 8 (2*i) (by omega),
    affine_get 139 131 8 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level8 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 8 (leaves 9) =
  (List.range 2).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+5)%256)) := by
  rw [show 8 = 7+1 from rfl, nodes_succ, merkle_zero_level7]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 2 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 196 4 (2*i) (by omega),
    affine_get 139 196 4 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_level9 : tree_nodes_value toy (List.replicate 32 0) 0 0 2 0 9 9 (leaves 9) =
  (List.range 1).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+70)%256)) := by
  rw [show 9 = 8+1 from rfl, nodes_succ, merkle_zero_level8]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 5 2 (2*i) (by omega),
    affine_get 139 5 2 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_zero_root : tree_root_value toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) = List.replicate 16 70 := by
  rw [root_value, merkle_zero_level9, affine_get 139 70 1 0 (by decide)]
  rfl
theorem merkle_zero_auth0 : tree_auth_values toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 0 = [List.replicate 16 20, List.replicate 16 159, List.replicate 16 242, List.replicate 16 235, List.replicate 16 12, List.replicate 16 205, List.replicate 16 14, List.replicate 16 79, List.replicate 16 144] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_zero_level0, merkle_zero_level1, merkle_zero_level2, merkle_zero_level3, merkle_zero_level4, merkle_zero_level5, merkle_zero_level6, merkle_zero_level7, merkle_zero_level8]
  norm_num [affine_get]
theorem merkle_zero_auth1 : tree_auth_values toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 1 = [List.replicate 16 3, List.replicate 16 159, List.replicate 16 242, List.replicate 16 235, List.replicate 16 12, List.replicate 16 205, List.replicate 16 14, List.replicate 16 79, List.replicate 16 144] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_zero_level0, merkle_zero_level1, merkle_zero_level2, merkle_zero_level3, merkle_zero_level4, merkle_zero_level5, merkle_zero_level6, merkle_zero_level7, merkle_zero_level8]
  norm_num [affine_get]
theorem merkle_zero_auth511 : tree_auth_values toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 511 = [List.replicate 16 225, List.replicate 16 174, List.replicate 16 81, List.replicate 16 10, List.replicate 16 203, List.replicate 16 220, List.replicate 16 197, List.replicate 16 218, List.replicate 16 5] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_zero_level0, merkle_zero_level1, merkle_zero_level2, merkle_zero_level3, merkle_zero_level4, merkle_zero_level5, merkle_zero_level6, merkle_zero_level7, merkle_zero_level8]
  norm_num [affine_get]
theorem merkle_zero_auth512 : tree_auth_values toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 512 = List.replicate 9 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 512 (by simp [leaves]) (by decide)
theorem merkle_zero_auth4294967295 : tree_auth_values toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 4294967295 = List.replicate 9 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 0 0 2 0 9 (leaves 9) 4294967295 (by simp [leaves]) (by decide)
theorem merkle_full_level0 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 0 (leaves 9) =
  (List.range 512).map (fun (i : Nat) => List.replicate 16 ((17*(i:Int)+3)%256)) := by
  rfl
theorem merkle_full_level1 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 1 (leaves 9) =
  (List.range 256).map (fun (i : Nat) => List.replicate 16 ((251*(i:Int)+155)%256)) := by
  rw [show 1 = 0+1 from rfl, nodes_succ, merkle_full_level0]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 256 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 17 3 512 (2*i) (by omega),
    affine_get 17 3 512 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level2 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 2 (leaves 9) =
  (List.range 128).map (fun (i : Nat) => List.replicate 16 ((11*(i:Int)+10)%256)) := by
  rw [show 2 = 1+1 from rfl, nodes_succ, merkle_full_level1]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 128 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 251 155 256 (2*i) (by omega),
    affine_get 251 155 256 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level3 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 3 (leaves 9) =
  (List.range 64).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+115)%256)) := by
  rw [show 3 = 2+1 from rfl, nodes_succ, merkle_full_level2]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 64 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 11 10 128 (2*i) (by omega),
    affine_get 11 10 128 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level4 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 4 (leaves 9) =
  (List.range 32).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+84)%256)) := by
  rw [show 4 = 3+1 from rfl, nodes_succ, merkle_full_level3]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 32 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 115 64 (2*i) (by omega),
    affine_get 139 115 64 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level5 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 5 (leaves 9) =
  (List.range 16).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+21)%256)) := by
  rw [show 5 = 4+1 from rfl, nodes_succ, merkle_full_level4]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 16 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 84 32 (2*i) (by omega),
    affine_get 139 84 32 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level6 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 6 (leaves 9) =
  (List.range 8).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+86)%256)) := by
  rw [show 6 = 5+1 from rfl, nodes_succ, merkle_full_level5]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 8 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 21 16 (2*i) (by omega),
    affine_get 139 21 16 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level7 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 7 (leaves 9) =
  (List.range 4).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+151)%256)) := by
  rw [show 7 = 6+1 from rfl, nodes_succ, merkle_full_level6]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 4 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 86 8 (2*i) (by omega),
    affine_get 139 86 8 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level8 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 8 (leaves 9) =
  (List.range 2).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+216)%256)) := by
  rw [show 8 = 7+1 from rfl, nodes_succ, merkle_full_level7]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 2 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 151 4 (2*i) (by omega),
    affine_get 139 151 4 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_level9 : tree_nodes_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 9 (leaves 9) =
  (List.range 1).map (fun (i : Nat) => List.replicate 16 ((139*(i:Int)+25)%256)) := by
  rw [show 9 = 8+1 from rfl, nodes_succ, merkle_full_level8]
  apply List.ext_getElem
  · simp only [tree_level_value, List.length_map, List.length_range]
  intro i hi hj
  have hb : i < 1 := by simpa only [tree_level_value, List.length_map, List.length_range] using hi
  simp only [tree_level_value, List.getElem_map, List.getElem_range]
  rw [affine_get 139 216 2 (2*i) (by omega),
    affine_get 139 216 2 (2*i+1) (by omega), toy_pair]
  have hiz : (i:Int) / 16777216 = 0 := Int.ediv_eq_zero_of_lt (by omega) (by omega)
  norm_num
  simp only [hiz]
  omega
theorem merkle_full_root : tree_root_value toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) = List.replicate 16 25 := by
  rw [root_value, merkle_full_level9, affine_get 139 25 1 0 (by decide)]
  rfl
theorem merkle_full_auth0 : tree_auth_values toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 0 = [List.replicate 16 20, List.replicate 16 150, List.replicate 16 21, List.replicate 16 254, List.replicate 16 223, List.replicate 16 160, List.replicate 16 225, List.replicate 16 34, List.replicate 16 99] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_full_level0, merkle_full_level1, merkle_full_level2, merkle_full_level3, merkle_full_level4, merkle_full_level5, merkle_full_level6, merkle_full_level7, merkle_full_level8]
  norm_num [affine_get]
theorem merkle_full_auth1 : tree_auth_values toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 1 = [List.replicate 16 3, List.replicate 16 150, List.replicate 16 21, List.replicate 16 254, List.replicate 16 223, List.replicate 16 160, List.replicate 16 225, List.replicate 16 34, List.replicate 16 99] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_full_level0, merkle_full_level1, merkle_full_level2, merkle_full_level3, merkle_full_level4, merkle_full_level5, merkle_full_level6, merkle_full_level7, merkle_full_level8]
  norm_num [affine_get]
theorem merkle_full_auth511 : tree_auth_values toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 511 = [List.replicate 16 225, List.replicate 16 165, List.replicate 16 116, List.replicate 16 29, List.replicate 16 158, List.replicate 16 175, List.replicate 16 152, List.replicate 16 173, List.replicate 16 216] := by
  norm_num only [tree_auth_values, List.range_succ, List.map_append, List.map_cons, List.map_nil, List.map_singleton]
  simp only [merkle_full_level0, merkle_full_level1, merkle_full_level2, merkle_full_level3, merkle_full_level4, merkle_full_level5, merkle_full_level6, merkle_full_level7, merkle_full_level8]
  norm_num [affine_get]
theorem merkle_full_auth512 : tree_auth_values toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 512 = List.replicate 9 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 512 (by simp [leaves]) (by decide)
theorem merkle_full_auth4294967295 : tree_auth_values toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 4294967295 = List.replicate 9 (List.replicate 16 0) := by
  exact auth_outside toy (List.replicate 32 0) 4294967295 18446744073709551615 2 0 9 (leaves 9) 4294967295 (by simp [leaves]) (by decide)
end Extracted.C10FunctionalBuildFixtures
