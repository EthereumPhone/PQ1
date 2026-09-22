require import AllCore List IntDiv.
require import SPHINCS_PLUS.
import SPHINCS_PLUS FSSLXMTWES.
require import C10HypertreeCoverage.

lemma checked_all_paths_cover_cube (good : int -> int -> int -> bool) :
  (forall idx layer, 0 <= idx < l => 0 <= layer < d =>
    good layer (path_cell idx layer).`1 (path_cell idx layer).`2) =>
  forall layer tree key, 0 <= layer < d =>
    0 <= tree < nr_trees layer => 0 <= key < l' => good layer tree key.
proof. exact all_paths_cover_cube. qed.
