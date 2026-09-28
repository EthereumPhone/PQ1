(* Deployed two-layer geometry. The nonadaptive hypertree experiment signs
   every index in [0,l), so its union of paths covers the precomputed cube.
   This is address coverage, not the missing probability/game coupling. *)
require import AllCore List IntDiv.
require import SPHINCS_PLUS.
import SPHINCS_PLUS FSSLXMTWES.

(* Derive geometry directly from the model. C10DeployedScope is a quarantined
   policy-cap leaf and must not be imported by reusable proof consumers. *)
lemma pow2_9 : 2 ^ 9 = 512.
proof.
by rewrite (_ : 9 = 8 + 1) 1:// exprS 1://
           (_ : 8 = 7 + 1) 1:// exprS 1://
           (_ : 7 = 6 + 1) 1:// exprS 1://
           (_ : 6 = 5 + 1) 1:// exprS 1://
           (_ : 5 = 4 + 1) 1:// exprS 1://
           (_ : 4 = 3 + 1) 1:// exprS 1://
           (_ : 3 = 2 + 1) 1:// exprS 1://
           (_ : 2 = 1 + 1) 1:// exprS 1:// expr1.
qed.

lemma ht_capacity : l = 262144.
proof.
  by rewrite /l /SPHINCS_PLUS.h hp_val d_val /=
    (_ : 18 = 9 + 9) 1:// exprD_nneg 1,2:// pow2_9.
qed.

op path_cell (idx layer : int) : int * int =
  edivz (if layer = 0 then idx else idx %/ l') l'.

op covering_index (layer tree key : int) : int =
  (tree * l' + key) * (if layer = 0 then 1 else l').

(* The fold is the repeated edivz operation used by the actual signer and
   precomputed-leaf reduction; this closes the pure indexing correspondence. *)
lemma path_cell_fold (idx layer : int) :
  0 <= layer < d => path_cell idx layer =
    fold (fun tk : int * int => edivz tk.`1 l') (idx,0) (layer+1).
proof.
  rewrite d_val => hl; have hc : layer = 0 \/ layer = 1 by smt().
  case: hc => ->.
  + by rewrite /path_cell foldS 1:// fold0.
  by rewrite /path_cell foldS 1:// (_ : 1 = 0+1) 1:// foldS 1:// fold0.
qed.

lemma subtree_width : l' = 512.
proof. by rewrite /l' hp_val pow2_9. qed.

lemma tree_count (layer : int) :
  0 <= layer < d => nr_trees layer = (if layer = 0 then 512 else 1).
proof.
  rewrite d_val => hl; have hc : layer = 0 \/ layer = 1 by smt().
  case: hc => ->; by rewrite /nr_trees hp_val d_val /= ?pow2_9 ?expr0.
qed.

lemma covering_index_range (layer tree key : int) :
  0 <= layer < d => 0 <= tree < nr_trees layer => 0 <= key < l' =>
  0 <= covering_index layer tree key < l.
proof.
  move=> hl; rewrite tree_count 1:hl subtree_width
    /covering_index subtree_width ht_capacity.
  by case (layer = 0); smt().
qed.

lemma covering_index_cell (layer tree key : int) :
  0 <= layer < d => 0 <= tree < nr_trees layer => 0 <= key < l' =>
  path_cell (covering_index layer tree key) layer = (tree, key).
proof.
  move=> hl; rewrite tree_count 1:hl subtree_width
    /covering_index /path_cell subtree_width.
  case (layer = 0) => he ht hk /=.
  + have hq := edivz_eq 512 tree key hk.
    have hr := emodz_eq 512 tree key hk.
    move: hq hr; by case: (edivz (tree * 512 + key) 512) => q r /= -> ->.
  rewrite mulzK 1://.
  have hq := edivz_eq 512 tree key hk.
  have hr := emodz_eq 512 tree key hk.
  move: hq hr; by case: (edivz (tree * 512 + key) 512) => q r /= -> ->.
qed.

(* This implication needs ALL l paths. A single signing path cannot justify it. *)
lemma all_paths_cover_cube (good : int -> int -> int -> bool) :
  (forall idx layer, 0 <= idx < l => 0 <= layer < d =>
    good layer (path_cell idx layer).`1 (path_cell idx layer).`2) =>
  forall layer tree key, 0 <= layer < d =>
    0 <= tree < nr_trees layer => 0 <= key < l' => good layer tree key.
proof.
  move=> hp layer tree key hl ht hk.
  have := hp (covering_index layer tree key) layer
    (covering_index_range layer tree key hl ht hk) hl.
  by rewrite covering_index_cell.
qed.
