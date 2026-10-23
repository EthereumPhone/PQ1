(* Shared construction recurrences; these do not specify oracle scheduling. *)
require import AllCore List IntDiv StdOrder.
require import C10Representation.
import IntOrder.

lemma functional_build_fold f seed layer tree kind kp total leaves n :
  tree_nodes_value f seed layer tree kind kp total n leaves =
    foldl (fun nodes i => tree_level_value f seed layer tree kind kp total (i+1) nodes)
      leaves (mkseq (fun i => i) n).
proof. by rewrite /tree_nodes_value -foldl_rev revK. qed.

lemma functional_build_zero f seed layer tree kind kp total leaves :
  tree_nodes_value f seed layer tree kind kp total 0 leaves = leaves.
proof. by rewrite functional_build_fold mkseq0. qed.

lemma functional_build_next f seed layer tree kind kp total leaves n : 0 <= n =>
  tree_nodes_value f seed layer tree kind kp total (n+1) leaves =
    tree_level_value f seed layer tree kind kp total (n+1)
      (tree_nodes_value f seed layer tree kind kp total n leaves).
proof. by move=> hn; rewrite !functional_build_fold mkseqS 1:hn foldl_rcons. qed.

lemma functional_level_size f seed layer tree kind kp total height nodes :
  size (tree_level_value f seed layer tree kind kp total height nodes) =
    2^(max 0 (total-height)).
proof.
  rewrite /tree_level_value size_mkseq.
  have hp : 0 < 2^(max 0 (total-height)) by apply expr_gt0.
  smt().
qed.

lemma functional_build_size f seed layer tree kind kp total leaves n :
  0 <= total => 0 <= n => size leaves = 2^total =>
  size (tree_nodes_value f seed layer tree kind kp total n leaves) =
    2^(max 0 (total-n)).
proof.
  move=> ht hn hl; case (n=0) => hz.
  + by rewrite hz functional_build_zero hl; congr; smt().
  have hs : n=(n-1)+1 by ring.
  by rewrite hs functional_build_next 1:/# functional_level_size; congr; ring.
qed.

lemma functional_auth_size f seed layer tree kind kp total leaves target : 0 <= total =>
  size (tree_auth_values f seed layer tree kind kp total leaves target) = total.
proof. by move=> ht; rewrite /tree_auth_values size_mkseq; smt(). qed.

lemma functional_level_nth f seed layer tree kind kp total height nodes i :
  0 <= i < 2^(max 0 (total-height)) =>
  nth (nseq 16 0) (tree_level_value f seed layer tree kind kp total height nodes) i =
    tree_pair_value f seed (address_words layer tree kind kp 0 height i)
      (nth (nseq 16 0) nodes (2*i)) (nth (nseq 16 0) nodes (2*i+1)).
proof. by move=> hi; rewrite /tree_level_value nth_mkseq 1:hi. qed.

lemma functional_root_value f seed layer tree kind kp total leaves :
  tree_root_value f seed layer tree kind kp total leaves =
    nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total total leaves) 0.
proof. by rewrite /tree_root_value. qed.

lemma functional_sibling_outside q b :
  b %% 2 = 0 => b <= q => b <= (if q %% 2 = 0 then q+1 else q-1).
proof. smt(). qed.

lemma functional_sibling_inside q b :
  b %% 2 = 0 => 0 <= q < b =>
  0 <= (if q %% 2 = 0 then q+1 else q-1) < b.
proof.
  have := modz_ge0 q 2; have := ltz_pmod q 2.
  have := modz_ge0 b 2; have := ltz_pmod b 2.
  have := divz_eq q 2; have := divz_eq b 2; smt().
qed.

lemma functional_power_even n : 0 < n => (2^n) %% 2 = 0.
proof. by move=> hn; rewrite (_ : n=(n-1)+1) 1:/# exprS 1:/# modzMr. qed.

lemma functional_auth_nth f seed layer tree kind kp total leaves target h :
  0 <= h < total =>
  nth (nseq 16 0) (tree_auth_values f seed layer tree kind kp total leaves target) h =
    nth (nseq 16 0) (tree_nodes_value f seed layer tree kind kp total h leaves)
      (max 0 (if (target %/ (2^h)) %% 2 = 0 then target %/ (2^h)+1
              else target %/ (2^h)-1)).
proof. by move=> hh; rewrite /tree_auth_values nth_mkseq 1:hh. qed.

lemma functional_auth_outside_nth f seed layer tree kind kp total leaves target h :
  0 <= h < total => size leaves = 2^total => 2^total <= target =>
  nth (nseq 16 0) (tree_auth_values f seed layer tree kind kp total leaves target) h =
    nseq 16 0.
proof.
  move=> hh hl ht.
  have hp : 0 < 2^h by apply expr_gt0.
  have he : 2^(total-h)*2^h = 2^total by rewrite -exprD_nneg 1,2:/#; congr; ring.
  have hq : 2^(total-h) <= target %/ (2^h) by rewrite lez_divRL 1:hp he.
  have hb := functional_power_even (total-h) _; first by smt().
  have hs := functional_sibling_outside (target %/ (2^h)) (2^(total-h)) hb hq.
  rewrite functional_auth_nth 1:hh nth_out; first last.
  + done.
  rewrite functional_build_size 1,2:/# 1:hl; smt().
qed.

lemma functional_auth_outside f seed layer tree kind kp total leaves target :
  0 <= total => size leaves = 2^total => 2^total <= target =>
  tree_auth_values f seed layer tree kind kp total leaves target = nseq total (nseq 16 0).
proof.
  move=> hh hl ht; apply (eq_from_nth (nseq 16 0)).
  + by rewrite functional_auth_size 1:hh size_nseq; smt().
  move=> h; rewrite functional_auth_size 1:hh => hi.
  have hv := functional_auth_outside_nth f seed layer tree kind kp total leaves target h hi hl ht.
  by rewrite hv nth_nseq; smt().
qed.
