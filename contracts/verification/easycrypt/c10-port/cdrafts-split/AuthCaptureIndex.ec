(* The concrete sibling tests select the target's unique parent pair. *)
require import AllCore List IntDiv.
require import RawFors DyadicStack NodeGridIndex.

lemma sibling_parent_cases index :
  (index %% 2 = 0 /\ sibling_index index = 2*(index %/ 2)+1) \/
  (index %% 2 <> 0 /\ sibling_index index = 2*(index %/ 2)).
proof.
  rewrite /sibling_index.
  case (index %% 2 = 0) => hh;
    smt(child_index_even child_index_odd).
qed.

lemma sibling_pair_membership index parent :
  (sibling_index index = 2*parent \/ sibling_index index = 2*parent+1) <=>
  index %/ 2 = parent.
proof. have := sibling_parent_cases index; smt(). qed.

lemma merkle_left_index kp height :
  0 <= height =>
  ((kp %/ (2^(height+1))) * (2^(height+1))) %/ (2^height) =
    2*(kp %/ (2^(height+1))).
proof.
  move=> hh.
  have hp := pow2_pos height hh.
  rewrite {2}exprS 1:hh.
  rewrite (_ : kp %/ (2^(height+1)) * (2*2^height) =
    (2*(kp %/ (2^(height+1))))*2^height) 1:/#.
  rewrite mulzK; smt().
qed.

lemma merkle_capture_parent kp target height :
  0 <= height =>
  let left_index = ((kp %/ (2^(height+1))) * (2^(height+1))) %/ (2^height) in
  let sib = sibling_index (target %/ (2^height)) in
    (left_index = sib \/ left_index+1 = sib) <=>
    kp %/ (2^(height+1)) = target %/ (2^(height+1)).
proof.
  move=> hh; rewrite merkle_left_index 1:hh.
  have ht := dyadic_index_step target height hh.
  have := sibling_pair_membership (target %/ (2^height)) (kp %/ (2^(height+1)));
    smt().
qed.

lemma sibling_index_parity index :
  (sibling_index index) %% 2 = 0 <=> index %% 2 <> 0.
proof.
  have ho : forall q, (2*q+1) %% 2 = 1.
  + move=> q; rewrite (mulrC 2) modzMDl pmod_small; smt().
  have he : forall q, (2*q) %% 2 = 0 by move=> q; rewrite modzMr.
  have := sibling_parent_cases index; smt().
qed.

lemma fors_capture_parent kp target height :
  0 <= height =>
  let parent = kp %/ (2^(height+1)) in
  let sib = sibling_index (target %/ (2^height)) in
  ((if sib %% 2 = 0 then sib * 2^height = parent * 2^(height+1)
    else sib * 2^height = parent * 2^(height+1) + 2^height) <=>
    parent = target %/ (2^(height+1))).
proof.
  move=> hh.
  have hp := pow2_pos height hh.
  have hs := sibling_parent_cases (target %/ (2^height)).
  have hpar := sibling_index_parity (target %/ (2^height)).
  have ht := dyadic_index_step target height hh.
  have hpow : 2^(height+1) = 2*2^height by rewrite exprS.
  smt().
qed.
