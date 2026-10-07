(* Termination of the factored signer for any lossless leaf backend. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawFors RawForest RawShuffle RawLayer RawSigner RoleGrind PreparedGrind RoleGrindCost.
require import ForsLeafView LeafForestView LeafSignerView.

lemma leaf_fors_tree_lossless (F <: ForsLeafOracle) :
  islossless F.hash => islossless F.leaf => islossless LeafFors(F).tree.
proof.
  move=> hh hf; proc; while true (2048-j).
  + move=> z; wp; while true (size stack).
    - move=> z'; wp; call hh; auto; smt(size_behead size_ge0 size_eq0).
    wp; call hf; auto; smt(size_ge0).
  auto; smt().
qed.
lemma leaf_fors_root_lossless (F <: ForsLeafOracle) :
  islossless F.hash => islossless F.leaf => islossless LeafFors(F).root.
proof. move=> hh hl; proc; call (leaf_fors_tree_lossless F hh hl); auto. qed.
lemma leaf_fors_sign_lossless (F <: ForsLeafOracle) :
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafFors(F).sign.
proof.
  move=> hh hl hs; proc; call (leaf_fors_tree_lossless F hh hl); call hs; auto.
qed.
lemma leaf_forest_one_lossless (O <: PreparationOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless LeafForest(O,F).one.
proof.
  move=> oh fh fl fs; proc; call (fors_recover_lossless O oh).
  call (leaf_fors_sign_lossless F fh fl fs); auto.
qed.
lemma leaf_forest_sign_lossless (O <: PreparationOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless LeafForest(O,F).sign.
proof.
  move=> oh fh fl fs; proc; call oh; wp; call oh; wp.
  call (leaf_fors_root_lossless F fh fl); wp.
  while true (12-step).
  + move=> z; wp; call (leaf_forest_one_lossless O F oh fh fl fs); auto; smt().
  wp; call (shuffle_permutation_lossless O oh); call (shuffle_derive_lossless O oh); auto; smt().
qed.
lemma leaf_signer_finish_lossless (O <: PrefixOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafSigner(O,F).finish.
proof.
  move=> oh od fh fl fs; have [#] vh vw vf := preparation_view_lossless O oh od.
  proc; wp; while true (2-layer).
  + move=> z; wp; call (layer_sign_lossless (PreparationView(O)) vh vw); auto; smt().
  wp; call (leaf_forest_sign_lossless (PreparationView(O)) F vh fh fl fs); auto; smt().
qed.
lemma leaf_signer_sign_lossless (O <: PrefixOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless O.derive =>
  islossless F.hash => islossless F.leaf => islossless F.secret => islossless LeafSigner(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless O oh od); auto.
  sp 1; if; auto; call (leaf_signer_finish_lossless O F oh od fh fl fs); auto.
qed.
