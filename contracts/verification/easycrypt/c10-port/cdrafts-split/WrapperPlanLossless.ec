(* The late-opening view terminates for arbitrary lossless oracle backends;
   successful grinding, readiness and final release are not premises. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion PreparedGrind.
require import RawKeygen RawFors RawShuffle RawLayer RawSigner RoleGrind RoleGrindCost.
require import ForsLeafView LeafViewLossless.
require import WrapperForsPlan WrapperForestPlan WrapperForestRelease WrapperSigningPlan WrapperPlanSigner WrapperReleasedFors.

lemma wrapper_fors_plan_lossless (F <: ForsLeafOracle) :
  islossless F.hash => islossless F.leaf => islossless WrapperForsPublicPlan(F).one.
proof. move=> hh hl; proc; call (leaf_fors_tree_lossless F hh hl); auto. qed.

lemma wrapper_forest_plan_lossless (O <: PreparationOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless F.hash => islossless F.leaf =>
  islossless WrapperForestPlan(O,F).sign.
proof.
  move=> oh fh fl; proc; call oh; wp; call oh.
  call (leaf_fors_root_lossless F fh fl).
  while true (12-step).
  + move=> z; wp; call (wrapper_fors_plan_lossless F fh fl); auto; smt().
  wp; call (shuffle_permutation_lossless O oh); call (shuffle_derive_lossless O oh); auto; smt().
qed.

lemma wrapper_finish_plan_lossless (O <: PrefixOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf =>
  islossless WrapperSigningPlan(O,F).finish.
proof.
  move=> oh od fh fl; have [#] vh vw vf := preparation_view_lossless O oh od.
  proc; wp; while true (2-layer).
  + move=> z; wp; call (layer_sign_lossless (PreparationView(O)) vh vw); auto; smt().
  wp; call (wrapper_forest_plan_lossless (PreparationView(O)) F vh fh fl); auto; smt().
qed.

lemma wrapper_sign_plan_lossless (O <: PrefixOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf =>
  islossless WrapperPlanSigner(O,F).sign.
proof.
  move=> oh od fh fl; proc; seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (role_grind_lossless O oh od); auto.
  sp 1; if; auto; call (wrapper_finish_plan_lossless O F oh od fh fl); auto.
qed.

lemma wrapper_released_fors_lossless (O <: PrefixOracle) (F <: ForsLeafOracle) :
  islossless O.hash => islossless O.derive => islossless F.hash => islossless F.leaf => islossless F.secret =>
  islossless WrapperReleasedFors(O,F).sign.
proof.
  move=> oh od fh fl fs; proc; sp 1; if; last auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (wrapper_sign_plan_lossless O F oh od fh fl); auto.
  if; last auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (wrapper_sign_plan_lossless O F oh od fh fl); auto.
  if; last auto.
  if; last auto.
  wp; call (wrapper_forest_release_ll F fs); auto.
qed.
