require import AllCore List Distr DBool SharedROBounded BoundedIID.
lemma repeated_input_is_two_trials :
  mu1 (ro_search dbool idfun [] [0;0]) None = 1%r/4%r.
proof.
  have he : ro_search dbool idfun [] [0;0] = bounded dbool idfun [tt].
  + rewrite /ro_search /bounded /= !assoc_nil ?assoc_cons /=; apply eq_dlet => // b.
    by case: b.
  by rewrite he bounded_exhaustion 1:dbool_ll /= dboolE /idfun /= RField.expr1.
qed.
