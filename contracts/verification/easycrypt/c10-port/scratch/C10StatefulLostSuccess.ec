require import AllCore List Distr DBool C10StatefulSearch.
lemma successful_answer_not_recorded :
  search_state dbool predT [] [0] = dmap dbool (fun b => (Some b,[])).
proof.
  by rewrite /search_state /= assoc_nil /predT /= /dmap.
qed.
