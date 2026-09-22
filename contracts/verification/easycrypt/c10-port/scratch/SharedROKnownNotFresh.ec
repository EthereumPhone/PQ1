require import AllCore List Distr DBool SharedROBounded.
lemma erased_history :
  mu1 (ro_search dbool idfun [(0,false)] [0]) None = 1%r/2%r.
proof. by rewrite replay_failed_answer 1:// dunit1E /=. qed.
