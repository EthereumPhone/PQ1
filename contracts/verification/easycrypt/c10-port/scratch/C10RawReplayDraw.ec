require import AllCore List Distr FMap C10RawOracle.
lemma replay_draws_again h x0 y c d :
  h.[x0] = Some y =>
  hoare[Shared.hash : Shared.history = h /\ x = x0 /\ Shared.calls = c /\ Shared.draws = d ==>
    res = y /\ Shared.history = h /\ Shared.calls = c+1 /\ Shared.draws = d+1].
proof. move=> hy; conseq (hash_replay h x0 y c d hy); by trivial. qed.
