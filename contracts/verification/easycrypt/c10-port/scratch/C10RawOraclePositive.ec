require import AllCore List Distr DBool FMap.
require import C10RawOracle C10RawGrind C10StatefulSearch FORSC10Digest.
lemma checked_replay h x0 y c d :
  h.[x0] = Some y =>
  hoare[Shared.hash : Shared.history = h /\ x = x0 /\ Shared.calls = c /\ Shared.draws = d ==>
    res = y /\ Shared.history = h /\ Shared.calls = c+1 /\ Shared.draws = d].
proof. exact (hash_replay h x0 y c d). qed.
lemma checked_raw_cost c0 d0 :
  hoare[StatefulGrind(Shared).run : Shared.calls = c0 /\ Shared.draws = d0 ==>
    c0 <= Shared.calls <= c0 + 2*C10Counter.signing_budget /\
    d0 <= Shared.draws <= d0 + 2*C10Counter.signing_budget].
proof. exact (grind_cost c0 d0). qed.
lemma checked_fresh_mass (h : (raw_input,digest) fmap) (x0 : raw_input) :
  x0 \notin h =>
  phoare[Shared.hash : Shared.history = h /\ x = x0 ==> accept_digest res] = ((inv 2%r)^11).
proof. exact (fresh_hash_acceptance h x0). qed.
lemma cached_failure_replays :
  search_state dbool idfun [(0,false)] [0] = dunit (None,[(0,false)]).
proof. by apply (repeated_failure dbool idfun [(0,false)] 0 false); rewrite ?assoc_cons /=. qed.

lemma successful_answer_recorded :
  search_state dbool predT [] [0] = dmap dbool (fun b => (Some b,[(0,b)])).
proof.
  by rewrite /search_state /= assoc_nil /predT /= /dmap.
qed.
