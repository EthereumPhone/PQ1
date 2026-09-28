require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind FORSC10Digest.
lemma cached_is_not_fresh (h : (raw_input,digest) fmap) (x0 : raw_input) :
  phoare[Shared.hash : Shared.history = h /\ x = x0 ==> accept_digest res] = ((inv 2%r)^11).
proof. exact (fresh_hash_acceptance h x0). qed.
