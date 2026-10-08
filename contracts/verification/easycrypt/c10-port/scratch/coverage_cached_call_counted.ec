require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess PrefixHybrid AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts.
lemma cached_accepted_count c x0 (d : digest) : accept_digest d =>
  hoare[HmsgMemo(AcceptedSamples).hash :
    x=x0 /\ size x0=160 /\ HmsgMemo.rawhistory.[x0]=Some d /\ HmsgMemo.accepted_calls=c ==>
    HmsgMemo.accepted_calls=c+1].
proof. move=> hd; proc; rcondf 2; first by auto; smt(domE).
  auto; rewrite /b2i.
  by move=> &m [hx [hw [hh hc]]]; rewrite hx hh /= hd /= hc. qed.
