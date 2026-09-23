require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid FullSession FullFailure.
lemma checked_failed_query (O <: PrefixOracle {-FullSession}) g c messages :
  hoare[FullSession(O).sign : FullSession.failed /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages ==>
    res = None /\ FullSession.failed /\ (glob O) = g /\
    FullSession.sign_calls = c /\ FullSession.signed_messages = messages].
proof. exact (full_failed_query_stops O g c messages). qed.
