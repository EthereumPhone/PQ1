require import AllCore List PrefixGuess FullSession TargetTableProjection TargetSessionOpenings.
lemma failed_session_accepts :
 hoare [TargetSession(ObservedTarget(Independent)).sign : FullSession.failed ==> !FullSession.failed].
proof. proc; sp 1; rcondf 1; first by auto; smt().
 by auto.
qed.
