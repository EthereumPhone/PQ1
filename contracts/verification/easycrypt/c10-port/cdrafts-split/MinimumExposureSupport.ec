(* Minimal counts for every retained response, preserved by adaptive extensions. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid FullSession ExposureLog.
require import PersistentGrind ForestReferenceHistory SignerMinimumCounts HonestMinimumCounts.

op minimum_entry h s seed root (entry : signing_exposure) =
  returned_minimum_counts h s seed root entry.`1 entry.`2.
op minimum_entries h s seed root (entries : signing_exposure list) =
  forall entry, mem entries entry => minimum_entry h s seed root entry.

lemma returned_minimum_extends h h' s s' seed root message signature :
  extends h h' => extends s s' => returned_minimum_counts h s seed root message signature =>
  returned_minimum_counts h' s' seed root message signature.
proof.
  move=> hh hs [d [ha [he hc]]]; exists d.
  have hc' := signed_minimum_extends h h' s s' seed (RawForest.hypertree_index d) signature.`4 hh hs hc.
  move: hh; rewrite /extends; smt().
qed.
lemma minimum_entries_extends h h' s s' seed root entries :
  extends h h' => extends s s' => minimum_entries h s seed root entries =>
  minimum_entries h' s' seed root entries.
proof. rewrite /minimum_entries /minimum_entry; smt(returned_minimum_extends). qed.
lemma minimum_entries_rcons h s seed root entries entry :
  minimum_entries h s seed root (rcons entries entry) =
  (minimum_entries h s seed root entries /\ minimum_entry h s seed root entry).
proof. rewrite /minimum_entries; smt(mem_rcons). qed.
lemma full_sign_minimum_history seed0 root0 message0 s0 h0 :
  hoare [FullSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => minimum_entry Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res))].
proof.
  conseq (full_sign_histories s0 h0) (full_sign_minimum_entry seed0 root0 message0);
    rewrite /minimum_entry; smt().
qed.
