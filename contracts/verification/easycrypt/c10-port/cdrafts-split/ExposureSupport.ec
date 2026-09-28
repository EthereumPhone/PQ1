(* Every actual returned output retains both construction references. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawForest FullSession ExposureLog.
require import PersistentGrind AcceptedContexts ForestReferenceHistory.
require import HonestForestMessages HonestSubtreeMessages SignerForestReference SignerSubtreeReference.

op exposure_supported h s seed root (entry : signing_exposure) =
  returned_forest_reference h s seed root entry.`1 entry.`2 /\
  returned_subtree_reference h s seed root entry.`1 entry.`2.
op exposures_supported h s seed root (entries : signing_exposure list) =
  forall entry, List.mem entries entry => exposure_supported h s seed root entry.

lemma returned_forest_extends h h' s s' seed root message signature :
  extends h h' => extends s s' => returned_forest_reference h s seed root message signature =>
  returned_forest_reference h' s' seed root message signature.
proof.
  move=> hh hs [d [ha [he hf]]]; exists d.
  have hf' := signed_forest_extends h h' s s' seed d signature hh hs hf.
  move: hh; rewrite /extends; smt().
qed.
lemma returned_subtree_extends h h' s s' seed root message signature :
  extends h h' => extends s s' => returned_subtree_reference h s seed root message signature =>
  returned_subtree_reference h' s' seed root message signature.
proof.
  move=> hh hs [d [ha [he hf]]]; exists d.
  have hf' := signed_subtree_extends h h' s s' seed (hypertree_index d) signature.`4 hh hs hf.
  move: hh; rewrite /extends; smt().
qed.
lemma exposures_supported_extends h h' s s' seed root entries :
  extends h h' => extends s s' => exposures_supported h s seed root entries =>
  exposures_supported h' s' seed root entries.
proof.
  rewrite /exposures_supported /exposure_supported.
  smt(returned_forest_extends returned_subtree_extends).
qed.
lemma exposures_supported_rcons h s seed root entries entry :
  exposures_supported h s seed root (rcons entries entry) =
  (exposures_supported h s seed root entries /\ exposure_supported h s seed root entry).
proof. rewrite /exposures_supported; smt(mem_rcons). qed.

lemma full_sign_exposure_entry seed0 root0 message0 :
  hoare [FullSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 ==>
    res<>None => exposure_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res)].
proof.
  conseq (full_sign_forest_entry seed0 root0 message0)
    (full_sign_subtree_entry seed0 root0 message0); rewrite /exposure_supported; smt().
qed.

lemma full_sign_exposure_history seed0 root0 message0 s0 h0 :
  hoare [FullSession(Independent).sign :
    FullSession.seed=seed0 /\ FullSession.root=root0 /\ message=message0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => exposure_supported Independent.rawhistory Independent.secrethistory
      seed0 root0 (message0,oget res))].
proof.
  conseq (full_sign_histories s0 h0) (full_sign_exposure_entry seed0 root0 message0); smt().
qed.
