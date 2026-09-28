(* A retained WOTS root remains the same under both oracle table extensions. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts WotsReference WotsLeafReference RawCountRecorded.

op wots_root h s seed layer tree kp root =
  wots_prefix h s seed layer tree kp 43 /\
  exists d, h.[wots_leaf_input h s seed layer tree kp]=Some d /\ root=node d.

lemma wots_root_extends h h' s s' seed layer tree kp root :
  extends h h' => extends s s' => wots_root h s seed layer tree kp root =>
  wots_root h' s' seed layer tree kp root.
proof.
  move=> hh hs [hp [d [hd hv]]].
  have [hp' he] := wots_prefix_extends h h' s s' seed layer tree kp 43 hh hs hp.
  rewrite /wots_root; split; first exact hp'.
  exists d; rewrite /wots_leaf_input he; move: hh hd; rewrite /extends /wots_leaf_input; smt().
qed.

lemma hash_keeps_wots_root seed0 layer0 tree0 kp0 root0 :
  hoare [Independent.hash :
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0].
proof. proc; sp 1; if; auto; smt(wots_root_extends extends_insert extends_refl). qed.

lemma count_keeps_wots_root seed0 layer0 tree0 kp0 root0 :
  hoare [RawWots(PreparationView(Independent)).count :
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0].
proof.
  proc; while (wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0).
  + wp; call (hash_keeps_wots_root seed0 layer0 tree0 kp0 root0); auto.
  auto.
qed.
