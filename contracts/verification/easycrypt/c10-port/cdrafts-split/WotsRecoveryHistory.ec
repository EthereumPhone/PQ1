(* Public-only recovery preserves reference keys and the actual recovery trace. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind AcceptedContexts MonotoneHistory RawCountRecorded.
require import WotsReferenceRoot WotsRecoveryTrace RawRecoveryTrace RecoveryHistory LayerPath.

lemma wots_recovery_keeps_root (R <: WotsRecovery {-Independent}) seed0 layer0 tree0 kp0 root0 :
  hoare [R(PreparationView(Independent)).recover :
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0].
proof.
  proc (wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0) => //.
  exact (hash_keeps_wots_root seed0 layer0 tree0 kp0 root0).
qed.

lemma wots_recovery_extends (R <: WotsRecovery {-Independent}) s0 h0 :
  hoare [R(PreparationView(Independent)).recover :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.

lemma recovery_trace_extends h h' seed layer tree kp message sigma count result :
  extends h h' => wots_recovery_trace h seed layer tree kp message sigma count result =>
  wots_recovery_trace h' seed layer tree kp message sigma count result.
proof.
  move=> hh [d [hd ht]]; exists d; split.
  + move: hh; rewrite /extends; smt(domE).
  case (count_accepts d) => ha; last by smt().
  have [hp [leaf [hl he]]] : recovery_prefix h seed layer tree kp d sigma 43 /\
    exists leaf, h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf /\ result=node leaf by smt().
  have [hp' hv] := recovery_prefix_extends h h' seed layer tree kp d sigma 43 hh hp.
  split; first exact hp'.
  exists leaf; rewrite /recovery_leaf_input hv; move: hh hl;
    rewrite /extends /recovery_leaf_input; smt(domE).
qed.

lemma recovery_trace_width h seed layer tree kp message sigma count result :
  wots_recovery_trace h seed layer tree kp message sigma count result => size result=16.
proof. rewrite /wots_recovery_trace; smt(node_width size_nseq). qed.

lemma hash_keeps_recovery_trace seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 :
  hoare [Independent.hash :
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 ==>
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0].
proof. proc; sp 1; if; auto; smt(recovery_trace_extends extends_insert). qed.

lemma merkle_keeps_recovery_trace (R <: MerkleRecovery {-Independent})
    seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 :
  hoare [R(PreparationView(Independent)).recover :
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0 ==>
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0].
proof.
  proc (wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 result0) => //.
  exact (hash_keeps_recovery_trace seed0 layer0 tree0 kp0 message0 sigma0 count0 result0).
qed.

lemma merkle_keeps_wots_root (R <: MerkleRecovery {-Independent}) seed0 layer0 tree0 kp0 root0 :
  hoare [R(PreparationView(Independent)).recover :
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0 ==>
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0].
proof.
  proc (wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 root0) => //.
  exact (hash_keeps_wots_root seed0 layer0 tree0 kp0 root0).
qed.
