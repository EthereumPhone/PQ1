(* The actual returned complete signature accounts for its selected chain disclosure. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid RawKeygen RawSigner RoleGrind.
require import PersistentGrind AcceptedContexts GrindReturned SignerReturned ForestReferenceHistory.
require import ChainValueView ChainStageSampling CachedChainOracle ChainSignerView.
require import ObservedValueOpening ObservedPrivateOpening ObservedCutEvidence ObservedFinishOpening.
require import ObservedComponentProjection ObservedReferenceTransfer.

op returned_cut_opened h s seed root message (signature : raw_signature) layer tree kp index cut =
  exists d, h.[hmsg_input seed root (pad signature.`1) message]=Some d /\
    signed_cut_opened h s seed (RawForest.hypertree_index d) signature.`4 layer tree kp index cut.
lemma returned_cut_opened_extends h h' s s' seed root message signature layer tree kp index cut :
  extends h h' => extends s s' => returned_cut_opened h s seed root message signature layer tree kp index cut =>
  returned_cut_opened h' s' seed root message signature layer tree kp index cut.
proof.
  move=> hh hs [d [hd ho]]; exists d; split.
  + move: hh; rewrite /extends; smt().
  exact (signed_cut_opened_extends h h' s s' seed (RawForest.hypertree_index d)
    signature.`4 layer tree kp index cut hh hs ho).
qed.
lemma observed_raw_grind_projection :
  equiv[RoleGrind(ChainPrefix(ObservedChain(Independent))).run ~ RoleGrind(Independent).run :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. symmetry; conseq ObservedComponentProjection.observed_grind_projection; smt(). qed.
lemma observed_grind_returned seed0 root0 message0 :
  hoare[RoleGrind(ChainPrefix(ObservedChain(Independent))).run :
    seed=seed0 /\ root=root0 /\ message=message0 ==>
    returned_digest_entry Independent.rawhistory seed0 root0 message0 res].
proof.
  conseq observed_raw_grind_projection (grind_returned_entry seed0 root0 message0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (random{m},message{m},seed{m},root{m}); smt().
  smt().
qed.
lemma observed_grind_returned_unopened seed0 root0 message0 opened0 :
  hoare[RoleGrind(ChainPrefix(ObservedChain(Independent))).run :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainRevelation.opened=opened0 ==>
    returned_digest_entry Independent.rawhistory seed0 root0 message0 res /\ ChainRevelation.opened=opened0].
proof. conseq (observed_grind_returned seed0 root0 message0) (observed_grind_unopened opened0); smt(). qed.
lemma observed_finish_entry randomizer0 x0 d0 :
  hoare[ChainSigner(ObservedChain(Independent)).finish :
    randomizer=randomizer0 /\ Independent.rawhistory.[x0]=Some d0 ==>
    Independent.rawhistory.[x0]=Some d0 /\ (res<>None => (oget res).`1=randomizer0)].
proof.
  conseq observed_raw_finish_projection (finish_keeps_randomizer_entry randomizer0 x0 d0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},randomizer{m},digest{m},shuffle{m}); smt().
  smt().
qed.
lemma observed_finish_entry_opening seed0 digest0 opened0 randomizer0 x0 :
  hoare[ChainSigner(ObservedChain(Independent)).finish :
    seed=seed0 /\ digest=digest0 /\ randomizer=randomizer0 /\ Independent.rawhistory.[x0]=Some digest0 /\
    ChainStage.seed=seed0 /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    Independent.rawhistory.[x0]=Some digest0 /\ (res<>None => (oget res).`1=randomizer0 /\
      (ChainRevelation.opened => opened0 \/ signed_cut_opened Independent.rawhistory Independent.secrethistory
        seed0 (RawForest.hypertree_index digest0) (oget res).`4
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut))].
proof.
  conseq (observed_finish_opening seed0 digest0 opened0) (observed_finish_entry randomizer0 x0 digest0); smt().
qed.
lemma observed_signer_opening seed0 root0 message0 opened0 :
  hoare[ChainSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    res<>None => ChainRevelation.opened => opened0 \/
      returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0
        (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof.
  proc; seq 1 : (seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    returned_digest_entry Independent.rawhistory seed0 root0 message0 accepted).
  + call (observed_grind_returned_unopened seed0 root0 message0 opened0); auto.
  sp 1; if; last by auto.
  exists* accepted; elim* => acc.
  call (observed_finish_entry_opening seed0 (oget acc).`2 opened0 (oget acc).`1
    (hmsg_input seed0 root0 (pad (oget acc).`1) message0)).
  auto; rewrite /returned_digest_entry /returned_cut_opened /pad; smt().
qed.
lemma observed_signer_histories s0 h0 :
  hoare[ChainSigner(ObservedChain(Independent)).sign :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  conseq observed_raw_sign_projection (complete_signer_histories RawSigner s0 h0).
  + move=> &m hm; exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},root{m},random{m},message{m},shuffle{m}); smt().
  smt().
qed.
lemma observed_signer_history_opening seed0 root0 message0 opened0 s0 h0 :
  hoare[ChainSigner(ObservedChain(Independent)).sign :
    seed=seed0 /\ root=root0 /\ message=message0 /\ ChainStage.seed=seed0 /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res<>None => ChainRevelation.opened => opened0 \/
      returned_cut_opened Independent.rawhistory Independent.secrethistory seed0 root0 message0
        (oget res) ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)].
proof.
  conseq (observed_signer_opening seed0 root0 message0 opened0) (observed_signer_histories s0 h0); smt().
qed.
