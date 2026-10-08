(* The actual adaptive output's cut is covered by the persistent disclosure ledger. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes KeygenExhaustion RawKeygen RawSigner.
require import FullSession ByteSession ExposureLog ClientQueryLog VerifierHistory.
require import PersistentGrind AcceptedContexts MonotoneHistory.
require import ChainValueView ChainStageSampling CachedChainOracle ChainKeygenView ChainSessionView ChainByteCandidates.
require import ObservedValueOpening ObservedKeygenOpening ObservedSessionOpening ExposureCutEvidence.

lemma observed_verify_histories (V <: PublicVerifier {-Independent}) s0 h0 :
  hoare[V(ChainPrefix(ObservedChain(Independent))).verify :
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc (extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory) => //.
  exact (independent_hash_extends s0 h0).
qed.
lemma observed_driver_cut_accounted
  (A <: FullClient {-Independent,-FullSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare[ChainQueryDriver(A,ObservedChain(Independent)).run :
    ChainStage.seed=seed /\ valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    res => !FullSession.failed /\
      (ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)].
proof.
  proc; seq 5 : (session_cut_accounted Independent.rawhistory Independent.secrethistory
    FullSession.seed FullSession.root ExposureLog.entries
    ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut
    FullSession.failed ChainRevelation.opened).
  + call (observed_client_cut_accounted A); wp;
      inline FullSession(ChainPrefix(ObservedChain(Independent))).init;
      auto; rewrite /session_cut_accounted; smt().
  sp 2; if; last by auto.
  exists* Independent.secrethistory,Independent.rawhistory; elim* => s0 h0.
  call (observed_verify_histories RawSigner s0 h0); auto;
    rewrite /session_cut_accounted; smt(extends_refl exposure_cut_opened_extends).
qed.
lemma observed_preparation_unopened opened0 :
  hoare[ChainPreparation(ObservedChain(Independent)).run :
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ ChainRevelation.opened=opened0 ==>
    res.`3=ChainStage.seed /\ ChainRevelation.opened=opened0].
proof.
  proc; exists* ChainStage.seed; elim* => seed0.
  call (observed_root_unopened seed0 1 0 opened0); auto; rewrite /valid_chain_address; smt().
qed.
lemma observed_context_cut_accounted
  (A <: FullClient {-Independent,-FullSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare[ChainQueryContext(A,ObservedChain(Independent)).run :
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    res => !FullSession.failed /\
      (ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries
        ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut)].
proof.
  proc; call (observed_driver_cut_accounted A).
  call (observed_preparation_unopened false); auto; smt().
qed.
lemma observed_candidates_cut_accounted
  (A <: ByteClient {-Independent,-FullSession,-ExposureLog,-ClientQueryLog,-ChainStage,-ChainCut,-ChainRevelation}) :
  hoare[ChainByteCandidates(A,ObservedChain(Independent)).run :
    ChainStage.seed=pad(node KeygenInputs.public_seed) /\
    valid_chain_address ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index /\
    ChainCut.cut<7 /\ !ChainRevelation.opened ==>
    res<>[] => ChainRevelation.opened => exposure_cut_opened Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries
      ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index ChainCut.cut].
proof. proc; wp; call (observed_context_cut_accounted (ByteLift(A))); auto; smt(). qed.
