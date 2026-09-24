require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer RawSignature.
require import MerkleRootWitness PersistentGrind AcceptedContexts SignerComponentHistory.
require import RootLayerExtraction VerifierWotsOpening MemoNodeCollision PublicNodeZero.

lemma layer_extracts_from_retained_root seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) root0 h0 s0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=kp0 /\ message=message0 /\ sig=sig0 /\
    0<=kp0<512 /\ layer_width sig0 /\
    merkle_root_witness h0 s0 seed0 layer0 tree0 root0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory /\
    (res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists leaf0, wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2))].
proof.
  conseq (layer_extracts_from_root seed0 layer0 tree0 kp0 message0 sig0 root0)
    (layer_recovery_extends RawLayer s0 h0); smt(merkle_root_witness_extends).
qed.
