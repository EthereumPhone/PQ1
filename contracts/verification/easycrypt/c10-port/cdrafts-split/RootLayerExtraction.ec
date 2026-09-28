(* The selected recovery index need not be known when the root was built. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawLayer RawSignature.
require import MerkleRootWitness RootCoverage LayerWotsExtraction VerifierWotsOpening.
require import MemoNodeCollision PublicNodeZero.

lemma layer_extracts_from_root seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) root0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=kp0 /\ message=message0 /\ sig=sig0 /\
    0<=kp0<512 /\ layer_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists leaf0, wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2)].
proof.
  conseq (_ : exists leaf0 auth0,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=kp0 /\ message=message0 /\ sig=sig0 /\
    layer_width sig0 /\ rows_width 9 auth0 /\
    WotsReferenceRoot.wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    LayerPath.layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 auth0 root0 ==> _).
  + move=> &m hp.
    have hw : merkle_root_witness Independent.rawhistory{m} Independent.secrethistory{m}
      seed0 layer0 tree0 root0 by smt().
    have ht : 0<=kp0<512 by smt().
    have [leaf0 auth0 hh] := root_reference_at Independent.rawhistory{m}
      Independent.secrethistory{m} seed0 layer0 tree0 root0 kp0 hw ht.
    exists leaf0 auth0; smt().
  elim* => leaf0 auth0.
  conseq (raw_layer_extracts_wots_opening seed0 layer0 tree0 kp0 message0 sig0 leaf0 auth0 root0); smt().
qed.
