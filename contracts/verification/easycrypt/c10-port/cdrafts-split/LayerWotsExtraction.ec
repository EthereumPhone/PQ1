(* A matching actual layer recovery exposes a verifier-domain WOTS opening. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawMerkle RawLayer RawSignature.
require import WotsReferenceRoot RawRecoveryTrace WotsRecoveryHistory VerifierWotsOpening.
require import LayerPath LayerExtractionHistory MerkleBuilderComparison NodeCollisionEvents MemoNodeCollision PublicNodeZero.

lemma merkle_extracts_wots_opening seed0 layer0 tree0 kp0 message0 sigma0 count0 recovered0 auth0 leaf0 reference_auth root0 :
  hoare [RawMerkle(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=recovered0 /\ index=kp0 /\ auth=auth0 /\
    rows_width 43 sigma0 /\ 0<=count0<4294967296 /\ rows_width 9 auth0 /\ rows_width 9 reference_auth /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 reference_auth root0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sigma0 count0 recovered0 ==>
    res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sigma0,count0)].
proof.
  conseq (merkle_recover_comparison_retained seed0 layer0 tree0 recovered0 kp0 auth0 leaf0 reference_auth root0)
    (merkle_keeps_root_and_trace seed0 layer0 tree0 kp0 message0 sigma0 count0 recovered0 leaf0).
  + rewrite /layer_path /wots_root; smt(recovery_trace_width node_width).
  smt(path_input_collision_is_public recovery_trace_opens_reference).
qed.

lemma raw_layer_extracts_wots_opening seed0 layer0 tree0 kp0 message0 (sig0 : layer_signature) leaf0 reference_auth root0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=kp0 /\ message=message0 /\ sig=sig0 /\
    layer_width sig0 /\ rows_width 9 reference_auth /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 reference_auth root0 ==>
    res=root0 => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      wots_verifier_opening Independent.rawhistory Independent.secrethistory
        seed0 layer0 tree0 kp0 message0 leaf0 (sig0.`1,sig0.`2)].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=kp0 /\ message=message0 /\ sig=sig0 /\
    layer_width sig0 /\ rows_width 9 reference_auth /\
    wots_root Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 leaf0 /\
    layer_path Independent.rawhistory seed0 layer0 tree0 kp0 leaf0 reference_auth root0 /\
    wots_recovery_trace Independent.rawhistory seed0 layer0 tree0 kp0 message0 sig0.`1 sig0.`2 pk).
  + call (wots_recovers_layer_trace seed0 layer0 tree0 kp0 message0 sig0.`1 sig0.`2 leaf0 reference_auth root0); auto.
  exists* pk; elim* => recovered0; wp.
  call (merkle_extracts_wots_opening seed0 layer0 tree0 kp0 message0 sig0.`1 sig0.`2 recovered0 sig0.`3 leaf0 reference_auth root0).
  auto; rewrite /layer_width; smt().
qed.
