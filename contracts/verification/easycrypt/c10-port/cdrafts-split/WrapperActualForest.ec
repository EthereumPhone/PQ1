(* Extract the exact verified final wrapper output from its initialized root.
   Freshness is checked against externally released signatures only. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature WrapperSession WrapperByteSession.
require import ExposureLog ClientQueryLog WrapperExposureLog WrapperQueryDriver WrapperHistory.
require import MerkleRootWitness RootSessionHistory SessionForestExtraction ForestOpeningCases.
require import MemoNodeCollision PublicNodeZero ByteGameTopExtraction ActualForestGame.

lemma wrapper_query_client_root_preserved
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 layer0 tree0 root0 :
  hoare [A(WrapperQueryExposureSession(Independent)).run :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  + proc; call (wrapper_hash_root_preserved seed0 layer0 tree0 root0); auto.
  proc; wp; call (wrapper_sign_root_preserved seed0 layer0 tree0 root0); auto.
qed.

lemma wrapper_query_driver_actual_forest
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  hoare [WrapperQueryDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=pad root0 /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
        WrapperSession.signed_messages ClientQueryLog.output)].
proof.
  proc; seq 5 : (seed=seed0 /\ root=pad root0 /\ WrapperSession.seed=seed0 /\ WrapperSession.root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (wrapper_query_client_root_preserved A seed0 1 0 root0); wp; inline WrapperSession(Independent).init; auto.
  sp 2; if; last auto.
  exists* forged; elim* => f0.
  call (verifier_extracts_forest seed0 root0 f0.`1 f0.`2).
  auto; rewrite /actual_forest_output; smt().
qed.

lemma wrapper_query_context_actual_forest
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  hoare [WrapperQueryContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    WrapperSession.seed=seed0 /\ (exists root0, WrapperSession.root=pad root0 /\
      (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          WrapperSession.signed_messages ClientQueryLog.output))].
proof.
  proc; seq 1 : (exists root0, inputs.`3=seed0 /\ inputs.`4=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (prepared_top_reference seed0); auto.
  elim* => root0; call (wrapper_query_driver_actual_forest A seed0 root0); auto; smt().
qed.

lemma wrapper_byte_actual_forest
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    WrapperSession.seed=seed0 /\ (exists root0, WrapperSession.root=pad root0 /\
      (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          WrapperSession.signed_messages ClientQueryLog.output))].
proof. proc; call (wrapper_query_context_actual_forest (WrapperByteLift(A)) seed0); inline Independent.init; auto. qed.
