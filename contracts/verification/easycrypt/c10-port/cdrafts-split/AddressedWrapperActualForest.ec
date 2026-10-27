(* Equal-address forest extraction from the actual wrapper output and its
   persistent initialized root. Freshness remains over released messages. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature WrapperSession ByteSession ExposureLog ClientQueryLog WrapperQueryDriver.
require import MerkleRootWitness RootSessionHistory SessionForestExtraction ForestOpeningCases.
require import MemoNodeCollision PublicNodeZero ByteGameTopExtraction.

require import ActualForestGame AddressedNodeCollision AddressedForestCases.
require import VerifierForestRecords.

require import WrapperByteSession WrapperActualForest AddressedActualForest.

lemma addressed_wrapper_query_driver_actual_forest
  (A <: WrapperClient {-WrapperSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  size seed0=32 =>
  hoare [WrapperQueryDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    WrapperSession.seed=seed0 /\ WrapperSession.root=pad root0 /\
    (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
        WrapperSession.signed_messages ClientQueryLog.output)].
proof.
  move=> hseed; proc; seq 5 : (seed=seed0 /\ root=pad root0 /\ WrapperSession.seed=seed0 /\ WrapperSession.root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (wrapper_query_client_root_preserved A seed0 1 0 root0); wp; inline WrapperSession(Independent).init; auto.
  sp 2; if; last auto.
  exists* forged; elim* => f0.
  call (addressed_verifier_extracts_forest seed0 root0 f0.`1 f0.`2 hseed).
  auto; rewrite /actual_forest_output; smt().
qed.

lemma addressed_wrapper_query_context_actual_forest
  (A <: WrapperClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  size seed0=32 =>
  hoare [WrapperQueryContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    WrapperSession.seed=seed0 /\ (exists root0, WrapperSession.root=pad root0 /\
      (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          WrapperSession.signed_messages ClientQueryLog.output))].
proof.
  move=> hseed; proc; seq 1 : (exists root0, inputs.`3=seed0 /\ inputs.`4=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (prepared_top_reference seed0); auto.
  elim* => root0; call (addressed_wrapper_query_driver_actual_forest A seed0 root0 hseed); auto; smt().
qed.

lemma addressed_wrapper_query_byte_actual_forest
  (A <: WrapperByteClient {-WrapperSession,-WrapperLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  size seed0=32 =>
  hoare [IndependentGame(WrapperQueryContext(WrapperByteLift(A))).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    WrapperSession.seed=seed0 /\ (exists root0, WrapperSession.root=pad root0 /\
      (res => addressed_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          WrapperSession.signed_messages ClientQueryLog.output))].
proof. move=> hseed; proc; call (addressed_wrapper_query_context_actual_forest (WrapperByteLift(A)) seed0 hseed); inline Independent.init; auto. qed.
