(* Retain the exact verified pair when descending from the initialized public root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import MerkleRootWitness RootSessionHistory SessionForestExtraction ForestOpeningCases.
require import MemoNodeCollision PublicNodeZero ByteGameTopExtraction.

lemma query_client_root_preserved
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 layer0 tree0 root0 :
  hoare [A(QueryExposureSession(Independent)).run :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0].
proof.
  proc (merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 root0) => //.
  + proc; call (full_hash_root_preserved seed0 layer0 tree0 root0); auto.
  proc; wp; call (full_sign_root_preserved seed0 layer0 tree0 root0); auto.
qed.

op actual_forest_output h s seed root messages (output : raw_input * raw_signature) =
  size output.`1=32 /\ signature_width output.`2 /\ !List.mem messages output.`1 /\
  verified_forest_opening h s seed root output.`1 output.`2.

lemma query_driver_actual_forest
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  hoare [ClientQueryDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    FullSession.seed=seed0 /\ FullSession.root=pad root0 /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
        FullSession.signed_messages ClientQueryLog.output)].
proof.
  proc; seq 5 : (seed=seed0 /\ root=pad root0 /\ FullSession.seed=seed0 /\ FullSession.root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (query_client_root_preserved A seed0 1 0 root0); wp; inline FullSession(Independent).init; auto.
  sp 2; if; last auto.
  exists* forged; elim* => f0.
  call (verifier_extracts_forest seed0 root0 f0.`1 f0.`2).
  auto; rewrite /actual_forest_output; smt().
qed.

lemma query_context_actual_forest
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  hoare [ClientQueryContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.seed=seed0 /\ (exists root0, FullSession.root=pad root0 /\
      (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          FullSession.signed_messages ClientQueryLog.output))].
proof.
  proc; seq 1 : (exists root0, inputs.`3=seed0 /\ inputs.`4=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (prepared_top_reference seed0); auto.
  elim* => root0; call (query_driver_actual_forest A seed0 root0); auto; smt().
qed.

lemma query_byte_actual_forest
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.seed=seed0 /\ (exists root0, FullSession.root=pad root0 /\
      (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          FullSession.signed_messages ClientQueryLog.output))].
proof. proc; call (query_context_actual_forest (ByteLift(A)) seed0); inline Independent.init; auto. qed.
