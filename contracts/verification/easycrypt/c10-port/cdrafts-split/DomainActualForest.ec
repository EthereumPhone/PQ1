(* Retain the exact verified pair when descending from the initialized public root. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner RawSignature FullSession ByteSession ExposureLog ClientQueryLog ClientQueryDriver.
require import MerkleRootWitness RootSessionHistory SessionForestExtraction ForestOpeningCases.
require import MemoNodeCollision PublicNodeZero ByteGameTopExtraction.

require import ActualForestGame DomainNodeCollision DomainForestCases.
require import VerifierForestRecords.

lemma domain_verifier_extracts_forest seed0 root0 message0 (sig0 : raw_signature) :
  size seed0=32 =>
  hoare [RawSigner(Independent).verify :
    seed=seed0 /\ root=pad root0 /\ message=message0 /\ sig=sig0 /\ signature_width sig0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 /\
    (res => domain_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      verified_forest_opening Independent.rawhistory Independent.secrethistory seed0 root0 message0 sig0)].
proof.
  move=> hseed;
  conseq (verifier_records_forest seed0 root0 message0 sig0)
    (public_verifier_root_preserved RawSigner seed0 1 0 root0); smt(domain_verified_records_to_forest).
qed.

lemma domain_query_driver_actual_forest
  (A <: FullClient {-FullSession,-ExposureLog,-ClientQueryLog,-Independent}) seed0 root0 :
  size seed0=32 =>
  hoare [ClientQueryDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    FullSession.seed=seed0 /\ FullSession.root=pad root0 /\
    (res => domain_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
        FullSession.signed_messages ClientQueryLog.output)].
proof.
  move=> hseed; proc; seq 5 : (seed=seed0 /\ root=pad root0 /\ FullSession.seed=seed0 /\ FullSession.root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (query_client_root_preserved A seed0 1 0 root0); wp; inline FullSession(Independent).init; auto.
  sp 2; if; last auto.
  exists* forged; elim* => f0.
  call (domain_verifier_extracts_forest seed0 root0 f0.`1 f0.`2 hseed).
  auto; rewrite /actual_forest_output; smt().
qed.

lemma domain_query_context_actual_forest
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  size seed0=32 =>
  hoare [ClientQueryContext(A,Independent).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.seed=seed0 /\ (exists root0, FullSession.root=pad root0 /\
      (res => domain_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          FullSession.signed_messages ClientQueryLog.output))].
proof.
  move=> hseed; proc; seq 1 : (exists root0, inputs.`3=seed0 /\ inputs.`4=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0).
  + call (prepared_top_reference seed0); auto.
  elim* => root0; call (domain_query_driver_actual_forest A seed0 root0 hseed); auto; smt().
qed.

lemma domain_query_byte_actual_forest
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 :
  size seed0=32 =>
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : pad (node KeygenInputs.public_seed)=seed0 ==>
    FullSession.seed=seed0 /\ (exists root0, FullSession.root=pad root0 /\
      (res => domain_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
        actual_forest_output Independent.rawhistory Independent.secrethistory seed0 root0
          FullSession.signed_messages ClientQueryLog.output))].
proof. move=> hseed; proc; call (domain_query_context_actual_forest (ByteLift(A)) seed0 hseed); inline Independent.init; auto. qed.
