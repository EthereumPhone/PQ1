(* The accumulated partition belongs to the original initialized byte client. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid PrefixIdeal KeygenPrefixes KeygenExhaustion.
require import RawKeygen RawSigner FullSession ByteSession IndependentWidths SignerEncodingCorrect.
require import ExposureLog ExposureDriver ExposureSupport ExposureAccounting ExposureSessionHistory.
require import ExposureWidths ExposurePartition MerkleRootWitness SessionForestExtraction.
require import MemoNodeCollision PublicNodeZero.

lemma exposure_driver_forest (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 :
  hoare [ExposureDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      new_message_forest_opening Independent.rawhistory Independent.secrethistory
        seed0 root0 FullSession.signed_messages].
proof.
  have he : equiv [ExposureDriver(A,Independent).run ~ FullDriver(A,Independent).run :
    ={arg,glob A,glob Independent} ==> ={res,glob A,glob Independent,glob FullSession}]
    by symmetry; conseq (exposure_driver_projection A Independent); smt().
  conseq he (full_driver_forest_extraction A seed0 root0).
  + move=> &m hm; exists (glob A){m} Independent.queries{m} Independent.rawhistory{m}
      Independent.secrethistory{m} (seed{m},root{m},qr{m},qs{m}); smt().
  smt().
qed.

lemma exposure_driver_typed_history (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 qs0 :
  0<=qs0 =>
  hoare [ExposureDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size ExposureLog.entries<=qs0 /\ exposures_width ExposureLog.entries /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 (pad root0) ExposureLog.entries /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages].
proof.
  move=> hqs; conseq (exposure_driver_history A seed0 (pad root0) qs0 hqs) (exposure_driver_width A);
    rewrite /exposure_accounting; smt().
qed.

lemma exposure_driver_partition (A <: FullClient {-FullSession,-ExposureLog,-Independent}) seed0 root0 qs0 :
  0<=qs0 =>
  hoare [ExposureDriver(A,Independent).run : seed=seed0 /\ root=pad root0 /\ qs=qs0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    size ExposureLog.entries<=qs0 /\ exposures_width ExposureLog.entries /\
    exposures_supported Independent.rawhistory Independent.secrethistory seed0 (pad root0) ExposureLog.entries /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      new_message_exposure_partition Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries)].
proof.
  move=> hqs.
  conseq (exposure_driver_typed_history A seed0 root0 qs0 hqs) (exposure_driver_forest A seed0 root0);
    smt(new_message_forest_partition).
qed.

lemma exposure_context_partition
  (A <: FullClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [ExposureContext(A,Independent).run : FullLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory ==>
    size ExposureLog.entries<=qs0 /\ exposures_width ExposureLog.entries /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries)].
proof.
  move=> hqs; proc; inline KeygenPreparation(PreparationView(Independent)).run.
  seq 2 : (FullLimits.sign_cap=qs0 /\ seed=seed0 /\
    independent_tables_valid Independent.rawhistory Independent.secrethistory /\
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root).
  + call (keygen_root_ready seed0); auto.
  exists* root; elim* => root0.
  call (exposure_driver_partition A seed0 root0 qs0 hqs); auto; smt().
qed.

lemma byte_exposure_partition
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ExposureContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    size ExposureLog.entries<=qs0 /\ exposures_width ExposureLog.entries /\
    exposure_messages ExposureLog.entries=FullSession.signed_messages /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      exists root0, new_message_exposure_partition Independent.rawhistory Independent.secrethistory seed0 root0 ExposureLog.entries)].
proof.
  move=> hqs; proc; call (exposure_context_partition (ByteLift(A)) seed0 qs0 hqs);
    call independent_init_valid; auto.
qed.
