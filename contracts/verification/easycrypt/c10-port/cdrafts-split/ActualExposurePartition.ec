(* The four residual cases refer to the actual verified output, with a shared digest. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid PrefixIdeal.
require import RawKeygen RawSigner RawSignature FullSession ByteSession KeygenPrefixes KeygenExhaustion.
require import ExposureLog ExposureDriver ClientQueryLog ClientQueryDriver ExposureSupport ExposureWidths.
require import ExposureAccounting ExposurePartition ForestOpeningCases ActualForestGame QueryMinimumHistory.
require import MinimumExposureSupport MemoNodeCollision PublicNodeZero.

op actual_exposure_partition h s seed root entries (output : raw_input * raw_signature) =
  size output.`1=32 /\ signature_width output.`2 /\
  !List.mem (exposure_messages entries) output.`1 /\
  exists d, accept_digest d /\ h.[hmsg_input seed root (pad output.`2.`1) output.`1]=Some d /\
    exposure_forgery_cases h s seed root entries d output.`2.

lemma actual_forest_partition h s seed root entries messages output :
  exposures_supported h s seed (pad root) entries => exposures_width entries =>
  exposure_messages entries=messages => !public_node_collision h =>
  actual_forest_output h s seed root messages output =>
  actual_exposure_partition h s seed (pad root) entries output.
proof.
  move=> hs hw hm hn [hmess [hsig [hnew [d [ha [hd hc]]]]]].
  have hp := forest_cases_exposure_partition h s seed (pad root) entries d output.`2 hs hw hn hc.
  rewrite /actual_exposure_partition; split; first exact hmess.
  split; first exact hsig.
  split; first smt().
  exists d; smt().
qed.

lemma query_byte_exposure_width
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) :
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : true ==> exposures_width ExposureLog.entries].
proof.
  have he : equiv [IndependentGame(ClientQueryContext(ByteLift(A))).run ~
    IndependentGame(ExposureContext(ByteLift(A))).run :
    ={glob A,glob FullLimits,glob KeygenInputs} ==> ={glob ExposureLog}]
    by symmetry; conseq (byte_query_exposure_game_projection A); smt().
  conseq he (byte_exposure_width A).
  + move=> &m hm; exists (glob A){m} FullLimits.raw_cap{m} FullLimits.sign_cap{m}
      KeygenInputs.message{m} KeygenInputs.public_seed{m} KeygenInputs.random{m}; smt().
  smt().
qed.

lemma query_byte_typed_canonical_history
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 ==>
    exposures_supported Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    minimum_entries Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    exposures_width ExposureLog.entries /\
    exposure_accounting ExposureLog.entries FullSession.signed_messages FullSession.sign_calls qs0].
proof.
  move=> hqs; conseq (query_byte_canonical_history A qs0 hqs) (query_byte_exposure_width A); smt().
qed.

lemma query_byte_actual_partition
  (A <: ByteClient {-FullSession,-FullLimits,-KeygenInputs,-ExposureLog,-ClientQueryLog,-Independent}) seed0 qs0 :
  0<=qs0 =>
  hoare [IndependentGame(ClientQueryContext(ByteLift(A))).run : FullLimits.sign_cap=qs0 /\
    pad (node KeygenInputs.public_seed)=seed0 ==>
    minimum_entries Independent.rawhistory Independent.secrethistory
      FullSession.seed FullSession.root ExposureLog.entries /\
    (res => public_node_collision Independent.rawhistory \/ public_node_zero Independent.rawhistory \/
      actual_exposure_partition Independent.rawhistory Independent.secrethistory
        FullSession.seed FullSession.root ExposureLog.entries ClientQueryLog.output)].
proof.
  move=> hqs; conseq (query_byte_typed_canonical_history A qs0 hqs) (query_byte_actual_forest A seed0);
    rewrite /exposure_accounting; smt(actual_forest_partition).
qed.
