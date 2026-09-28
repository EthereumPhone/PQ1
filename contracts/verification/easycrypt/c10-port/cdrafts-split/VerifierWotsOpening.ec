(* Verifier openings use the wire counter domain, not the bounded signing search. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawWots RawSignature RawCountRecorded.
require import WotsReference WotsReferenceRoot WotsSignatureValue WotsRecoveryTrace.
require import RawRecoveryTrace RecoveryCompression MemoNodeCollision PublicNodeZero WotsZeroSentinel.

op wots_verifier_opening h s seed layer tree kp message root (signature : raw_input list * int) =
  wots_root h s seed layer tree kp root /\ 0<=signature.`2<4294967296 /\
  exists d, count_accepts d /\
    h.[wots_count_input seed layer tree kp message signature.`2]=Some d /\
    wots_signature h s seed layer tree kp d signature.`1.

lemma recovery_trace_opens_reference h s seed layer tree kp message sigma count root :
  wots_root h s seed layer tree kp root => rows_width 43 sigma => 0<=count<4294967296 =>
  wots_recovery_trace h seed layer tree kp message sigma count root =>
  !public_node_collision h => !public_node_zero h =>
  wots_verifier_opening h s seed layer tree kp message root (sigma,count).
proof.
  move=> hr [hs hw] hc [d [hd ht]] hn hz.
  have ha : count_accepts d by smt(wots_zero_is_public).
  have [hp [leaf [hl he]]] : recovery_prefix h seed layer tree kp d sigma 43 /\
    exists leaf, h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf /\ root=node leaf by smt().
  rewrite /wots_verifier_opening /=; split; first exact hr.
  split; first exact hc.
  exists d; split; first exact ha.
  split; first exact hd.
  rewrite /wots_signature; split; first exact hs.
  move=> i hi.
  have heq := matching_wots_endpoints h s seed layer tree kp d sigma root leaf hn hr hw hl _ i hi;
    first by smt().
  apply (recovery_chain_unique h s seed layer tree kp d sigma i) => //.
  by move: hr; rewrite /wots_root; smt().
qed.
