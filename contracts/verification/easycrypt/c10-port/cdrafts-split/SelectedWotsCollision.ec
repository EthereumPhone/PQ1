(* Localized accepted collisions sufficient for the actual WOTS opening cut. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawCountRecorded.
require import WotsEncodingSplit WotsDigitOrder WotsCountDomain.

op selected_accepted_collision (h : (raw_input,digest) fmap) =
  exists x y d e, x<>y /\ wots_count_query x /\ wots_count_query y /\
    h.[x]=Some d /\ h.[y]=Some e /\ count_accepts d /\ count_accepts e /\ raw_digits d=raw_digits e.

lemma actual_different_messages_selected_collision h seed layer tree kp message message' count count' d d' :
  size seed=32 => 0<=count<4294967296 => 0<=count'<4294967296 => message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  count_accepts d => count_accepts d' => raw_digits d=raw_digits d' =>
  selected_accepted_collision h.
proof.
  move=> hs hc hc' hn hd hd' ha ha' he.
  have hq := actual_count_query_shape seed layer tree kp message count hs hc.
  have hq' := actual_count_query_shape seed layer tree kp message' count' hs hc'.
  rewrite /selected_accepted_collision.
  exists (wots_count_input seed layer tree kp message count)
    (wots_count_input seed layer tree kp message' count') d d'.
  smt(count_input_message_injective).
qed.

lemma selected_new_message_reverse_or_encoding h seed layer tree kp message message' count count' d d' :
  size seed=32 => 0<=count<4294967296 => 0<=count'<4294967296 => message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  count_accepts d => count_accepts d' =>
  selected_accepted_collision h \/ exists i, 0<=i<43 /\ RadixEncoding.digit 3 d i<RadixEncoding.digit 3 d' i.
proof.
  move=> hs hc hc' hn hd hd' ha ha'.
  have [he|hi] := accepted_digits_reverse_or_equal d d' ha ha'; last smt().
  left; exact (actual_different_messages_selected_collision h seed layer tree kp message message' count count' d d'
    hs hc hc' hn hd hd' ha ha' he).
qed.
