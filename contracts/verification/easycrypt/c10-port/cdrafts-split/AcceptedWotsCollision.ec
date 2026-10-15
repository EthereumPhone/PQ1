(* Only accepted encodings can obstruct the actual WOTS reverse-chain argument. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawSignature RawWots RawCountRecorded WotsDigitOrder ByteEncodingCharge.
require import WotsEncodingSplit WotsSignatureValue WotsChainSplit WotsSignWitness VerifierWotsOpening.

op accepted_wots_encoding_collision (h : (raw_input,digest) fmap) =
  exists x y d e, x<>y /\ h.[x]=Some d /\ h.[y]=Some e /\
    count_accepts d /\ count_accepts e /\ raw_digits d=raw_digits e.

lemma accepted_collision_is_encoding_collision h :
  accepted_wots_encoding_collision h => wots_encoding_collision h.
proof. rewrite /accepted_wots_encoding_collision /wots_encoding_collision; smt(). qed.

lemma accepted_different_messages_same_encoding h seed layer tree kp message message' count count' d d' :
  message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  count_accepts d => count_accepts d' =>
  raw_digits d=raw_digits d' => accepted_wots_encoding_collision h.
proof.
  move=> hn hd hd' ha ha' he; rewrite /accepted_wots_encoding_collision.
  exists (wots_count_input seed layer tree kp message count)
    (wots_count_input seed layer tree kp message' count') d d'.
  smt(count_input_message_injective).
qed.

lemma accepted_new_message_reverse_or_encoding h seed layer tree kp message message' count count' d d' :
  message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  count_accepts d => count_accepts d' =>
  accepted_wots_encoding_collision h \/ exists i, 0<=i<43 /\ digit 3 d i<digit 3 d' i.
proof.
  move=> hn hd hd' ha ha'.
  have [he|hi] := accepted_digits_reverse_or_equal d d' ha ha'; last smt().
  left; exact (accepted_different_messages_same_encoding h seed layer tree kp message message' count count' d d'
    hn hd hd' ha ha' he).
qed.

lemma accepted_new_wots_opening_requires_reverse h s seed layer tree kp message message' root root' signature signature' :
  message<>message' => !accepted_wots_encoding_collision h =>
  wots_verifier_opening h s seed layer tree kp message root signature =>
  wots_opening h s seed layer tree kp message' root' signature' =>
  exists d d' i, 0<=i<43 /\
    h.[wots_count_input seed layer tree kp message signature.`2]=Some d /\
    h.[wots_count_input seed layer tree kp message' signature'.`2]=Some d' /\
    digit 3 d i<digit 3 d' i /\
    nth (nseq 16 0) signature.`1 i=wots_partial h s seed layer tree kp i (digit 3 d i) /\
    nth (nseq 16 0) signature'.`1 i=wots_partial h s seed layer tree kp i (digit 3 d' i).
proof.
  move=> hn he [hr [hc [d [ha [hd [hw hv]]]]]] [hr' [hc' [d' [ha' [hd' [hw' hv']]]]]].
  have [bad|[i [hi hb]]] := accepted_new_message_reverse_or_encoding h seed layer tree kp message message'
    signature.`2 signature'.`2 d d' hn hd hd' ha ha'; first smt().
  exists d d' i; smt().
qed.
