(* Distinct component messages must collide in encoding or move a chain backwards. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawSignature RawWots RawCountRecorded WotsDigitOrder ByteEncodingCharge.
require import WotsSignatureValue WotsChainSplit WotsSignWitness VerifierWotsOpening.

lemma count_input_message_injective seed layer tree kp message message' count count' :
  wots_count_input seed layer tree kp message count=wots_count_input seed layer tree kp message' count' =>
  message=message'.
proof.
  move=> he.
  have hp : pad message ++ be 32 count=pad message' ++ be 32 count'
    by move: he; rewrite /wots_count_input -!catA; smt(catsI).
  have hs : size message=size message'.
  + have hh : size (pad message ++ be 32 count)=size (pad message' ++ be 32 count') by rewrite hp.
    move: hh; rewrite /pad !size_cat !be_width 1,2://; smt().
  have ht : take (size message) (pad message ++ be 32 count)=take (size message) (pad message' ++ be 32 count') by rewrite hp.
  move: ht; rewrite /pad -!catA !take_size_cat; smt().
qed.

lemma different_messages_same_encoding h seed layer tree kp message message' count count' d d' :
  message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  raw_digits d=raw_digits d' => wots_encoding_collision h.
proof.
  move=> hn hd hd' he; rewrite /wots_encoding_collision.
  exists (wots_count_input seed layer tree kp message count)
    (wots_count_input seed layer tree kp message' count') d d'.
  smt(count_input_message_injective).
qed.

lemma new_message_reverse_or_encoding h seed layer tree kp message message' count count' d d' :
  message<>message' =>
  h.[wots_count_input seed layer tree kp message count]=Some d =>
  h.[wots_count_input seed layer tree kp message' count']=Some d' =>
  count_accepts d => count_accepts d' =>
  wots_encoding_collision h \/ exists i, 0<=i<43 /\ digit 3 d i<digit 3 d' i.
proof.
  move=> hn hd hd' ha ha'.
  have [he|hi] := accepted_digits_reverse_or_equal d d' ha ha'; last smt().
  left; exact (different_messages_same_encoding h seed layer tree kp message message' count count' d d'
    hn hd hd' he).
qed.

lemma new_wots_opening_requires_reverse h s seed layer tree kp message message' root root' signature signature' :
  message<>message' => !wots_encoding_collision h =>
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
  have [bad|[i [hi hb]]] := new_message_reverse_or_encoding h seed layer tree kp message message'
    signature.`2 signature'.`2 d d' hn hd hd' ha ha'; first smt().
  exists d d' i; smt().
qed.
