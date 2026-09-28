(* Fixed-width messages remain separated across private derivation histories.
   Randomizer input lengths may differ; total preimage length distinguishes them. *)
require import AllCore List FMap.
require import C10RawOracle C10Bytes C10Counter PrefixGuess RoleGrind RTailFresh.

lemma r_tail_length random message nonce :
  size (r_tail random message nonce) = 39 + size random + size message.
proof. by rewrite /r_tail !size_cat counter_bytes_size !size_nseq /=; ring. qed.

lemma r_tail_message random message nonce :
  size message = 32 =>
  take 32 (drop (7+size random) (r_tail random message nonce)) = message.
proof.
  move=> hm; rewrite /r_tail -!catA drop_cat /=.
  have hs : 0 <= size random by exact size_ge0.
  rewrite (_ : (7+size random < 7) = false) 1:/# /=.
  by rewrite drop_cat /= drop0 take_cat hm /= take0 cats0.
qed.

lemma r_tail_different_messages random1 random2 message1 message2 nonce1 nonce2 :
  size message1 = 32 => size message2 = 32 => message1 <> message2 =>
  r_tail random1 message1 nonce1 <> r_tail random2 message2 nonce2.
proof.
  move=> h1 h2 hn; apply negP => he.
  have hs : size random1 = size random2 by smt(r_tail_length).
  have hm := r_tail_message random1 message1 nonce1 h1.
  by move: hm; rewrite hs he (r_tail_message random2 message2 nonce2 h2); smt().
qed.

op r_history_messages (h : (raw_input,digest) fmap) (messages : raw_input list) =
  forall tail, tail \in h => head 0 tail = 82 =>
    exists random message nonce, message \in messages /\ size message = 32 /\
      tail = r_tail random message nonce.

lemma unqueried_message_fresh (h : (raw_input,digest) fmap)
  (messages : raw_input list) (random message : raw_input) :
  r_history_messages h messages => size message = 32 => !List.mem messages message =>
  future_fresh h random message 0.
proof.
  rewrite /r_history_messages /future_fresh => hh hm hn j hj.
  apply negP => hin.
  have ht : head 0 (r_query random message j) = 82 by rewrite /r_query /r_tail /=.
  have hex := hh _ hin ht.
  elim hex => random0 message0 nonce0 [#] hmem hwidth he.
  have hd := r_tail_different_messages random random0 message message0 (U32.insubd j) nonce0 hm hwidth _.
  + smt().
  by move: he hd; rewrite /r_query; smt().
qed.
