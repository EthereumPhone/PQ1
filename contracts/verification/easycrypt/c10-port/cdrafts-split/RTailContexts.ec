(* Fixed-width messages make (opt_rand,message) private R domains injective. *)
require import AllCore List FMap.
require import C10RawOracle C10Bytes C10Counter PrefixGuess RoleGrind RTailFresh RTailMessages.

lemma r_tail_random random message nonce :
  take (size random) (drop 7 (r_tail random message nonce)) = random.
proof.
  by rewrite /r_tail -!catA drop_size_cat 1:// take_cat /= take0 cats0.
qed.

lemma r_tail_context_injective random1 random2 message1 message2 nonce1 nonce2 :
  size message1 = 32 => size message2 = 32 =>
  r_tail random1 message1 nonce1 = r_tail random2 message2 nonce2 =>
  random1 = random2 /\ message1 = message2.
proof.
  move=> hm1 hm2 he.
  have hs : size random1 = size random2 by smt(r_tail_length).
  have hr := r_tail_random random1 message1 nonce1.
  rewrite hs he (r_tail_random random2 message2 nonce2) in hr.
  split; first smt().
  by smt(r_tail_different_messages).
qed.

op r_history_contexts (h : (raw_input,digest) fmap) (contexts : (raw_input * raw_input) list) =
  forall tail, tail \in h => head 0 tail = 82 =>
    exists random message nonce, (random,message) \in contexts /\ size message = 32 /\
      tail = r_tail random message nonce.

lemma unqueried_context_fresh (h : (raw_input,digest) fmap)
  (contexts : (raw_input * raw_input) list) (random message : raw_input) :
  r_history_contexts h contexts => size message = 32 =>
  !List.mem contexts (random,message) => future_fresh h random message 0.
proof.
  rewrite /r_history_contexts /future_fresh => hh hm hn j hj.
  apply negP => hin.
  have ht : head 0 (r_query random message j) = 82 by rewrite /r_query /r_tail /=.
  have hex := hh _ hin ht.
  elim hex => random0 message0 nonce0 [#] hmem hwidth he.
  have hc := r_tail_context_injective random random0 message message0
    (U32.insubd j) nonce0 hm hwidth he.
  smt().
qed.

lemma r_history_other h contexts tail rd :
  r_history_contexts h contexts => head 0 tail <> 82 =>
  r_history_contexts h.[tail <- rd] contexts.
proof. rewrite /r_history_contexts; smt(mem_set). qed.

lemma r_history_add h contexts random message nonce rd :
  r_history_contexts h contexts => size message = 32 =>
  r_history_contexts h.[r_tail random message nonce <- rd] (rcons contexts (random,message)).
proof.
  rewrite /r_history_contexts => hh hm tail hin ht.
  have hmem : tail = r_tail random message nonce \/ tail \in h by smt(mem_set).
  case hmem => he.
  + exists random message nonce; smt(mem_rcons).
  have hex := hh tail he ht.
  elim hex => r m n [#] hctx hwidth htail.
  exists r m n; smt(mem_rcons).
qed.
