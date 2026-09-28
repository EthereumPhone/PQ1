(* External Q2 research: private R history belongs to signed messages. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrind RoleGrindCost.
require import RTailFresh RTailMessages KeygenPrefixes.

lemma message_history_other h messages tail rd :
  r_history_messages h messages => head 0 tail <> 82 =>
  r_history_messages h.[tail <- rd] messages.
proof. rewrite /r_history_messages; smt(mem_set). qed.

lemma no_r_messages h messages :
  no_r_tails h => r_history_messages h messages.
proof. rewrite /no_r_tails /r_history_messages; smt(). qed.

lemma message_history_known h messages random message nonce rd :
  r_history_messages h messages => message \in messages => size message = 32 =>
  r_history_messages h.[r_tail random message nonce <- rd] messages.
proof.
  rewrite /r_history_messages => hh hm hw tail hin ht.
  have hmem : tail = r_tail random message nonce \/ tail \in h by smt(mem_set).
  case hmem => he.
  + exists random message nonce; smt().
  exact (hh tail he ht).
qed.

lemma message_history_enlarge h messages message :
  r_history_messages h messages =>
  r_history_messages h (rcons messages message).
proof.
  rewrite /r_history_messages => hh tail hin ht.
  have hex := hh tail hin ht.
  elim hex => r m n [#] hc hw he; exists r m n; smt(mem_rcons).
qed.

lemma hash_keeps_messages messages :
  hoare[Independent.hash : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof. proc; sp 1; if; auto. qed.

lemma derive_known_message_history messages random message nonce :
  hoare[Independent.derive : r_history_messages Independent.secrethistory messages /\
    message \in messages /\ size message = 32 /\ tail = r_tail random message nonce ==>
    r_history_messages Independent.secrethistory messages].
proof. proc; if; auto; smt(message_history_known). qed.

lemma derive_other_message_history messages :
  hoare[Independent.derive : r_history_messages Independent.secrethistory messages /\ head 0 tail <> 82 ==>
    r_history_messages Independent.secrethistory messages].
proof. proc; if; auto; smt(message_history_other). qed.

lemma role_grind_keeps_messages messages random0 message0 :
  message0 \in messages => size message0 = 32 =>
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\
    r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof.
  move=> hc hw; proc; while (random = random0 /\ message = message0 /\
    r_history_messages Independent.secrethistory messages).
  + wp; call (hash_keeps_messages messages); wp.
    exists* i; elim* => i0.
    call (derive_known_message_history messages random0 message0 (U32.insubd i0)); auto.
  auto.
qed.

lemma wots_keeps_messages messages :
  hoare[PreparationView(Independent).wots : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof. proc; call (derive_other_message_history messages); auto; rewrite /wots_tag /=. qed.

lemma fors_keeps_messages messages :
  hoare[PreparationView(Independent).fors : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof. proc; call (derive_other_message_history messages); auto; rewrite /fors_tag /=. qed.

lemma preparation_keeps_messages (P <: Preparation {-Independent}) messages :
  hoare[P(PreparationView(Independent)).run : r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory messages].
proof.
  proc (r_history_messages Independent.secrethistory messages) => //.
  + exact (hash_keeps_messages messages).
  + exact (wots_keeps_messages messages).
  exact (fors_keeps_messages messages).
qed.

lemma role_message_records messages random0 message0 :
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\ size message0 = 32 /\
    r_history_messages Independent.secrethistory messages ==>
    r_history_messages Independent.secrethistory (rcons messages message0)].
proof.
  proc; while (random = random0 /\ message = message0 /\ size message0 = 32 /\
    r_history_messages Independent.secrethistory (rcons messages message0)).
  + wp; call (hash_keeps_messages (rcons messages message0)); wp.
    exists* i; elim* => i0.
    call (derive_known_message_history (rcons messages message0) random0 message0 (U32.insubd i0));
      auto; smt(mem_rcons).
  auto; smt(message_history_enlarge).
qed.
