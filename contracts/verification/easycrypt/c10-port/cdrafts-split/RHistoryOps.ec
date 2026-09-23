(* Persistent context attribution through the real independent-table loop. *)
require import AllCore List FMap.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid RoleGrind RoleGrindCost.
require import RTailFresh RTailMessages RTailContexts KeygenPrefixes.

lemma r_history_known h contexts random message nonce rd :
  r_history_contexts h contexts => (random,message) \in contexts => size message = 32 =>
  r_history_contexts h.[r_tail random message nonce <- rd] contexts.
proof.
  rewrite /r_history_contexts => hh hm hw tail hin ht.
  have hmem : tail = r_tail random message nonce \/ tail \in h by smt(mem_set).
  case hmem => he.
  + exists random message nonce; smt().
  exact (hh tail he ht).
qed.

lemma r_history_enlarge h contexts random message :
  r_history_contexts h contexts =>
  r_history_contexts h (rcons contexts (random,message)).
proof.
  rewrite /r_history_contexts => hh tail hin ht.
  have hex := hh tail hin ht.
  elim hex => r m n [#] hc hw he; exists r m n; smt(mem_rcons).
qed.

lemma hash_keeps_contexts contexts :
  hoare[Independent.hash : r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof. proc; sp 1; if; auto. qed.

lemma derive_known_context contexts random message nonce :
  hoare[Independent.derive : r_history_contexts Independent.secrethistory contexts /\
    (random,message) \in contexts /\ size message = 32 /\ tail = r_tail random message nonce ==>
    r_history_contexts Independent.secrethistory contexts].
proof. proc; if; auto; smt(r_history_known). qed.

lemma derive_other_context contexts :
  hoare[Independent.derive : r_history_contexts Independent.secrethistory contexts /\ head 0 tail <> 82 ==>
    r_history_contexts Independent.secrethistory contexts].
proof. proc; if; auto; smt(r_history_other). qed.

lemma role_grind_keeps_contexts contexts random0 message0 :
  (random0,message0) \in contexts => size message0 = 32 =>
  hoare[RoleGrind(Independent).run : random = random0 /\ message = message0 /\
    r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof.
  move=> hc hw; proc; while (random = random0 /\ message = message0 /\
    r_history_contexts Independent.secrethistory contexts).
  + wp; call (hash_keeps_contexts contexts); wp.
    exists* i; elim* => i0.
    call (derive_known_context contexts random0 message0 (U32.insubd i0)); auto.
  auto.
qed.

lemma wots_keeps_contexts contexts :
  hoare[PreparationView(Independent).wots : r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof. proc; call (derive_other_context contexts); auto; rewrite /wots_tag /=. qed.

lemma fors_keeps_contexts contexts :
  hoare[PreparationView(Independent).fors : r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof. proc; call (derive_other_context contexts); auto; rewrite /fors_tag /=. qed.

lemma preparation_keeps_contexts (P <: Preparation {-Independent}) contexts :
  hoare[P(PreparationView(Independent)).run : r_history_contexts Independent.secrethistory contexts ==>
    r_history_contexts Independent.secrethistory contexts].
proof.
  proc (r_history_contexts Independent.secrethistory contexts) => //.
  + exact (hash_keeps_contexts contexts).
  + exact (wots_keeps_contexts contexts).
  exact (fors_keeps_contexts contexts).
qed.
