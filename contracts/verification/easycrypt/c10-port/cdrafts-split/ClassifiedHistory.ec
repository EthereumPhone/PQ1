(* External Q2 research: every fixed-width context is either entirely unused
   or has a retained first-accepted trace. No exposed ghost list is needed. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.
require import PrefixGuess PrefixHybrid RoleGrind RTailFresh RTailContexts KeygenPrefixes.
require import PersistentGrind AcceptedContexts GrindTrace.

op classified_context s h seed root random message =
  future_fresh s random message 0 \/
  exists answer, completed_trace s h random message seed root answer.
op classified_history s h seed root =
  forall random message, size message = 32 => classified_context s h seed root random message.
op classified_except s h seed root random0 message0 =
  forall random message, size message = 32 => (random,message) <> (random0,message0) =>
    classified_context s h seed root random message.

lemma fresh_other_tail s random message random0 message0 nonce d :
  size message = 32 => size message0 = 32 => (random,message) <> (random0,message0) =>
  future_fresh s random message 0 =>
  future_fresh s.[r_tail random0 message0 nonce <- d] random message 0.
proof.
  move=> hm hm0 hn; rewrite /future_fresh => hf j hj.
  have hi := hf j hj.
  have hd : r_tail random0 message0 nonce <> r_query random message j.
  + rewrite /r_query; smt(r_tail_context_injective).
  smt(mem_set).
qed.

lemma fresh_nonr_tail s random message tail d :
  head 0 tail <> 82 => future_fresh s random message 0 =>
  future_fresh s.[tail <- d] random message 0.
proof.
  move=> ht; rewrite /future_fresh => hf j hj.
  have hi := hf j hj.
  have hd : tail <> r_query random message j by rewrite /r_query /r_tail; smt().
  smt(mem_set).
qed.

lemma classified_raw_insert s h seed root random message x d :
  x \notin h => classified_context s h seed root random message =>
  classified_context s h.[x <- d] seed root random message.
proof.
  rewrite /classified_context => hx hc.
  case hc => hf; first by left.
  right; elim hf => answer ht; exists answer.
  exact (completed_trace_extends s h s h.[x <- d] random message seed root answer
    (extends_refl s) (extends_insert h x d hx) ht).
qed.

lemma classified_nonr_insert s h seed root random message tail d :
  tail \notin s => head 0 tail <> 82 =>
  classified_context s h seed root random message =>
  classified_context s.[tail <- d] h seed root random message.
proof.
  rewrite /classified_context => hn ht hc.
  case hc => hf.
  + left; exact (fresh_nonr_tail s random message tail d ht hf).
  right; elim hf => answer ha; exists answer.
  exact (completed_trace_extends s h s.[tail <- d] h random message seed root answer
    (extends_insert s tail d hn) (extends_refl h) ha).
qed.

lemma classified_other_insert s h seed root random message random0 message0 nonce d :
  r_tail random0 message0 nonce \notin s =>
  size message = 32 => size message0 = 32 => (random,message) <> (random0,message0) =>
  classified_context s h seed root random message =>
  classified_context s.[r_tail random0 message0 nonce <- d] h seed root random message.
proof.
  rewrite /classified_context => hn hm hm0 hneq hc.
  case hc => hf.
  + left; exact (fresh_other_tail s random message random0 message0 nonce d hm hm0 hneq hf).
  right; elim hf => answer ha; exists answer.
  exact (completed_trace_extends s h s.[r_tail random0 message0 nonce <- d] h
    random message seed root answer
    (extends_insert s (r_tail random0 message0 nonce) d hn) (extends_refl h) ha).
qed.

lemma no_r_classified s h seed root :
  no_r_tails s => classified_history s h seed root.
proof.
  move=> hn; rewrite /classified_history /classified_context.
  move=> random message hm; left; exact (no_r_future_fresh s random message hn).
qed.

lemma classified_exclude s h seed root random message :
  classified_history s h seed root => classified_except s h seed root random message.
proof. rewrite /classified_history /classified_except; smt(). qed.

lemma classified_include s h seed root random0 message0 answer :
  classified_except s h seed root random0 message0 =>
  completed_trace s h random0 message0 seed root answer =>
  classified_history s h seed root.
proof.
  rewrite /classified_except /classified_history /classified_context; smt().
qed.
