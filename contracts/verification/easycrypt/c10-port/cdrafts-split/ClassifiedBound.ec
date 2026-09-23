(* External Q2 research: a predicate that rejects the retained output of a
   repeated context is bounded without pretending the repeat is a fresh draw. *)
require import AllCore List Distr FMap StdOrder StdBigop.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid.
require import RoleGrind RawSigner FullSession SignerReturned SignerTrace SessionDigest.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.
require import GrindTrace ClassifiedHistory ClassifiedSession.
import RealOrder Bigreal BRA.

lemma completed_trace_not_fresh s h random message seed root answer :
  completed_trace s h random message seed root answer =>
  !future_fresh s random message 0.
proof.
  rewrite /completed_trace => hex.
  elim hex => j [#] hj hb hp ht ha he.
  move: ht; rewrite /trial_recorded /future_fresh /r_query; smt().
qed.

lemma session_fresh_digest_bound p random message shuffle &m :
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size FullSession.seed{m} = 32 => size FullSession.root{m} = 32 =>
  Pr[SessionDigestEvent.run(p,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge (size Independent.queries{m}).
proof.
  move=> hrecord hf hs hr.
  have hle :
    Pr[SessionDigestEvent.run(p,random,message,shuffle) @ &m : res] <=
    Pr[SignatureDigestEvent.run(p,FullSession.seed{m},FullSession.root{m},random,message,shuffle) @ &m : res]
    by byequiv session_digest_reduction => //.
  have hb := signature_digest_bound p (size Independent.queries{m})
    FullSession.seed{m} FullSession.root{m} random message shuffle &m
    _ _ hrecord hf hs hr.
  + exact size_ge0.
  + trivial.
  smt().
qed.

lemma session_repeated_digest random0 message0 seed0 root0 answer :
  hoare[FullSession(Independent).sign :
    random = random0 /\ message = message0 /\
    FullSession.seed = seed0 /\ FullSession.root = root0 /\
    completed_trace Independent.secrethistory Independent.rawhistory random0 message0 seed0 root0 answer ==>
    res <> None =>
      Independent.rawhistory.[hmsg_input seed0 root0
        ((oget res).`1 ++ nseq 16 0) message0] = Some answer.`2].
proof.
  proc; sp 1; if; last by auto.
  wp; call (signer_repeated_digest random0 message0 seed0 root0 answer); auto; smt().
qed.

lemma session_repeated_event_zero p0 random0 message0 shuffle0 answer &m :
  completed_trace Independent.secrethistory{m} Independent.rawhistory{m}
    random0 message0 FullSession.seed{m} FullSession.root{m} answer =>
  !p0 answer.`2 =>
  Pr[SessionDigestEvent.run(p0,random0,message0,shuffle0) @ &m : res] = 0%r.
proof.
  move=> ht hp.
  byphoare (_ : p = p0 /\ random = random0 /\ message = message0 /\
    FullSession.seed = FullSession.seed{m} /\ FullSession.root = FullSession.root{m} /\
    completed_trace Independent.secrethistory Independent.rawhistory
      random0 message0 FullSession.seed{m} FullSession.root{m} answer ==> res) => //.
  hoare; proc.
  call (session_repeated_digest random0 message0 FullSession.seed{m} FullSession.root{m} answer).
  auto; smt().
qed.

lemma accepted_revisit_nonnegative p q : 0 <= q =>
  0%r <= accepted_probability p + revisit_charge q.
proof.
  move=> hq; apply addr_ge0.
  + have hp := accepted_probability_bounds p; smt().
  rewrite /revisit_charge; apply Bigreal.sumr_ge0_seq => i.
  rewrite mem_range => hi _; apply mulr_ge0.
  + rewrite le_fromint; smt().
  apply expr_ge0; smt().
qed.

lemma session_novel_digest_bound p random message shuffle &m :
  live_classified Independent.secrethistory{m} Independent.rawhistory{m}
    FullSession.seed{m} FullSession.root{m} FullSession.failed{m} =>
  !FullSession.failed{m} =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  size message = 32 => size FullSession.seed{m} = 32 => size FullSession.root{m} = 32 =>
  (forall answer, completed_trace Independent.secrethistory{m} Independent.rawhistory{m}
    random message FullSession.seed{m} FullSession.root{m} answer => !p answer.`2) =>
  Pr[SessionDigestEvent.run(p,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge (size Independent.queries{m}).
proof.
  move=> hc hl hrecord hm hs hr hp.
  have hclass : classified_context Independent.secrethistory{m} Independent.rawhistory{m}
    FullSession.seed{m} FullSession.root{m} random message
    by move: hc; rewrite /live_classified /classified_history; smt().
  case hclass => hf.
  + exact (session_fresh_digest_bound p random message shuffle &m hrecord hf hs hr).
  elim hf => answer ht.
  rewrite (session_repeated_event_zero p random message shuffle answer &m ht (hp answer ht)).
  exact (accepted_revisit_nonnegative p (size Independent.queries{m}) (size_ge0 _)).
qed.
