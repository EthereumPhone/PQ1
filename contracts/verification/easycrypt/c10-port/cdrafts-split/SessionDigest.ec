(* External Q2 research: bound a new-message complete signing request from
   the actual session invariant, including guarded/refused calls. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid.
require import RawSigner FullSession SignerReturned FullHistory RTailMessages.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.
import RealOrder.

module SessionDigestEvent = {
  proc run(p : digest -> bool, random message shuffle : raw_input) : bool = {
    var signed;
    signed <@ FullSession(Independent).sign(random,message,shuffle);
    return signed <> None /\ p (oget Independent.rawhistory.[
      hmsg_input FullSession.seed FullSession.root ((oget signed).`1 ++ nseq 16 0) message]);
  }
}.

lemma session_sign_enabled :
  equiv[FullSession(Independent).sign ~ RawSigner(Independent).sign :
    ={random,message,shuffle,glob Independent} /\
    FullSession.seed{1} = seed{2} /\ FullSession.root{1} = root{2} /\
    !FullSession.failed{1} /\ size message{1} = 32 /\
    (size random{1} = 0 \/ size random{1} = 16) /\ size shuffle{1} = 32 /\
    FullSession.sign_calls{1} < FullSession.sign_limit{1} ==>
    ={res,glob Independent}].
proof.
  proc*; inline FullSession(Independent).sign.
  sp 4 0; rcondt{1} 1; first by auto.
  wp; call (_ : ={arg,glob Independent} ==> ={res,glob Independent}).
  + by sim.
  auto.
qed.

lemma session_digest_reduction :
  equiv[SessionDigestEvent.run ~ SignatureDigestEvent.run :
    ={p,random,message,shuffle,glob Independent} /\
    FullSession.seed{1} = seed{2} /\ FullSession.root{1} = root{2} ==>
    res{1} => res{2}].
proof.
  proc.
  case (!FullSession.failed{1} /\ size message{1} = 32 /\
    (size random{1} = 0 \/ size random{1} = 16) /\ size shuffle{1} = 32 /\
    FullSession.sign_calls{1} < FullSession.sign_limit{1}).
  + call session_sign_enabled; auto.
  inline FullSession(Independent).sign.
  sp 4 0; rcondf{1} 1; first by auto.
  call{2} (signer_sign_lossless Independent independent_hash_ll independent_derive_ll).
  auto.
qed.

lemma session_new_message_digest_bound p random message shuffle &m :
  full_history Independent.secrethistory{m} Independent.rawhistory{m} Independent.queries{m}
    FullSession.signed_messages{m} FullSession.failed{m} =>
  !FullSession.failed{m} =>
  size message = 32 => !List.mem FullSession.signed_messages{m} message =>
  size FullSession.seed{m} = 32 => size FullSession.root{m} = 32 =>
  Pr[SessionDigestEvent.run(p,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge (size Independent.queries{m}).
proof.
  move=> hh hl hm hn hs hr.
  have hrecord : history_recorded Independent.rawhistory{m} Independent.queries{m}
    by move: hh; rewrite /full_history; smt().
  have hf : future_fresh Independent.secrethistory{m} random message 0.
  + apply (unqueried_message_fresh _ FullSession.signed_messages{m} _ _); smt().
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
