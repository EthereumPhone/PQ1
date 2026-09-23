(* External Q research: relate private grind observation to the actual
   complete signature's randomizer and retained H_msg table entry. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10HashDomains C10Randomizer.
require import PrefixGuess RoleGrind RawSigner GrindReturned SignerAccepted.
require import RawTrial RTailFresh GrindExhaustion AcceptedSampling.

lemma finish_randomizer (O <: PrefixOracle) randomizer0 :
  hoare[RawSigner(O).finish : randomizer = randomizer0 ==>
    res <> None => (oget res).`1 = randomizer0].
proof.
  proc; wp; while true.
  + by trivial.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma finish_keeps_randomizer_entry randomizer0 x0 d0 :
  hoare[RawSigner(Independent).finish :
    randomizer = randomizer0 /\ Independent.rawhistory.[x0] = Some d0 ==>
    Independent.rawhistory.[x0] = Some d0 /\
    (res <> None => (oget res).`1 = randomizer0)].
proof.
  conseq (finish_randomizer Independent randomizer0) (signer_finish_keeps_entry x0 d0); smt().
qed.

lemma observed_signer_entry seed0 root0 message0 :
  hoare[ObservedSigner(Independent).sign :
    seed = seed0 /\ root = root0 /\ message = message0 ==>
    res <> None =>
      SignObservation.accepted <> None /\
      (oget res).`1 = (oget SignObservation.accepted).`1 /\
      Independent.rawhistory.[hmsg_input seed0 root0
        ((oget res).`1 ++ nseq 16 0) message0] = Some (oget SignObservation.accepted).`2 /\
      accept_digest (oget SignObservation.accepted).`2].
proof.
  proc; seq 1 : (seed = seed0 /\ root = root0 /\ message = message0 /\
    returned_digest_entry Independent.rawhistory seed0 root0 message0 SignObservation.accepted).
  + call (grind_returned_entry seed0 root0 message0); auto.
  sp 1; if; last by auto.
  exists* SignObservation.accepted; elim* => answer.
  call (finish_keeps_randomizer_entry (oget answer).`1
    (hmsg_input seed0 root0 ((oget answer).`1 ++ nseq 16 0) message0) (oget answer).`2).
  auto; rewrite /returned_digest_entry; smt().
qed.

lemma observed_signer_entry_equiv seed0 root0 message0 :
  equiv[RawSigner(Independent).sign ~ ObservedSigner(Independent).sign :
    ={seed,root,random,message,shuffle,glob Independent} /\
    seed{1} = seed0 /\ root{1} = root0 /\ message{1} = message0 ==>
    ={res,glob Independent} /\
    (res{2} <> None =>
      Independent.rawhistory{2}.[hmsg_input seed0 root0
        ((oget res{2}).`1 ++ nseq 16 0) message0] =
        Some (oget SignObservation.accepted{2}).`2)].
proof.
  conseq (observed_signer_refines Independent) _ (observed_signer_entry seed0 root0 message0); smt().
qed.

module SignatureDigestEvent = {
  proc run(p : digest -> bool, seed root random message shuffle : raw_input) : bool = {
    var signed;
    signed <@ RawSigner(Independent).sign(seed,root,random,message,shuffle);
    return signed <> None /\ p (oget Independent.rawhistory.[
      hmsg_input seed root ((oget signed).`1 ++ nseq 16 0) message]);
  }
}.

lemma signature_digest_observation :
  equiv[SignatureDigestEvent.run ~ ObservedSignEvent.run :
    ={p,seed,root,random,message,shuffle,glob Independent} ==> ={res}].
proof.
  proc; exists* seed{2}, root{2}, message{2}; elim* => seed0 root0 message0.
  call (observed_signer_entry_equiv seed0 root0 message0); auto; smt().
qed.

lemma signature_digest_bound p q0 seed root random message shuffle &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[SignatureDigestEvent.run(p,seed,root,random,message,shuffle) @ &m : res] <=
    accepted_probability p + revisit_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have he :
    Pr[SignatureDigestEvent.run(p,seed,root,random,message,shuffle) @ &m : res] =
    Pr[ObservedSignEvent.run(p,seed,root,random,message,shuffle) @ &m : res]
    by byequiv signature_digest_observation => //.
  rewrite he; exact (complete_sign_accepted_bound p q0 seed root random message shuffle &m
    hq hsize hrecord hf hs hr).
qed.
