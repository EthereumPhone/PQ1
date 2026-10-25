(* The initialized wrapper's internal verifier replays the second equal
   signature. Its removal in this proof view preserves results and both maps,
   including final refusal. The original program and its cost bound stay intact. *)
require import AllCore List FMap.
require import C10RawOracle C10RawGrind C10HashDomains PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawWrapper.
require import PersistentGrind AcceptedContexts MerkleRootWitness SignerTrace ForestReferenceHistory.
require import SignerReturnedOpening SignerFinishState WrapperMemoProjection WrapperVerifierReplay.

module WrapperWithoutInternalVerify (O : PrefixOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, result;
    result <- None;
    if (ready) {
      first <@ RawSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first <> None) {
        second <@ RawSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second <> None /\ first=second) {
          if (final_guard) { result <- first; }
        }
      }
    }
    return result;
  }
}.

lemma wrapper_signer_table_projection (S <: CompleteSigner {-Independent}) :
  equiv [S(Independent).sign ~ S(Independent).sign :
    ={arg,glob S,Independent.rawhistory,Independent.secrethistory} ==>
    ={res,glob S,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc (={Independent.rawhistory,Independent.secrethistory}) => //.
  + exact wrapper_memo_hash_projection.
  exact wrapper_memo_derive_projection.
qed.

lemma wrapper_raw_signer_keeps_root seed0 root0 :
  hoare [RawSigner(Independent).sign :
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0 ==>
    merkle_root_witness Independent.rawhistory Independent.secrethistory seed0 1 0 root0].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (complete_signer_histories RawSigner s0 h0); smt(extends_refl merkle_root_witness_extends).
qed.

lemma wrapper_internal_verify_projection seed_ref root_ref message_ref :
  equiv [RawWrapper(Independent).sign ~ WrapperWithoutInternalVerify(Independent).sign :
    seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  proc; sp 1 1; if => //.
  seq 1 1 : (seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={seed,root,random,message,shuffle_b,final_guard,first,result,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref).
  + call (_ : ={arg,Independent.rawhistory,Independent.secrethistory} /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref).
    - conseq (wrapper_signer_table_projection RawSigner) (wrapper_raw_signer_keeps_root seed_ref root_ref); smt().
    auto.
  if => //.
  seq 1 1 : (seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={seed,root,message,final_guard,first,second,result,Independent.rawhistory,Independent.secrethistory} /\
    (second{1}<>None => exists d, accept_digest d /\
      Independent.rawhistory{1}.[hmsg_input seed_ref (pad root_ref) (pad (oget second{1}).`1) message_ref]=Some d /\
      signer_finish_opening Independent.rawhistory{1} Independent.secrethistory{1} seed_ref d (oget second{1}) root_ref)).
  + call (_ : seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
      ={res,Independent.rawhistory,Independent.secrethistory} /\
      (res{1}<>None => exists d, accept_digest d /\
        Independent.rawhistory{1}.[hmsg_input seed_ref (pad root_ref) (pad (oget res{1}).`1) message_ref]=Some d /\
        signer_finish_opening Independent.rawhistory{1} Independent.secrethistory{1} seed_ref d (oget res{1}) root_ref)).
    - conseq (wrapper_signer_table_projection RawSigner)
        (raw_signer_complete_opening seed_ref root_ref message_ref); smt().
    auto.
  if => //.
  conseq (_ : exists d, seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={final_guard,first,result,Independent.rawhistory,Independent.secrethistory} /\
    accept_digest d /\
    Independent.rawhistory{1}.[hmsg_input seed_ref (pad root_ref) (pad (oget first{1}).`1) message_ref]=Some d /\
    signer_finish_opening Independent.rawhistory{1} Independent.secrethistory{1} seed_ref d (oget first{1}) root_ref ==> _).
  + smt().
  elim* => d.
  exists* first{1},Independent.rawhistory{1},Independent.secrethistory{1}; elim* => sig_ref h_ref s_ref.
  wp; call{1} (wrapper_verify_opening_total seed_ref root_ref message_ref (oget sig_ref) d h_ref s_ref).
  auto; smt().
qed.
