(* Chain-position interface for the complete release-guarded wrapper view.
   Internal plans request endpoints; signature positions are requested only
   after both plans agree and the final guard admits release. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawSigner RawWrapper.
require import MerkleRootWitness ChainValueView WrapperInternalVerify WrapperWotsRelease.
require import WrapperReleasedWots WrapperChainWotsPlanSigner.

module WrapperChainReleasedWots (O : ChainOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, signature, result;
    result <- None;
    if (ready) {
      first <@ WrapperChainWotsPlanSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first<>None) {
        second <@ WrapperChainWotsPlanSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second<>None /\ first=second) {
          if (final_guard) {
            signature <@ WrapperWotsRelease(O).run(seed,oget first);
            result <- Some signature;
          }
        }
      }
    }
    return result;
  }
}.

lemma wrapper_chain_released_projection (O <: PrefixOracle) :
  equiv [WrapperReleasedWots(O,ConcreteChain(O)).sign ~ WrapperChainReleasedWots(ConcreteChain(O)).sign :
    ={arg,glob O} ==> ={res,glob O}].
proof.
  proc; sp 1 1; if => //.
  seq 1 1 : (={seed,root,random,message,shuffle_b,final_guard,first,result,glob O}).
  + call (wrapper_chain_wots_sign_projection O); auto.
  if => //.
  seq 1 1 : (={seed,root,first,second,final_guard,result,glob O}).
  + call (wrapper_chain_wots_sign_projection O); auto.
  if => //; if => //.
  wp; call (_ : ={arg,glob O} ==> ={res,glob O}); first by sim.
  auto.
qed.

lemma wrapper_chain_released_lossless (O <: ChainOracle) :
  islossless O.hash => islossless O.derive => islossless O.value =>
  islossless WrapperChainReleasedWots(O).sign.
proof.
  move=> hh hd hv; proc; sp 1; if; last auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (wrapper_chain_wots_sign_lossless O hh hd hv); auto.
  if; last auto.
  seq 1 : true 1%r 1%r 0%r 0%r => //.
  + call (wrapper_chain_wots_sign_lossless O hh hd hv); auto.
  if; last auto.
  if; last auto.
  wp; call (wrapper_wots_release_lossless O hv); auto.
qed.

lemma wrapper_chain_released_original seed_ref root_ref message_ref :
  equiv [RawWrapper(Independent).sign ~ WrapperChainReleasedWots(ConcreteChain(Independent)).sign :
    seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
    ={arg,Independent.rawhistory,Independent.secrethistory} /\
    merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
    ={res,Independent.rawhistory,Independent.secrethistory}].
proof.
  transitivity WrapperReleasedWots(Independent,ConcreteChain(Independent)).sign
    (seed{1}=seed_ref /\ root{1}=pad root_ref /\ message{1}=message_ref /\
      ={arg,Independent.rawhistory,Independent.secrethistory} /\
      merkle_root_witness Independent.rawhistory{1} Independent.secrethistory{1} seed_ref 1 0 root_ref ==>
      ={res,Independent.rawhistory,Independent.secrethistory})
    (={arg,glob Independent} ==> ={res,glob Independent}) => //.
  + smt().
  + exact (wrapper_released_wots_projection seed_ref root_ref message_ref).
  exact (wrapper_chain_released_projection Independent).
qed.
