(* Dropping hidden-prefix programs is invisible until a public input guesses a hidden node. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen WotsReference LeafCommitmentHybrid.
require import ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainRedactionTables.
module ChainGuess = { var bad : bool }.
module ChainHybridPrefix = {
  proc hash(x : raw_input) : digest = {
    var d;
    ChainGuess.bad <- ChainGuess.bad \/ mem (map node DualDigest.hidden) (leaf_suffix_candidate x);
    d <@ Independent.hash(x); return d;
  }
  proc derive = RedactedChainPrefix.derive
}.
module HybridCachedChain = {
  proc hash = ChainHybridPrefix.hash
  proc derive = RedactedChainPrefix.derive
  proc value(seed : raw_input, layer tree kp index stop : int) : raw_input = {
    var result;
    if ((seed,layer,tree,kp,index)=(ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index) /\
        0<=stop<=7) {
      if (stop<=ChainCut.cut) { ChainRedaction.opened <- true; result <- nseq 16 0; }
      else { result <- nth (nseq 16 0) ChainStage.values stop; }
    } else {
      result <@ ConcreteChain(ChainHybridPrefix).value(seed,layer,tree,kp,index,stop);
    }
    return result;
  }
}.

lemma chain_hybrid_hash_lossless : islossless ChainHybridPrefix.hash.
proof. proc; call independent_hash_ll; auto. qed.
lemma chain_hybrid_value_lossless : islossless HybridCachedChain.value.
proof.
  proc; if; first by if; auto.
  call (concrete_chain_value_lossless ChainHybridPrefix chain_hybrid_hash_lossless redacted_chain_derive_lossless); auto.
qed.
lemma chain_public_query_redaction :
  equiv [Independent.hash ~ ChainHybridPrefix.hash :
    ={arg} /\ !ChainGuess.bad{2} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} ==>
    !ChainGuess.bad{2} => ={res} /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2}].
proof.
  proc; case (mem (map node DualDigest.hidden{2}) (leaf_suffix_candidate x{2})).
  + wp; call{2} independent_hash_ll; sp 1 0; if{1}; auto; smt(full_digest_ll).
  inline Independent.hash; sp 1 3; if.
  + auto; rewrite /chain_public_agree; smt(domE).
  + auto; smt(chain_public_both_update get_set_sameE).
  auto; rewrite /chain_public_agree; smt().
qed.
lemma chain_private_query_redaction :
  equiv [RedactedChainPrefix.derive ~ RedactedChainPrefix.derive :
    ={arg,ChainRedaction.opened,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2} ==>
    ={res,ChainRedaction.opened} /\
    chain_private_agree (wots_key ChainStage.layer{2} ChainStage.tree{2} ChainStage.kp{2} ChainStage.index{2})
      Independent.secrethistory{1} Independent.secrethistory{2}].
proof.
  proc; if; first auto.
  + auto.
  inline Independent.derive; sp; if.
  + auto; rewrite /chain_private_agree; smt(domE).
  + auto; smt(chain_private_both_update get_set_sameE).
  auto; rewrite /chain_private_agree; smt().
qed.
