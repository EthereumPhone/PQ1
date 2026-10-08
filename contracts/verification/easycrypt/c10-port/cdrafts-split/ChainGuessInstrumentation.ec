(* Guess monitoring records exactly the public suffix candidates and changes no result. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LeafCommitmentHybrid ChainValueView ChainStageSampling CachedChainOracle DualDigestSampling.
require import RedactedChainOracle ChainPublicHybrid NodeVectorMass.

op chain_query_hit hidden queries = has (fun x => mem (map node hidden) (leaf_suffix_candidate x)) queries.
lemma chain_query_hit_nil hidden : chain_query_hit hidden []=false.
proof. by rewrite /chain_query_hit. qed.
lemma chain_query_hit_rcons hidden queries x :
  chain_query_hit hidden (rcons queries x)=
    (chain_query_hit hidden queries \/ mem (map node hidden) (leaf_suffix_candidate x)).
proof. rewrite /chain_query_hit -cats1 has_cat /=; smt(). qed.
lemma chain_query_vector_hit hidden queries :
  chain_query_hit hidden queries = node_vector_hit hidden (map leaf_suffix_candidate queries).
proof. rewrite /chain_query_hit /node_vector_hit !hasP; smt(mapP). qed.
lemma node_vector_hit_cat hidden xs ys :
  node_vector_hit hidden (xs++ys)=(node_vector_hit hidden xs \/ node_vector_hit hidden ys).
proof. rewrite /node_vector_hit !hasP; smt(mem_cat). qed.

lemma chain_hash_instrumentation hidden0 :
  equiv [ChainHybridPrefix.hash ~ Independent.hash :
    ={arg,glob Independent} /\ DualDigest.hidden{1}=hidden0 /\
    ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2} ==>
    ={res,glob Independent} /\
    ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}].
proof. proc; inline Independent.hash; sp 3 1; if; auto; smt(chain_query_hit_rcons). qed.

lemma chain_fallback_instrumentation hidden0 :
  equiv [ConcreteChain(ChainHybridPrefix).value ~ ConcreteChain(RedactedChainPrefix).value :
    ={arg,glob Independent,ChainRedaction.opened,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    DualDigest.hidden{1}=hidden0 /\ ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2} ==>
    ={res,glob Independent,ChainRedaction.opened} /\
    ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}].
proof.
  proc; inline RawWots(PreparationView(ChainHybridPrefix)).chain RawWots(PreparationView(RedactedChainPrefix)).chain.
  wp; while (={seed0,layer0,tree0,kp0,index0,current0,j,stop0,glob Independent,ChainRedaction.opened} /\
    DualDigest.hidden{1}=hidden0 /\ ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}).
  + wp; call (chain_hash_instrumentation hidden0); auto.
  wp; inline PreparationView(ChainHybridPrefix).wots PreparationView(RedactedChainPrefix).wots.
  wp; call (_ : ={glob Independent,ChainRedaction.opened,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index}); first by sim.
  auto.
qed.
lemma chain_value_instrumentation hidden0 :
  equiv [HybridCachedChain.value ~ RedactedCachedChain.value :
    ={arg,glob Independent,ChainRedaction.opened,ChainCut.cut,ChainStage.seed,ChainStage.layer,
      ChainStage.tree,ChainStage.kp,ChainStage.index,ChainStage.values} /\
    DualDigest.hidden{1}=hidden0 /\ ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2} ==>
    ={res,glob Independent,ChainRedaction.opened} /\
    ChainGuess.bad{1}=chain_query_hit hidden0 Independent.queries{2}].
proof.
  proc; if; first auto.
  + if; auto.
  call (chain_fallback_instrumentation hidden0); auto.
qed.
