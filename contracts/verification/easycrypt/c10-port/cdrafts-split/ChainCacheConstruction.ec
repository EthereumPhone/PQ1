(* Silent chain sampling constructs a complete cache, including from fresh tables. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference WotsChainSplit.
require import PersistentGrind AcceptedContexts LinearChain ChainReferenceEntries ChainCacheInvariant ChainPrefixCache.
require import PublicTargetSampling PrivateValueSampling ChainStageSampling ChainStartSampling ChainReferenceSampling.

lemma public_sample_records h0 x0 :
  hoare [PublicTargetSample.sample : Independent.rawhistory=h0 /\ PublicTargetSample.target=x0 ==>
    extends h0 Independent.rawhistory /\ Independent.rawhistory.[x0]=Some PublicTargetSample.value].
proof. proc; inline *; sp; if; auto; smt(extends_refl extends_insert get_set_sameE domE). qed.
lemma private_sample_records x0 :
  hoare [PrivateValueSample.sample : PrivateValueSample.target=x0 ==>
    Independent.secrethistory.[x0]=Some PrivateValueSample.value].
proof. proc; inline *; sp; if; auto; smt(get_set_sameE domE). qed.

lemma chain_start_constructs c :
  hoare [ChainStart.initialize :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c /\
    ChainStage.step=0 /\
    ChainStage.current=wots_partial Independent.rawhistory Independent.secrethistory c.`1 c.`2 c.`3 c.`4 c.`5 0 /\
    prefix_chain_cache Independent.rawhistory Independent.secrethistory c ChainStage.values 0].
proof.
  proc; wp; call (private_sample_records (wots_key c.`2 c.`3 c.`4 c.`5)); auto.
  rewrite /wots_start; smt(domE prefix_cache_zero wots_partial_zero).
qed.

lemma chain_stage_constructs c n :
  0<=n =>
  hoare [ChainStage.advance :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c /\
    ChainStage.step=n /\
    ChainStage.current=wots_partial Independent.rawhistory Independent.secrethistory c.`1 c.`2 c.`3 c.`4 c.`5 n /\
    prefix_chain_cache Independent.rawhistory Independent.secrethistory c ChainStage.values n ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c /\
    ChainStage.step=n+1 /\
    ChainStage.current=wots_partial Independent.rawhistory Independent.secrethistory c.`1 c.`2 c.`3 c.`4 c.`5 (n+1) /\
    prefix_chain_cache Independent.rawhistory Independent.secrethistory c ChainStage.values (n+1)].
proof.
  move=> hn; proc;
  exists* Independent.rawhistory,Independent.secrethistory,ChainStage.values,ChainStage.current; elim* => h0 s0 values0 current0.
  wp; call (public_sample_records h0 (chain_input c.`1 c.`2 c.`3 c.`4 c.`5 n current0)).
  auto; smt(prefix_cache_extends prefix_cache_step prefix_cache_current_extends prefix_cache_next_value extends_refl).
qed.

lemma complete_chain_constructs c :
  hoare [CompleteChainCache.sample :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=c /\
    ChainStage.step=7 /\
    complete_chain_cache Independent.rawhistory Independent.secrethistory c ChainStage.values].
proof.
  have hn0 : 0<=0 by smt().
  have hn1 : 0<=1 by smt().
  have hn2 : 0<=2 by smt().
  have hn3 : 0<=3 by smt().
  have hn4 : 0<=4 by smt().
  have hn5 : 0<=5 by smt().
  have hn6 : 0<=6 by smt().
  proc.
  call (chain_stage_constructs c 6 hn6).
  call (chain_stage_constructs c 5 hn5).
  call (chain_stage_constructs c 4 hn4).
  call (chain_stage_constructs c 3 hn3).
  call (chain_stage_constructs c 2 hn2).
  call (chain_stage_constructs c 1 hn1).
  call (chain_stage_constructs c 0 hn0).
  call (chain_start_constructs c); auto; smt(prefix_cache_complete).
qed.
