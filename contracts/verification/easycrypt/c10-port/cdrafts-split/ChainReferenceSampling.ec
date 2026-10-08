(* Sampling an existing complete reference changes neither memo table nor its chain values. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen RawChainTrace WotsReference WotsChainSplit.
require import PublicTargetSampling PrivateValueSampling ChainStageSampling ChainStartSampling ChainReferenceEntries.

lemma public_sample_existing target0 d h0 :
  hoare [PublicTargetSample.sample : PublicTargetSample.target=target0 /\
    Independent.rawhistory=h0 /\ h0.[target0]=Some d ==>
    Independent.rawhistory=h0 /\ PublicTargetSample.value=d].
proof. proc; inline *; sp; if; auto; smt(domE). qed.
lemma private_sample_existing target0 d s0 :
  hoare [PrivateValueSample.sample : PrivateValueSample.target=target0 /\
    Independent.secrethistory=s0 /\ s0.[target0]=Some d ==>
    Independent.secrethistory=s0 /\ PrivateValueSample.value=d].
proof. proc; inline *; sp; if; auto; smt(domE). qed.

lemma chain_start_existing seed0 layer0 tree0 kp0 i0 h0 s0 :
  hoare [ChainStart.initialize :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ ChainStage.step=0 /\
    ChainStage.current=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 0 /\
    stored_wots_values h0 s0 seed0 layer0 tree0 kp0 i0 ChainStage.values 0].
proof.
  proc; wp; call (private_sample_existing (wots_key layer0 tree0 kp0 i0)
    (oget s0.[wots_key layer0 tree0 kp0 i0]) s0).
  auto; rewrite /chain_reference;
    smt(domE wots_partial_zero stored_wots_initial).
qed.

lemma chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 n :
  0<=n<7 =>
  hoare [ChainStage.advance :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 /\ ChainStage.step=n /\
    ChainStage.current=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 n /\
    stored_wots_values h0 s0 seed0 layer0 tree0 kp0 i0 ChainStage.values n ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 /\ ChainStage.step=n+1 /\
    ChainStage.current=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 (n+1) /\
    stored_wots_values h0 s0 seed0 layer0 tree0 kp0 i0 ChainStage.values (n+1)].
proof.
  move=> hn; proc; wp.
  call (public_sample_existing
    (chain_input seed0 layer0 tree0 kp0 i0 n (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 n))
    (oget h0.[chain_input seed0 layer0 tree0 kp0 i0 n (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 n)]) h0).
  auto;
    smt(wots_reference_entry stored_wots_next).
qed.

module CompleteChainCache = {
  proc sample() : unit = {
    ChainStart.initialize();
    ChainStage.advance(); ChainStage.advance(); ChainStage.advance();
    ChainStage.advance(); ChainStage.advance(); ChainStage.advance(); ChainStage.advance();
  }
}.
lemma complete_chain_existing seed0 layer0 tree0 kp0 i0 h0 s0 :
  hoare [CompleteChainCache.sample :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    stored_wots_values h0 s0 seed0 layer0 tree0 kp0 i0 ChainStage.values 7].
proof.
  have hn0 : 0<=0<7 by smt().
  have hn1 : 0<=1<7 by smt().
  have hn2 : 0<=2<7 by smt().
  have hn3 : 0<=3<7 by smt().
  have hn4 : 0<=4<7 by smt().
  have hn5 : 0<=5<7 by smt().
  have hn6 : 0<=6<7 by smt().
  proc.
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 6 hn6).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 5 hn5).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 4 hn4).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 3 hn3).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 2 hn2).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 1 hn1).
  call (chain_stage_existing seed0 layer0 tree0 kp0 i0 h0 s0 0 hn0).
  call (chain_start_existing seed0 layer0 tree0 kp0 i0 h0 s0); auto; smt().
qed.
