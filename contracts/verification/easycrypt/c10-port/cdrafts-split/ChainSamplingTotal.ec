(* Silent memo precomputation terminates and reuses an already complete reference surely. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import PrivateValueSampling PublicTargetSampling ChainStageSampling ChainStartSampling.
require import ChainReferenceEntries ChainReferenceSampling.

lemma private_memo_sample_lossless : islossless PrivateMemoSample.get.
proof. proc; if; auto; smt(full_digest_ll). qed.
lemma public_memo_sample_lossless : islossless PublicMemoSample.get.
proof. proc; if; auto; smt(full_digest_ll). qed.
lemma chain_start_lossless : islossless ChainStart.initialize.
proof. proc; inline PrivateValueSample.sample; wp; call private_memo_sample_lossless; auto. qed.
lemma chain_stage_lossless : islossless ChainStage.advance.
proof. proc; inline PublicTargetSample.sample; wp; call public_memo_sample_lossless; auto. qed.
lemma complete_chain_sample_lossless : islossless CompleteChainCache.sample.
proof.
  proc; call chain_stage_lossless; call chain_stage_lossless; call chain_stage_lossless;
    call chain_stage_lossless; call chain_stage_lossless; call chain_stage_lossless;
    call chain_stage_lossless; call chain_start_lossless; auto.
qed.
lemma complete_chain_existing_sure seed0 layer0 tree0 kp0 i0 h0 s0 :
  phoare[CompleteChainCache.sample :
    (ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index)=(seed0,layer0,tree0,kp0,i0) /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    chain_reference h0 s0 seed0 layer0 tree0 kp0 i0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    stored_wots_values h0 s0 seed0 layer0 tree0 kp0 i0 ChainStage.values 7] = 1%r.
proof.
  conseq complete_chain_sample_lossless (complete_chain_existing seed0 layer0 tree0 kp0 i0 h0 s0); smt().
qed.
