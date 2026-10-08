(* Compose the fresh memo sampler with the independent hidden/visible vector program. *)
require import AllCore List Distr DList FMap.
require import C10RawOracle C10Randomizer PrefixGuess PrefixHybrid RawKeygen.
require import ChainStageSampling CachedChainOracle ChainReferenceSampling ProgrammedChain ChainVectorProgram.
require import DualDigestSampling DualChainVector SeparatedChainVector DigestVectorSampling ChainVectorInstall.
require import ChainTableInstallation VisibleChainInstallation.

module IndexedRandomChain = {
  proc sample() : unit = {
    DualDigest.hidden <$ dlist full_digest 8;
    DualDigest.visible <$ dlist full_digest 8;
    IndexedChainInstall.run();
  }
}.
lemma indexed_random_chain_projection :
  equiv[ListChainVector.run ~ IndexedRandomChain.sample :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index,
      ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  proc; call indexed_chain_install_projection;
    inline ListEightDigests.sample FullDigestLists.Sample.sample; auto.
qed.

lemma complete_chain_programmed_projection :
  equiv[CompleteChainCache.sample ~ ProgrammedChain.sample :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  conseq programmed_chain_complete; smt().
qed.

lemma complete_chain_vector_projection :
  equiv[CompleteChainCache.sample ~ ChainVectorProgram.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity ProgrammedChain.sample
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_programmed_projection.
  conseq programmed_chain_vector; smt().
qed.

lemma complete_chain_called_projection :
  equiv[CompleteChainCache.sample ~ CalledChainVectorProgram.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity ChainVectorProgram.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_vector_projection.
  conseq called_chain_vector_projection; smt().
qed.

lemma complete_chain_dual_projection :
  equiv[CompleteChainCache.sample ~ DualChainVectorProgram.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity CalledChainVectorProgram.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_called_projection.
  conseq called_dual_chain_vector_projection; smt().
qed.

lemma complete_chain_separated_projection :
  equiv[CompleteChainCache.sample ~ SeparatedChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity DualChainVectorProgram.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_dual_projection.
  conseq separated_chain_vector_projection; smt().
qed.

lemma complete_chain_stream_projection :
  equiv[CompleteChainCache.sample ~ StreamChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity SeparatedChainVector.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_separated_projection.
  conseq stream_chain_vector_projection; smt().
qed.

lemma complete_chain_list_projection :
  equiv[CompleteChainCache.sample ~ ListChainVector.run :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity StreamChainVector.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_stream_projection.
  conseq list_chain_vector_projection; smt().
qed.

lemma complete_chain_indexed_projection :
  equiv[CompleteChainCache.sample ~ IndexedRandomChain.sample :
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==>
    ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}].
proof.
  transitivity ListChainVector.run
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ Independent.rawhistory{1}=empty /\ Independent.secrethistory{1}=empty ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values})
    (={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} ==> ={glob Independent,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\ ={ChainStage.current,ChainStage.step,ChainStage.values}) => //.
  + smt().
  + exact complete_chain_list_projection.
  conseq indexed_random_chain_projection; smt().
qed.

lemma selected_vector_hidden cut hidden visible :
  0<=cut<8 => nth (nseq 16 0) (map node (selected_vector cut hidden visible)) cut =
    node (nth (nseq 256 false) hidden cut).
proof.
  move=> hc; rewrite (nth_map (nseq 256 false)) 1:/selected_vector 1:size_mkseq 1:/#.
  by rewrite /selected_vector nth_mkseq 1:/# /selected_digest; smt().
qed.
lemma indexed_random_chain_cut :
  hoare[IndexedRandomChain.sample : 0<=ChainCut.cut<7 ==>
    nth (nseq 16 0) ChainStage.values ChainCut.cut=
      node(nth (nseq 256 false) DualDigest.hidden ChainCut.cut)].
proof.
  proc; inline IndexedChainInstall.run FullChainStep.run; auto; smt(selected_vector_hidden).
qed.
