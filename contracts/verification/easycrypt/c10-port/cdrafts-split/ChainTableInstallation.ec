(* Hidden-input programs and visible-suffix programs agree away from hidden-node guesses. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawChainTrace WotsReference PrefixGuess.
require import ChainStageSampling CachedChainOracle DualDigestSampling ChainRedactionTables.

op selected_digest (cut : int) (hidden visible : digest list) (j : int) =
  if j<=cut then nth (nseq 256 false) hidden j else nth (nseq 256 false) visible j.
op selected_vector cut hidden visible = mkseq (selected_digest cut hidden visible) 8.

module FullChainStep = {
  proc run(j : int) : unit = {
    Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index
      j (node (selected_digest ChainCut.cut DualDigest.hidden DualDigest.visible j))] <-
      selected_digest ChainCut.cut DualDigest.hidden DualDigest.visible (j+1);
  }
}.
module VisibleChainStep = {
  proc run(j : int) : unit = {
    if (ChainCut.cut<j) {
      Independent.rawhistory.[chain_input ChainStage.seed ChainStage.layer ChainStage.tree ChainStage.kp ChainStage.index
        j (node (nth (nseq 256 false) DualDigest.visible j))] <- nth (nseq 256 false) DualDigest.visible (j+1);
    }
  }
}.
lemma chain_step_installation :
  equiv [FullChainStep.run ~ VisibleChainStep.run :
    ={arg,glob DualDigest,ChainCut.cut,ChainStage.seed,ChainStage.layer,ChainStage.tree,ChainStage.kp,ChainStage.index} /\
    0<=j{1}<7 /\ size DualDigest.hidden{1}=8 /\
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2} ==>
    chain_public_agree DualDigest.hidden{2} Independent.rawhistory{1} Independent.rawhistory{2}].
proof.
  proc; if{2}; auto; rewrite /selected_digest;
    smt(chain_public_both_update chain_public_hidden_update chain_input_hidden_node).
qed.

lemma selected_vector_literal cut hidden visible :
  selected_vector cut hidden visible =
    [selected_digest cut hidden visible 0; selected_digest cut hidden visible 1;
     selected_digest cut hidden visible 2; selected_digest cut hidden visible 3;
     selected_digest cut hidden visible 4; selected_digest cut hidden visible 5;
     selected_digest cut hidden visible 6; selected_digest cut hidden visible 7].
proof.
  rewrite /selected_vector (mkseqS _ 7) 1:// (mkseqS _ 6) 1:// (mkseqS _ 5) 1://
    (mkseqS _ 4) 1:// (mkseqS _ 3) 1:// (mkseqS _ 2) 1:// (mkseqS _ 1) 1:// (mkseqS _ 0) 1://.
  by rewrite mkseq0 /=.
qed.
lemma selected_vector_visible cut hidden visible :
  size visible=8 => chain_visible_agree cut (map node (selected_vector cut hidden visible)) (map node visible).
proof.
  move=> hv; rewrite /chain_visible_agree => j hj hcut.
  have hs : size (selected_vector cut hidden visible)=8 by rewrite /selected_vector size_mkseq.
  rewrite !(nth_map (nseq 256 false)) 1,2:/# /selected_vector nth_mkseq 1:/# /selected_digest.
  smt().
qed.
