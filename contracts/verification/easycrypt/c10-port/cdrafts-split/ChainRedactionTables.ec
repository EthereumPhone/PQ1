(* Programmed hidden-prefix entries may differ only at inputs containing a hidden node. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawChainTrace LeafCommitmentHybrid.

op chain_public_agree (hidden : digest list) (hL hR : (raw_input,digest) fmap) =
  forall x, !mem (map node hidden) (leaf_suffix_candidate x) => hL.[x]=hR.[x].
op chain_private_agree (key : raw_input) (hL hR : (raw_input,digest) fmap) =
  forall x, x<>key => hL.[x]=hR.[x].
op chain_visible_agree (cut : int) (hL hR : raw_input list) =
  forall j, 0<=j<8 => cut<j => nth (nseq 16 0) hL j=nth (nseq 16 0) hR j.

lemma chain_public_empty hidden : chain_public_agree hidden empty empty.
proof. by rewrite /chain_public_agree. qed.
lemma chain_private_empty key : chain_private_agree key empty empty.
proof. by rewrite /chain_private_agree. qed.
lemma chain_public_both_update hidden hL hR x d :
  chain_public_agree hidden hL hR =>
  chain_public_agree hidden hL.[x<-d] hR.[x<-d].
proof. rewrite /chain_public_agree; smt(get_setE). qed.
lemma chain_public_hidden_update hidden hL hR x d :
  mem (map node hidden) (leaf_suffix_candidate x) => chain_public_agree hidden hL hR =>
  chain_public_agree hidden hL.[x<-d] hR.
proof. rewrite /chain_public_agree; smt(get_setE). qed.
lemma chain_private_both_update key hL hR x d :
  chain_private_agree key hL hR => chain_private_agree key hL.[x<-d] hR.[x<-d].
proof. rewrite /chain_private_agree; smt(get_setE). qed.
lemma chain_private_hidden_update key hL hR d :
  chain_private_agree key hL hR => chain_private_agree key hL.[key<-d] hR.
proof. rewrite /chain_private_agree; smt(get_setE). qed.

lemma chain_input_hidden_node hidden seed layer tree kp index j :
  0<=j<size hidden =>
  mem (map node hidden) (leaf_suffix_candidate
    (chain_input seed layer tree kp index j (node (nth (nseq 256 false) hidden j)))).
proof.
  move=> hj; rewrite /chain_input padded_leaf_suffix; first by rewrite node_width.
  apply mapP; exists (nth (nseq 256 false) hidden j); split; first exact (mem_nth _ hidden j hj).
  done.
qed.
