(* Public address kind separates the canonical WOTS, Merkle and FORS families. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawChainTrace RawPathReplay RawForsPathReplay WotsLeafReference.
require import ClientGuessCandidates ForsInputSeparation AddressedInputFields AddressedNodeCollision AddressedForsException.
require import AddressedWotsCanonicity AddressedForsCanonicity AddressedMerkleCanonicity AddressedTreeLog.

op public_address_kind (x : raw_input) = (address_field_bytes (take 32 (drop 32 (take 64 x)))).`3.

lemma public_address_kind_same x y :
  same_node_address x y => public_address_kind x=public_address_kind y.
proof. rewrite /same_node_address /public_address_kind; smt(). qed.

lemma public_address_kind_input seed layer tree kind kp ci cp ha payload :
  size seed=32 => public_address_kind (seed++address layer tree kind kp ci cp ha++payload)=be 4 kind.
proof.
  move=> hs; rewrite /public_address_kind
    (node_prefix seed (address layer tree kind kp ci cp ha) payload hs (raw_address_width _ _ _ _ _ _ _)).
  have he := public_input_address_bytes seed (address layer tree kind kp ci cp ha) []
    hs (raw_address_width _ _ _ _ _ _ _).
  rewrite cats0 in he.
  by rewrite he address_field_bytes_exact.
qed.

lemma public_address_kind_pair seed layer tree kind kp ci cp ha lval rval :
  size seed=32 => public_address_kind (seed++address layer tree kind kp ci cp ha++lval++rval)=be 4 kind.
proof.
  move=> hs; have hh := public_address_kind_input seed layer tree kind kp ci cp ha (lval++rval) hs.
  smt(catA).
qed.

lemma canonical_wots_kind h s seed x :
  size seed=32 => canonical_wots_input h s seed x =>
  public_address_kind x=be 4 0 \/ public_address_kind x=be 4 1.
proof.
  move=> hs; rewrite /canonical_wots_input; move=> [hc|hl].
  + elim hc => layer tree kp index step [hv [hr hx]].
    rewrite hx /canonical_wots_chain_input /chain_input; left; exact (public_address_kind_input _ _ _ _ _ _ _ _ _ hs).
  elim hl => layer tree kp [hv [hr hx]].
  rewrite hx /wots_leaf_input; right; exact (public_address_kind_input _ _ _ _ _ _ _ _ _ hs).
qed.

lemma canonical_merkle_kind h s seed x :
  size seed=32 => canonical_merkle_input h s seed x => public_address_kind x=be 4 2.
proof.
  move=> hs [layer tree level parent c [hv [hl [hc hx]]]].
  rewrite hx /canonical_merkle_pair_input /merkle_pair.
  exact (public_address_kind_pair _ _ _ _ _ _ _ _ _ _ hs).
qed.

lemma canonical_fors_kind h s seed x :
  size seed=32 => canonical_fors_input h s seed x => public_address_kind x=be 4 3.
proof.
  move=> hs; rewrite /canonical_fors_input; move=> [hl|hp].
  + elim hl => ht tree index [hv [hk hx]].
    rewrite hx /canonical_fors_leaf_input /fors_leaf_input.
    exact (public_address_kind_input _ _ _ _ _ _ _ _ _ hs).
  elim hp => ht tree level parent c [hv [hl [hc hx]]].
  rewrite hx /canonical_fors_pair_input /fors_pair.
  exact (public_address_kind_pair _ _ _ _ _ _ _ _ _ _ hs).
qed.

lemma canonical_tree_input_unique h s seed x y :
  size seed=32 => canonical_tree_input h s seed x => canonical_tree_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs; rewrite /canonical_tree_input; move=> [hw|hm] [hw'|hm'] he.
  + smt(canonical_wots_input_unique).
  + have hx := canonical_wots_kind h s seed x hs hw.
    have hy := canonical_merkle_kind h s seed y hs hm'.
    have hk := public_address_kind_same x y he; smt(be4_injective).
  + have hx := canonical_merkle_kind h s seed x hs hm.
    have hy := canonical_wots_kind h s seed y hs hw'.
    have hk := public_address_kind_same x y he; smt(be4_injective).
  smt(canonical_merkle_input_unique).
qed.

lemma canonical_tree_fors_separate h s seed x y :
  size seed=32 => canonical_tree_input h s seed x => canonical_fors_input h s seed y =>
  !same_node_address x y.
proof.
  move=> hs; rewrite /canonical_tree_input; move=> [hw|hm] hf; apply/negP => he.
  + have hx := canonical_wots_kind h s seed x hs hw.
    have hy := canonical_fors_kind h s seed y hs hf.
    have hk := public_address_kind_same x y he; smt(be4_injective).
  have hx := canonical_merkle_kind h s seed x hs hm.
  have hy := canonical_fors_kind h s seed y hs hf.
  have hk := public_address_kind_same x y he; smt(be4_injective).
qed.
