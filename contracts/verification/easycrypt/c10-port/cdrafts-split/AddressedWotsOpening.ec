(* Actual WOTS recovery needs collisions only at equal seed/address prefixes. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle RawKeygen RawWots RawSignature ClientGuessCandidates.
require import LinearChain RawChainTrace WotsReference WotsChainSplit WotsLeafReference WotsReferenceRoot.
require import WotsRecoveryTrace RecoveryCompression RawRecoveryTrace WotsSignatureValue.
require import VerifierWotsOpening PublicNodeZero WotsZeroSentinel.
require import NodeQueryDomain DomainNodeCollision DomainLinearCollision HmsgShapes.

require import DomainWotsOpening AddressedNodeCollision.

lemma addressed_recovery_reference_prefix h s seed layer tree kp d sigma :
  size seed=32 =>
  same_node_address (recovery_leaf_input h seed layer tree kp d sigma)
    (wots_leaf_input h s seed layer tree kp).
proof.
  move=> hs; rewrite /same_node_address /recovery_leaf_input /wots_leaf_input.
  have hw := raw_address_width layer tree 1 kp 0 0 0.
  by rewrite (node_prefix seed _ _ hs hw) (node_prefix seed _ _ hs hw).
qed.

lemma addressed_recovery_chain_unique h s seed layer tree kp d sigma i :
  size seed=32 => all (fun row => size row=16) sigma =>
  !addressed_node_collision h => wots_prefix h s seed layer tree kp 43 =>
  recovery_prefix h seed layer tree kp d sigma 43 => 0<=i<43 =>
  recovery_endpoint h seed layer tree kp d sigma i = wots_endpoint h s seed layer tree kp i =>
  nth (nseq 16 0) sigma i = wots_partial h s seed layer tree kp i (digit 3 d i).
proof.
  move=> hs hw hc hp hr hi he.
  have [hpre [hsuf hv]] := wots_reference_split h s seed layer tree kp i (digit 3 d i)
    hp hi (raw_digit_bounds d i).
  apply (addressed_raw_chain_start_unique h seed layer tree kp i (range (digit 3 d i) 7)) => //.
  + smt(all_nth_width).
  + rewrite /wots_partial; apply linear_value_width; rewrite /wots_start; exact (node_width _).
  + exact (hr i hi).
  by rewrite -hv.
qed.

lemma addressed_matching_wots_endpoints h s seed layer tree kp d sigma root leaf :
  size seed=32 => !addressed_node_collision h => wots_root h s seed layer tree kp root =>
  all (fun row => size row=16) sigma =>
  h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf => node leaf=root =>
  forall i, 0<=i<43 =>
    recovery_endpoint h seed layer tree kp d sigma i = wots_endpoint h s seed layer tree kp i.
proof.
  move=> hs hc [hp [rd [hr hv]]] hw hl he.
  have hi : recovery_leaf_input h seed layer tree kp d sigma = wots_leaf_input h s seed layer tree kp.
  + have haddr := addressed_recovery_reference_prefix h s seed layer tree kp d sigma hs.
    apply (addressed_recorded_equal_input h) => //;
      smt(domain_recovery_leaf domain_wots_leaf domE).
  have hf : flatten (recovery_elements h seed layer tree kp d sigma 43) =
    flatten (wots_elements h s seed layer tree kp 43).
  + move: hi; rewrite /recovery_leaf_input /wots_leaf_input -!catA; smt(catsI).
  apply (padded_rows_injective (recovery_endpoint h seed layer tree kp d sigma)
    (wots_endpoint h s seed layer tree kp) 43) => //.
  smt(recovery_endpoint_width wots_endpoint_width).
qed.

lemma addressed_recovery_trace_opens_reference h s seed layer tree kp message sigma count root :
  size seed=32 =>
  wots_root h s seed layer tree kp root => rows_width 43 sigma => 0<=count<4294967296 =>
  wots_recovery_trace h seed layer tree kp message sigma count root =>
  !addressed_node_collision h => !public_node_zero h =>
  wots_verifier_opening h s seed layer tree kp message root (sigma,count).
proof.
  move=> hseed hr [hs hw] hc [d [hd ht]] hn hz.
  have ha : count_accepts d by smt(wots_zero_is_public).
  have [hp [leaf [hl he]]] : recovery_prefix h seed layer tree kp d sigma 43 /\
    exists leaf, h.[recovery_leaf_input h seed layer tree kp d sigma]=Some leaf /\ root=node leaf by smt().
  rewrite /wots_verifier_opening /=; split; first exact hr.
  split; first exact hc.
  exists d; split; first exact ha.
  split; first exact hd.
  rewrite /wots_signature; split; first exact hs.
  move=> i hi.
  have heq := addressed_matching_wots_endpoints h s seed layer tree kp d sigma root leaf
    hseed hn hr hw hl _ i hi; first by smt().
  apply (addressed_recovery_chain_unique h s seed layer tree kp d sigma i) => //.
  by move: hr; rewrite /wots_root; smt().
qed.
