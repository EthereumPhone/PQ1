(* Canonical WOTS inputs determined by one retained public/private history.
   The actual callers must establish the recorded-prefix premises separately. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawSignature RawChainTrace.
require import PersistentGrind AcceptedContexts LinearChain WotsReference WotsLeafReference.
require import AddressedNodeCollision AddressedInputFields.
require import ClientGuessCandidates ForsInputSeparation.

op wots_address_valid layer tree kp index step =
  0<=layer<4294967296 /\ 0<=tree<2^64 /\ 0<=kp<4294967296 /\
  0<=index<43 /\ 0<=step<7.

op canonical_wots_chain_input h s seed layer tree kp index step =
  chain_input seed layer tree kp index step
    (linear_value h (chain_input seed layer tree kp index)
      (wots_start s layer tree kp index) (range 0 step)).

op canonical_wots_chain_supported h s seed layer tree kp index step =
  wots_key layer tree kp index \in s /\
  linear_recorded h (chain_input seed layer tree kp index)
    (wots_start s layer tree kp index) (range 0 step).

lemma canonical_wots_chain_extends h h' s s' seed layer tree kp index step :
  extends h h' => extends s s' =>
  canonical_wots_chain_supported h s seed layer tree kp index step =>
  canonical_wots_chain_supported h' s' seed layer tree kp index step /\
  canonical_wots_chain_input h' s' seed layer tree kp index step =
    canonical_wots_chain_input h s seed layer tree kp index step.
proof.
  move=> hh hs [hk hr].
  have hstart := wots_start_extends s s' layer tree kp index hs hk.
  have [hr' hv] := linear_recorded_extends h h' (chain_input seed layer tree kp index)
    (wots_start s layer tree kp index) (range 0 step) hh hr.
  rewrite /canonical_wots_chain_supported /canonical_wots_chain_input hstart.
  move: hs; rewrite /extends; smt(domE).
qed.

lemma canonical_wots_chain_unique h s seed layer tree kp index step
    layer' tree' kp' index' step' :
  size seed=32 => wots_address_valid layer tree kp index step =>
  wots_address_valid layer' tree' kp' index' step' =>
  same_node_address (canonical_wots_chain_input h s seed layer tree kp index step)
    (canonical_wots_chain_input h s seed layer' tree' kp' index' step') =>
  canonical_wots_chain_input h s seed layer tree kp index step =
    canonical_wots_chain_input h s seed layer' tree' kp' index' step'.
proof.
  move=> hs hv hv'.
  rewrite /canonical_wots_chain_input /chain_input => he.
  have ha : address layer tree 0 kp index step 0=address layer' tree' 0 kp' index' step' 0
    by have hp := addressed_prefix_coordinates seed (address layer tree 0 kp index step 0)
      _ seed (address layer' tree' 0 kp' index' step' 0) _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) he; smt().
  have hf := address_fields_injective layer tree 0 kp index step 0
    layer' tree' 0 kp' index' step' 0.
  move: hv hv'; rewrite /wots_address_valid; smt().
qed.

lemma canonical_wots_leaf_extends h h' s s' seed layer tree kp :
  extends h h' => extends s s' => wots_prefix h s seed layer tree kp 43 =>
  wots_leaf_input h' s' seed layer tree kp=wots_leaf_input h s seed layer tree kp.
proof. rewrite /wots_leaf_input; smt(wots_prefix_extends). qed.

lemma canonical_wots_leaf_unique h s seed layer tree kp layer' tree' kp' :
  size seed=32 => wots_address_valid layer tree kp 0 0 =>
  wots_address_valid layer' tree' kp' 0 0 =>
  same_node_address (wots_leaf_input h s seed layer tree kp)
    (wots_leaf_input h s seed layer' tree' kp') =>
  wots_leaf_input h s seed layer tree kp=wots_leaf_input h s seed layer' tree' kp'.
proof.
  move=> hs hv hv'; rewrite /wots_leaf_input => he.
  have ha : address layer tree 1 kp 0 0 0=address layer' tree' 1 kp' 0 0 0
    by have hp := addressed_prefix_coordinates seed (address layer tree 1 kp 0 0 0)
      _ seed (address layer' tree' 1 kp' 0 0 0) _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) he; smt().
  have hf := address_fields_injective layer tree 1 kp 0 0 0 layer' tree' 1 kp' 0 0 0.
  move: hv hv'; rewrite /wots_address_valid; smt().
qed.

lemma canonical_wots_chain_leaf_separate h s seed layer tree kp index step layer' tree' kp' :
  size seed=32 =>
  !same_node_address (canonical_wots_chain_input h s seed layer tree kp index step)
    (wots_leaf_input h s seed layer' tree' kp').
proof.
  move=> hs; rewrite /canonical_wots_chain_input /chain_input /wots_leaf_input.
  apply/negP => he.
  have ha : address layer tree 0 kp index step 0=address layer' tree' 1 kp' 0 0 0
    by have hp := addressed_prefix_coordinates seed (address layer tree 0 kp index step 0)
      _ seed (address layer' tree' 1 kp' 0 0 0) _ hs hs
      (raw_address_width _ _ _ _ _ _ _) (raw_address_width _ _ _ _ _ _ _) he; smt().
  have hf : address_field_bytes (address layer tree 0 kp index step 0)=
    address_field_bytes (address layer' tree' 1 kp' 0 0 0) by rewrite ha.
  rewrite !address_field_bytes_exact in hf.
  smt(ForsInputSeparation.be4_injective).
qed.

op canonical_wots_input h s seed x =
  (exists layer tree kp index step,
    wots_address_valid layer tree kp index step /\
    canonical_wots_chain_supported h s seed layer tree kp index step /\
    x=canonical_wots_chain_input h s seed layer tree kp index step) \/
  (exists layer tree kp,
    wots_address_valid layer tree kp 0 0 /\ wots_prefix h s seed layer tree kp 43 /\
    x=wots_leaf_input h s seed layer tree kp).

lemma canonical_wots_input_extends h h' s s' seed x :
  extends h h' => extends s s' => canonical_wots_input h s seed x =>
  canonical_wots_input h' s' seed x.
proof.
  move=> hh hs; rewrite /canonical_wots_input; move=> [hc|hl].
  + left; elim hc => layer tree kp index step [hv [hr hx]].
    exists layer tree kp index step; smt(canonical_wots_chain_extends).
  right; elim hl => layer tree kp [hv [hr hx]].
  exists layer tree kp; smt(wots_prefix_extends canonical_wots_leaf_extends).
qed.

lemma canonical_wots_input_unique h s seed x y :
  size seed=32 => canonical_wots_input h s seed x => canonical_wots_input h s seed y =>
  same_node_address x y => x=y.
proof.
  move=> hs; rewrite /canonical_wots_input.
  move=> [hc|hl] [hc'|hl'] he.
  + elim hc => layer tree kp index step [hv [hr hx]].
    elim hc' => layer' tree' kp' index' step' [hv' [hr' hy]].
    smt(canonical_wots_chain_unique).
  + elim hc => layer tree kp index step [hv [hr hx]].
    elim hl' => layer' tree' kp' [hv' [hr' hy]].
    smt(canonical_wots_chain_leaf_separate).
  + elim hl => layer tree kp [hv [hr hx]].
    elim hc' => layer' tree' kp' index' step' [hv' [hr' hy]].
    have hsym : same_node_address y x by move: he; rewrite /same_node_address; smt().
    smt(canonical_wots_chain_leaf_separate).
  elim hl => layer tree kp [hv [hr hx]].
  elim hl' => layer' tree' kp' [hv' [hr' hy]].
  smt(canonical_wots_leaf_unique).
qed.
