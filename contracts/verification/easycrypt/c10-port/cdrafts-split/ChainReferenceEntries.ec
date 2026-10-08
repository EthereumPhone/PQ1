(* A complete WOTS reference determines each recorded transition and cached cut. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen LinearChain LinearSplit RawChainTrace WotsReference WotsChainSplit.

op chain_reference h s seed layer tree kp i =
  wots_key layer tree kp i \in s /\
  linear_recorded h (chain_input seed layer tree kp i) (wots_start s layer tree kp i) (range 0 7).
lemma wots_chain_reference h s seed layer tree kp i :
  wots_prefix h s seed layer tree kp 43 => 0<=i<43 => chain_reference h s seed layer tree kp i.
proof. rewrite /wots_prefix /chain_reference; smt(). qed.

lemma wots_partial_zero h s seed layer tree kp i :
  wots_partial h s seed layer tree kp i 0=wots_start s layer tree kp i.
proof. by rewrite /wots_partial range_geq 1:// /linear_value /=. qed.

lemma wots_reference_entry h s seed layer tree kp i cut :
  chain_reference h s seed layer tree kp i => 0<=cut<7 =>
  exists d, h.[chain_input seed layer tree kp i cut (wots_partial h s seed layer tree kp i cut)]=Some d /\
    wots_partial h s seed layer tree kp i (cut+1)=node d.
proof.
  move=> [hk hr] hc.
  have [hpre [hsuf hend]] := linear_range_split h (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) 0 cut 7 _ _ hr; first 2 smt().
  have hsuf' : linear_recorded h (chain_input seed layer tree kp i)
    (wots_partial h s seed layer tree kp i cut) (range cut 7) by exact hsuf.
  have hmem : chain_input seed layer tree kp i cut (wots_partial h s seed layer tree kp i cut) \in h.
  + move: hsuf'; rewrite (range_ltn cut 7) 1:/# /=; smt().
  exists (oget h.[chain_input seed layer tree kp i cut (wots_partial h s seed layer tree kp i cut)]).
  split; first smt(domE).
  by rewrite /wots_partial rangeSr 1:/# linear_value_rcons /linear_step.
qed.

op stored_wots_values h s seed layer tree kp i (values : raw_input list) n =
  size values=n+1 /\ forall cut, 0<=cut<=n =>
    nth (nseq 16 0) values cut=wots_partial h s seed layer tree kp i cut.

lemma stored_wots_initial h s seed layer tree kp i :
  stored_wots_values h s seed layer tree kp i [wots_start s layer tree kp i] 0.
proof. rewrite /stored_wots_values /=; smt(wots_partial_zero). qed.

lemma stored_wots_next h s seed layer tree kp i values n value :
  0<=n => stored_wots_values h s seed layer tree kp i values n =>
  value=wots_partial h s seed layer tree kp i (n+1) =>
  stored_wots_values h s seed layer tree kp i (rcons values value) (n+1).
proof. rewrite /stored_wots_values; smt(size_rcons nth_rcons). qed.
