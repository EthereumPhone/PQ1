(* Public and private memo extensions preserve the selected chain cache. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid RawKeygen.
require import PersistentGrind AcceptedContexts MonotoneHistory LinearChain LinearSplit RawChainTrace.
require import WotsReference WotsChainSplit ChainReferenceEntries.

lemma chain_reference_extends h h' s s' seed layer tree kp i :
  extends h h' => extends s s' => chain_reference h s seed layer tree kp i =>
  chain_reference h' s' seed layer tree kp i.
proof.
  move=> hh hs [hk hr].
  have hv := wots_start_extends s s' layer tree kp i hs hk.
  have [hr' he] := linear_recorded_extends h h' (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) (range 0 7) hh hr.
  rewrite /chain_reference hv; move: hs; rewrite /extends; smt(domE).
qed.
lemma chain_partial_extends h h' s s' seed layer tree kp i cut :
  extends h h' => extends s s' => chain_reference h s seed layer tree kp i => 0<=cut<=7 =>
  wots_partial h' s' seed layer tree kp i cut=wots_partial h s seed layer tree kp i cut.
proof.
  move=> hh hs [hk hr] hc.
  have hv := wots_start_extends s s' layer tree kp i hs hk.
  have [hp rest] := linear_range_split h (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) 0 cut 7 _ _ hr; first 2 smt().
  have [hp' he] := linear_recorded_extends h h' (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) (range 0 cut) hh hp.
  by rewrite /wots_partial hv.
qed.

type chain_coordinate = raw_input * int * int * int * int.
op complete_chain_cache h s (c : chain_coordinate) values =
  chain_reference h s c.`1 c.`2 c.`3 c.`4 c.`5 /\
    stored_wots_values h s c.`1 c.`2 c.`3 c.`4 c.`5 values 7.

lemma complete_chain_cache_extends h h' s s' c values :
  extends h h' => extends s s' => complete_chain_cache h s c values =>
  complete_chain_cache h' s' c values.
proof.
  move=> hh hs [hr [hn hv]].
  have hr' := chain_reference_extends h h' s s' c.`1 c.`2 c.`3 c.`4 c.`5 hh hs hr.
  split; first exact hr'.
  split; first exact hn.
  move=> cut hc; rewrite (chain_partial_extends h h' s s' c.`1 c.`2 c.`3 c.`4 c.`5 cut hh hs hr hc).
  exact (hv cut hc).
qed.
lemma chain_cache_hash_preserved c values :
  hoare [Independent.hash : complete_chain_cache Independent.rawhistory Independent.secrethistory c values ==>
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_hash_extends s0 h0); smt(extends_refl complete_chain_cache_extends).
qed.
lemma chain_cache_derive_preserved c values :
  hoare [Independent.derive : complete_chain_cache Independent.rawhistory Independent.secrethistory c values ==>
    complete_chain_cache Independent.rawhistory Independent.secrethistory c values].
proof.
  exists* Independent.rawhistory,Independent.secrethistory; elim* => h0 s0.
  conseq (independent_derive_extends s0 h0); smt(extends_refl complete_chain_cache_extends).
qed.
