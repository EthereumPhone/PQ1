(* A growing chain cache retains each prefix value under memo-table extension. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen PersistentGrind AcceptedContexts LinearChain LinearSplit RawChainTrace.
require import WotsReference WotsChainSplit ChainReferenceEntries ChainCacheInvariant.

op prefix_chain_cache h s (c : chain_coordinate) values n =
  wots_key c.`2 c.`3 c.`4 c.`5 \in s /\
  linear_recorded h (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) (range 0 n) /\
  stored_wots_values h s c.`1 c.`2 c.`3 c.`4 c.`5 values n.

lemma prefix_cache_zero h s (c : chain_coordinate) :
  wots_key c.`2 c.`3 c.`4 c.`5 \in s =>
  prefix_chain_cache h s c [wots_start s c.`2 c.`3 c.`4 c.`5] 0.
proof. rewrite /prefix_chain_cache (range_geq 0 0) 1:// /=; smt(stored_wots_initial). qed.

lemma prefix_cache_complete h s c values :
  prefix_chain_cache h s c values 7 => complete_chain_cache h s c values.
proof. by rewrite /prefix_chain_cache /complete_chain_cache /chain_reference; smt(). qed.

lemma prefix_cache_extends h h' s s' c values n :
  0<=n => extends h h' => extends s s' => prefix_chain_cache h s c values n =>
  prefix_chain_cache h' s' c values n.
proof.
  move=> hn hh hs [hk [hr [hlen hv]]].
  have hstart := wots_start_extends s s' c.`2 c.`3 c.`4 c.`5 hs hk.
  have [hr' he] := linear_recorded_extends h h' (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) (range 0 n) hh hr.
  split; first by move: hs; rewrite /extends; smt(domE).
  split; first by rewrite hstart.
  split; first exact hlen.
  move=> cut hc.
  have [hp rest] := linear_range_split h (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) 0 cut n _ _ hr; first 2 smt().
  have [hp' he'] := linear_recorded_extends h h' (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) (range 0 cut) hh hp.
  have heq : wots_partial h' s' c.`1 c.`2 c.`3 c.`4 c.`5 cut =
    wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 cut by rewrite /wots_partial hstart.
  rewrite heq; exact (hv cut hc).
qed.

lemma prefix_cache_step h s c values n current d :
  0<=n => prefix_chain_cache h s c values n =>
  current=wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 n =>
  h.[chain_input c.`1 c.`2 c.`3 c.`4 c.`5 n current]=Some d =>
  prefix_chain_cache h s c (rcons values (node d)) (n+1).
proof.
  move=> hn [hk [hr hv]] hcurrent hd.
  have [hr' he] := linear_recorded_step h (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) (range 0 n) n d current hr _ hd; first by rewrite /wots_partial in hcurrent; smt().
  have hnext : wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 (n+1)=node d
    by rewrite /wots_partial rangeSr 1:/#.
  split; first exact hk.
  split; first by rewrite rangeSr 1:/#.
  apply (stored_wots_next h s c.`1 c.`2 c.`3 c.`4 c.`5 values n (node d) hn hv); smt().
qed.

lemma prefix_cache_current_extends h h' s c values n current :
  0<=n => extends h h' => prefix_chain_cache h s c values n =>
  current=wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 n =>
  current=wots_partial h' s c.`1 c.`2 c.`3 c.`4 c.`5 n.
proof.
  move=> hn hh [hk [hr hv]] hc.
  have [hr' he] := linear_recorded_extends h h' (chain_input c.`1 c.`2 c.`3 c.`4 c.`5)
    (wots_start s c.`2 c.`3 c.`4 c.`5) (range 0 n) hh hr.
  by rewrite /wots_partial he.
qed.
lemma prefix_cache_next_value h s (c : chain_coordinate) n current d :
  0<=n => current=wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 n =>
  h.[chain_input c.`1 c.`2 c.`3 c.`4 c.`5 n current]=Some d =>
  wots_partial h s c.`1 c.`2 c.`3 c.`4 c.`5 (n+1)=node d.
proof.
  move=> hn hc hd; rewrite /wots_partial rangeSr 1:/# linear_value_rcons /linear_step.
  rewrite /wots_partial in hc.
  by rewrite -hc hd oget_some.
qed.
