(* A complete WOTS reference is retained private starts and public chain steps. *)
require import AllCore List FMap.
require import C10RawOracle KeygenPrefixes RawKeygen PersistentGrind AcceptedContexts.
require import LinearChain RawChainTrace.

op wots_key layer tree kp i = wots_tag ++ wots_tail layer tree kp i.
op wots_start (private : (raw_input,digest) fmap) layer tree kp i =
  node (oget private.[wots_key layer tree kp i]).
op wots_endpoint public private seed layer tree kp i =
  linear_value public (chain_input seed layer tree kp i)
    (wots_start private layer tree kp i) (range 0 7).
op wots_prefix public (private : (raw_input,digest) fmap) seed layer tree kp n =
  forall i, 0 <= i < n =>
    wots_key layer tree kp i \in private /\
    linear_recorded public (chain_input seed layer tree kp i)
      (wots_start private layer tree kp i) (range 0 7).
op wots_elements public private seed layer tree kp n =
  map (fun i => pad (wots_endpoint public private seed layer tree kp i)) (range 0 n).

lemma wots_start_extends s s' layer tree kp i :
  extends s s' => wots_key layer tree kp i \in s =>
  wots_start s' layer tree kp i = wots_start s layer tree kp i.
proof. rewrite /extends /wots_start; smt(). qed.

lemma wots_prefix_extends h h' s s' seed layer tree kp n :
  extends h h' => extends s s' => wots_prefix h s seed layer tree kp n =>
  wots_prefix h' s' seed layer tree kp n /\
    wots_elements h' s' seed layer tree kp n = wots_elements h s seed layer tree kp n.
proof.
  move=> hh hs hp.
  have he : forall i, 0 <= i < n =>
    wots_key layer tree kp i \in s' /\
    linear_recorded h' (chain_input seed layer tree kp i)
      (wots_start s' layer tree kp i) (range 0 7) /\
    wots_endpoint h' s' seed layer tree kp i = wots_endpoint h s seed layer tree kp i.
  + move=> i hi; have [hk hr] := hp i hi.
    have hstart := wots_start_extends s s' layer tree kp i hs hk.
    have [hr' hv] := linear_recorded_extends h h' (chain_input seed layer tree kp i)
      (wots_start s layer tree kp i) (range 0 7) hh hr.
    rewrite hstart /wots_endpoint hstart; move: hs; rewrite /extends; smt(domE).
  split; first by rewrite /wots_prefix; smt().
  rewrite /wots_elements; apply eq_in_map => i hi; smt(mem_range).
qed.

lemma wots_prefix_add h s seed layer tree kp n :
  0 <= n => wots_prefix h s seed layer tree kp n =>
  wots_key layer tree kp n \in s =>
  linear_recorded h (chain_input seed layer tree kp n)
    (wots_start s layer tree kp n) (range 0 7) =>
  wots_prefix h s seed layer tree kp (n+1).
proof. rewrite /wots_prefix; smt(). qed.

lemma wots_elements_step h s seed layer tree kp n :
  0 <= n => wots_elements h s seed layer tree kp (n+1) =
  rcons (wots_elements h s seed layer tree kp n) (pad (wots_endpoint h s seed layer tree kp n)).
proof. move=> hn; by rewrite /wots_elements rangeSr 1:hn map_rcons. qed.
