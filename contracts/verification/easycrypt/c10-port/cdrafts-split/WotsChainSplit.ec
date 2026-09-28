(* Valid digit cuts split each actual retained WOTS chain. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen LinearChain LinearSplit RawChainTrace WotsReference.

op wots_partial h s seed layer tree kp i cut =
  linear_value h (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) (range 0 cut).

lemma wots_reference_split h s seed layer tree kp i cut :
  wots_prefix h s seed layer tree kp 43 => 0 <= i < 43 => 0 <= cut <= 7 =>
  linear_recorded h (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) (range 0 cut) /\
  linear_recorded h (chain_input seed layer tree kp i)
    (wots_partial h s seed layer tree kp i cut) (range cut 7) /\
  wots_endpoint h s seed layer tree kp i =
    linear_value h (chain_input seed layer tree kp i)
      (wots_partial h s seed layer tree kp i cut) (range cut 7).
proof.
  move=> hp hi hc; have [hk hr] := hp i hi.
  have hs := linear_range_split h (chain_input seed layer tree kp i)
    (wots_start s layer tree kp i) 0 cut 7 _ _ hr; first 2 smt().
  by rewrite /wots_partial /wots_endpoint.
qed.
