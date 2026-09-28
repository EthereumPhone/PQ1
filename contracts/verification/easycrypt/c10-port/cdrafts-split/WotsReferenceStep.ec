(* Finishing one actual chain extends the sequential keygen reference. *)
require import AllCore List FMap.
require import C10RawOracle KeygenPrefixes RawKeygen LinearChain RawChainTrace WotsReference.

lemma wots_reference_finish h s seed layer tree kp n sd value values :
  0 <= n => wots_prefix h s seed layer tree kp n =>
  wots_elements h s seed layer tree kp n = values =>
  s.[wots_key layer tree kp n] = Some sd =>
  linear_recorded h (chain_input seed layer tree kp n) (node sd) (range 0 7) =>
  value = linear_value h (chain_input seed layer tree kp n) (node sd) (range 0 7) =>
  wots_prefix h s seed layer tree kp (n+1) /\
  wots_elements h s seed layer tree kp (n+1) = rcons values (pad value).
proof.
  move=> hn hp hv hs hr he.
  have hstart : wots_start s layer tree kp n = node sd
    by rewrite /wots_start hs oget_some.
  split.
  + apply (wots_prefix_add h s seed layer tree kp n hn hp).
    - smt(domE).
    by rewrite hstart.
  by rewrite wots_elements_step 1:hn hv /wots_endpoint hstart -he.
qed.
