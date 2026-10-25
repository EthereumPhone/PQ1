(* Materialize the requested positions of a builder-recorded WOTS reference.
   An arbitrary permutation is retained; the values are uniquely determined
   by the accepted digest and the same immutable memo entries. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawShuffle.
require import WotsReference WotsChainSplit WotsSignatureValue RawChainCached ChainReferenceEntries ChainValueView.

module WrapperWotsValues (O : ChainOracle) = {
  proc run(seed : raw_input, layer tree kp : int, accepted : digest, order : int list) : raw_input list = {
    var sigma, step, i, current;
    sigma <- nseq 43 (nseq 16 0); step <- 0;
    while (step<43) {
      i <- nth 0 order step;
      current <@ O.value(seed,layer,tree,kp,i,digit 3 accepted i);
      sigma <- put sigma i current; step <- step+1;
    }
    return sigma;
  }
}.

lemma wrapper_wots_values_lossless (O <: ChainOracle) :
  islossless O.value => islossless WrapperWotsValues(O).run.
proof.
  move=> hv; proc; while true (43-step).
  + move=> z; wp; call hv; auto; smt().
  auto; smt().
qed.

lemma wrapper_wots_values_recorded seed0 layer0 tree0 kp0 d0 order0 h0 s0 :
  perm_eq order0 (range 0 43) =>
  hoare [WrapperWotsValues(ConcreteChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 res].
proof.
  move=> hp; proc.
  while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    0<=step<=43 /\ visited_signature h0 s0 seed0 layer0 tree0 kp0 d0 order0 step sigma).
  + exists* step; elim* => st.
    wp; call (concrete_chain_tables_replay seed0 layer0 tree0 kp0 (nth 0 order0 st)
      (digit 3 d0 (nth 0 order0 st)) h0 s0 (raw_digit_bounds d0 (nth 0 order0 st))).
    auto; rewrite /chain_reference;
      smt(visited_signature_step perm_eq_size size_range mem_nth perm_eq_mem mem_range).
  auto; smt(visited_signature_empty visited_signature_complete).
qed.

lemma wrapper_wots_values_total seed0 layer0 tree0 kp0 d0 order0 h0 s0 :
  perm_eq order0 (range 0 43) =>
  phoare [WrapperWotsValues(ConcreteChain(Independent)).run :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ order=order0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 res] = 1%r.
proof.
  move=> hp.
  conseq (wrapper_wots_values_lossless (ConcreteChain(Independent))
    (concrete_chain_value_lossless Independent independent_hash_ll independent_derive_ll))
    (wrapper_wots_values_recorded seed0 layer0 tree0 kp0 d0 order0 h0 s0 hp); smt().
qed.

lemma wrapper_wots_signature_unique h s seed layer tree kp d sigma sigma' :
  wots_signature h s seed layer tree kp d sigma =>
  wots_signature h s seed layer tree kp d sigma' => sigma=sigma'.
proof.
  move=> [hs hv] [hs' hv']; apply (eq_from_nth (nseq 16 0)); smt().
qed.
