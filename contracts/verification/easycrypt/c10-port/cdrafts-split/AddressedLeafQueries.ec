(* Canonical input accounting for every public query of an actual WOTS
   key-generation leaf, including all 43 chains and their compression. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import RawLeafChains WotsReference WotsLeafReference WotsReferenceOracle WotsChainReference.
require import AddressedWotsCanonicity AddressedWotsLog AddressedWotsQueries.

lemma canonical_wots_leaf_member h s seed layer tree kp :
  wots_address_valid layer tree kp 0 0 => wots_prefix h s seed layer tree kp 43 =>
  canonical_wots_input h s seed (wots_leaf_input h s seed layer tree kp).
proof.
  move=> hv hr; rewrite /canonical_wots_input; right; exists layer tree kp; smt().
qed.

lemma wots_records_reference_and_log seed0 layer0 tree0 kp0 n values base :
  hoare [PreparationView(Independent).wots :
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n=values /\
    tail=wots_tail layer0 tree0 kp0 n /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n=values /\
    Independent.secrethistory.[wots_key layer0 tree0 kp0 n]=Some res /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  have hl : hoare [PreparationView(Independent).wots :
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
  + proc; call (derive_preserves_current_wots_log seed0 base); auto.
  conseq (wots_records_reference seed0 layer0 tree0 kp0 n values) hl; smt().
qed.

lemma chain_completes_reference_and_log seed0 layer0 tree0 kp0 n values sd base :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=n /\
    current=node sd /\ start=0 /\ stop=7 /\ wots_address_valid layer0 tree0 kp0 n 0 /\
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n=values /\
    Independent.secrethistory.[wots_key layer0 tree0 kp0 n]=Some sd /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 (n+1) /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 (n+1)
      =rcons values (pad res) /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  exists* Independent.secrethistory; elim* => s0.
  conseq (raw_chain_extends_canonical_log seed0 layer0 tree0 kp0 n 7 s0 base)
    (chain_completes_wots_reference seed0 layer0 tree0 kp0 n values sd).
  + rewrite /wots_start /wots_address_valid; smt(domE).
  smt().
qed.

lemma factored_leaf_canonical_queries seed0 layer0 tree0 kp0 base :
  hoare [RawLeafChains(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    wots_address_valid layer0 tree0 kp0 0 0 /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  proc; seq 3 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    wots_address_valid layer0 tree0 kp0 0 0 /\
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43=elements /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries).
  + while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ 0<=i<=43 /\
      wots_address_valid layer0 tree0 kp0 0 0 /\
      wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i /\
      wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i=elements /\
      canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries).
    - exists* i,elements; elim* => i0 values.
      seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
        i=i0 /\ 0<=i0<43 /\ elements=values /\ wots_address_valid layer0 tree0 kp0 0 0 /\
        wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i0 /\
        wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i0=values /\
        Independent.secrethistory.[wots_key layer0 tree0 kp0 i0]=Some d /\
        canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries).
      + call (wots_records_reference_and_log seed0 layer0 tree0 kp0 i0 values base); auto; smt().
      exists* d; elim* => sd.
      wp; call (chain_completes_reference_and_log seed0 layer0 tree0 kp0 i0 values sd base).
      auto; rewrite /wots_address_valid; smt().
    auto; rewrite /wots_prefix /wots_elements; smt(range_geq).
  call (hash_appends_canonical_wots_log seed0 base).
  auto; move=> &m hp; split; first smt().
  have hh := canonical_wots_leaf_member Independent.rawhistory{m} Independent.secrethistory{m}
    seed0 layer0 tree0 kp0 _ _; first 2 smt().
  move: hh; rewrite /wots_leaf_input; smt().
qed.

lemma raw_leaf_canonical_queries seed0 layer0 tree0 kp0 base :
  hoare [RawKeygen(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    wots_address_valid layer0 tree0 kp0 0 0 /\
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries ==>
    canonical_wots_log Independent.rawhistory Independent.secrethistory seed0 base Independent.queries].
proof.
  conseq (raw_leaf_chain_projection (PreparationView(Independent)))
    (factored_leaf_canonical_queries seed0 layer0 tree0 kp0 base).
  + move=> &m hm.
    exists Independent.queries{m} Independent.rawhistory{m} Independent.secrethistory{m}
      (seed{m},layer{m},tree{m},kp{m}); smt().
  smt().
qed.
