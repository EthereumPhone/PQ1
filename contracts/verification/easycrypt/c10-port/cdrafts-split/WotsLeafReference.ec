(* Every actual key-generation leaf supplies its complete retained WOTS chains. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts RawLeafChains WotsReference.
require import WotsReferenceOracle WotsChainReference.

op wots_leaf_input h s seed layer tree kp =
  seed ++ address layer tree 1 kp 0 0 0 ++ flatten (wots_elements h s seed layer tree kp 43).

lemma hash_records_wots_leaf seed0 layer0 tree0 kp0 values x0 :
  hoare [Independent.hash :
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 = values /\ x=x0 ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 = values /\
    Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(wots_prefix_extends extends_insert extends_refl get_set_sameE domE).
qed.

lemma factored_leaf_recorded seed0 layer0 tree0 kp0 :
  hoare [RawLeafChains(PreparationView(Independent)).leaf :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    exists d, Independent.rawhistory.[wots_leaf_input Independent.rawhistory Independent.secrethistory
      seed0 layer0 tree0 kp0] = Some d /\ res=node d].
proof.
  proc; seq 3 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 43 = elements).
  + while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ 0<=i<=43 /\
      wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i /\
      wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i = elements).
    - exists* i,elements; elim* => i0 values.
      seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\
        i=i0 /\ 0<=i0<43 /\ elements=values /\
        wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i0 /\
        wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 i0 = values /\
        Independent.secrethistory.[wots_key layer0 tree0 kp0 i0] = Some d).
      + call (wots_records_reference seed0 layer0 tree0 kp0 i0 values); auto; smt().
      exists* d; elim* => sd.
      wp; call (chain_completes_wots_reference seed0 layer0 tree0 kp0 i0 values sd).
      auto; smt().
    auto; rewrite /wots_prefix /wots_elements; smt(range_geq).
  exists* elements; elim* => values.
  call (hash_records_wots_leaf seed0 layer0 tree0 kp0 values
    (seed0 ++ address layer0 tree0 1 kp0 0 0 0 ++ flatten values)).
  auto; rewrite /wots_leaf_input; smt().
qed.
