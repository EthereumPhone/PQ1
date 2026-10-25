(* WOTS recovery of a retained honest opening does not extend the public map.
   Count acceptance and every suffix-chain input are justified by that opening. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import LinearChain RawChainTrace RawChainCached WotsReference WotsChainSplit WotsSignatureValue.
require import WotsSignWitness WotsReferenceRoot WotsLeafReference RawCountRecorded.

lemma wrapper_wots_suffix_tables seed0 layer0 tree0 kp0 i0 cut0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).chain :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ index=i0 /\
    current=wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut0 /\ start=cut0 /\ stop=7 /\
    0<=i0<43 /\ 0<=cut0<=7 /\ wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ Independent.rawhistory=h0 ==>
    Independent.rawhistory=h0 /\ res=wots_endpoint h0 s0 seed0 layer0 tree0 kp0 i0].
proof.
  conseq (raw_chain_tables_replay seed0 layer0 tree0 kp0 i0
    (wots_partial h0 s0 seed0 layer0 tree0 kp0 i0 cut0) cut0 7 h0); smt(wots_reference_split).
qed.

lemma wrapper_wots_reference_tables seed0 layer0 tree0 kp0 message0 sigma0 count0 d0 leaf0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\ count_accepts d0 /\
    h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\ Independent.rawhistory=h0 ==>
    Independent.rawhistory=h0 /\ res=node leaf0].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\ count_accepts d0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\ Independent.rawhistory=h0).
  + call (hash_existing_entry h0 (wots_count_input seed0 layer0 tree0 kp0 message0 count0) d0).
    auto; rewrite /wots_count_input; smt().
  sp 1; if; last by auto; smt().
  wp; call (hash_existing_entry h0 (wots_leaf_input h0 s0 seed0 layer0 tree0 kp0) leaf0).
  wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\ 0<=i<=43 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\
    elements=wots_elements h0 s0 seed0 layer0 tree0 kp0 i /\ Independent.rawhistory=h0).
  + exists* i; elim* => i0; wp.
    call (wrapper_wots_suffix_tables seed0 layer0 tree0 kp0 i0 (digit 3 d0 i0) h0 s0).
    auto; rewrite /wots_signature; smt(raw_digit_bounds wots_elements_step).
  auto; rewrite /wots_leaf_input /wots_elements; smt(range_geq).
qed.

lemma wrapper_wots_opening_tables seed0 layer0 tree0 kp0 message0 (signature0 : raw_input list * int) root0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\ Independent.rawhistory=h0 /\
    wots_opening h0 s0 seed0 layer0 tree0 kp0 message0 root0 signature0 ==>
    Independent.rawhistory=h0 /\ res=root0].
proof.
  conseq (_ : exists d leaf,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    sigma=signature0.`1 /\ count=signature0.`2 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d signature0.`1 /\ count_accepts d /\
    h0.[wots_count_input seed0 layer0 tree0 kp0 message0 signature0.`2]=Some d /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf /\ root0=node leaf /\ Independent.rawhistory=h0 ==> _).
  + rewrite /wots_opening /wots_root; smt().
  elim* => d leaf.
  conseq (wrapper_wots_reference_tables seed0 layer0 tree0 kp0 message0 signature0.`1 signature0.`2 d leaf h0 s0); smt().
qed.
