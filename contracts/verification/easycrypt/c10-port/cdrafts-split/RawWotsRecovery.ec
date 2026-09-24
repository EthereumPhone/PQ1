(* Actual WOTS recovery follows a valid reference opening to its retained leaf. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsLeafReference WotsChainSplit WotsSignatureValue.
require import FixedWotsChains FixedHashReplay RawCountRecorded.

lemma raw_wots_recovers_reference seed0 layer0 tree0 kp0 message0 sigma0 count0 d0 leaf0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ sigma=sigma0 /\ count=count0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\ count_accepts d0 /\
    h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=node leaf0 /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; seq 1 : (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\ count_accepts d0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + call (hash_from_history (wots_count_input seed0 layer0 tree0 kp0 message0 count0) d0 s0 h0).
    auto; rewrite /wots_count_input; smt().
  sp 1; if; last by auto; smt().
  wp; call (hash_from_history (wots_leaf_input h0 s0 seed0 layer0 tree0 kp0) leaf0 s0 h0).
  wp; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ sigma=sigma0 /\ d=d0 /\ 0<=i<=43 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 sigma0 /\
    h0.[wots_leaf_input h0 s0 seed0 layer0 tree0 kp0]=Some leaf0 /\
    elements=wots_elements h0 s0 seed0 layer0 tree0 kp0 i /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + exists* i; elim* => i0; wp.
    call (fixed_wots_suffix seed0 layer0 tree0 kp0 i0 (digit 3 d0 i0) h0 s0).
    auto; rewrite /wots_signature; smt(raw_digit_bounds wots_elements_step).
  auto; rewrite /wots_leaf_input /wots_elements; smt(range_geq).
qed.

lemma raw_wots_invalid_sum_sentinel seed0 layer0 tree0 kp0 message0 count0 d0 h0 s0 :
  hoare [RawWots(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\ count=count0 /\
    !count_accepts d0 /\ h0.[wots_count_input seed0 layer0 tree0 kp0 message0 count0]=Some d0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=nseq 16 0].
proof.
  proc; seq 1 : (d=d0 /\ !count_accepts d0).
  + call (hash_from_history (wots_count_input seed0 layer0 tree0 kp0 message0 count0) d0 s0 h0).
    auto; rewrite /wots_count_input; smt().
  sp 1; if; first by exfalso; auto; smt().
  auto.
qed.
