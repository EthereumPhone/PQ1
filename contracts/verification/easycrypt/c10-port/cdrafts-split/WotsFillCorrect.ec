(* Every shuffled signing index receives its retained reference-chain prefix. *)
require import AllCore List FMap RadixEncoding.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots.
require import PersistentGrind WotsReference WotsChainSplit WotsSignatureValue.
require import RawWotsFill PreparationHistory FixedChainReplay FixedWotsChains.

lemma wots_fill_correct seed0 layer0 tree0 kp0 d0 h0 s0 :
  hoare [RawWotsFill(PreparationView(Independent)).fill :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    wots_signature h0 s0 seed0 layer0 tree0 kp0 d0 res /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ accepted=d0 /\ 0<=step<=43 /\
    wots_prefix h0 s0 seed0 layer0 tree0 kp0 43 /\ perm_eq order (range 0 43) /\
    visited_signature h0 s0 seed0 layer0 tree0 kp0 d0 order step sigma /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + exists* order,step; elim* => ord st.
    wp; call (fixed_wots_prefix seed0 layer0 tree0 kp0 (nth 0 ord st) (digit 3 d0 (nth 0 ord st)) h0 s0).
    call (wots_from_history (wots_tail layer0 tree0 kp0 (nth 0 ord st))
      (oget s0.[wots_key layer0 tree0 kp0 (nth 0 ord st)]) s0 h0).
    auto; rewrite /wots_start /wots_key;
      smt(visited_signature_step raw_digit_bounds perm_eq_size size_range mem_nth perm_eq_mem mem_range get_some).
  wp; call (raw_shuffle_recorded 43 s0 h0); auto;
    smt(visited_signature_empty visited_signature_complete).
qed.
