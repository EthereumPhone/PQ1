(* Local memo-table widths and exact accepted-call accounting. *)
require import AllCore List Distr FMap.
require import C10RawOracle RawWots C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import IndependentWidths WotsAcceptedDistribution WotsAcceptedPrefix WotsCountDomain WotsMemoOracle.

lemma wots_hash_width :
  hoare [WotsMemo(WotsAcceptedSamples).hash :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ size res=256].
proof.
  have he : equiv [WotsMemo(WotsAcceptedSamples).hash ~ Independent.hash :
    ={x} /\ WotsMemo.rawhistory{1}=Independent.rawhistory{2} /\
    WotsMemo.secrethistory{1}=Independent.secrethistory{2} /\
    WotsMemo.queries{1}=Independent.queries{2} ==>
    ={res} /\ WotsMemo.rawhistory{1}=Independent.rawhistory{2} /\
    WotsMemo.secrethistory{1}=Independent.secrethistory{2} /\
    WotsMemo.queries{1}=Independent.queries{2}].
  + symmetry; conseq wots_memo_hash_refinement; smt().
  conseq he independent_hash_width.
  + move=> &m hv; exists WotsMemo.queries{m} WotsMemo.rawhistory{m} WotsMemo.secrethistory{m} x{m}; smt().
  smt().
qed.
lemma wots_derive_width :
  hoare [WotsMemo(WotsAcceptedSamples).derive :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ size res=256].
proof.
  proc; if; auto => />.
  + move=> &m hp hs0 hn y hy; have hs : size y=256
      by move: hy; rewrite /full_digest DList.supp_dlist /=; smt().
    move: hp hs0; rewrite /valid_history; smt(get_setE get_set_sameE).
  move=> &m hp hs0 hn; move: hp hs0; rewrite /valid_history; smt(domE).
qed.

lemma wots_hash_count c marked :
  hoare [WotsMemo(WotsAcceptedSamples).hash : WotsMemo.accepted_calls=c /\ (wots_count_query x)=marked ==>
    WotsMemo.accepted_calls=c+b2i(marked /\ count_accepts res)].
proof.
  proc; wp; sp 1; if; last by auto; rewrite /b2i; smt().
  wp; if.
  + call (_ : WotsMemo.accepted_calls=c ==> WotsMemo.accepted_calls=c).
    - conseq (split_wots_accepted_lossless WotsAcceptedSamples wots_accepted_samples_lossless); smt().
    auto; rewrite /b2i; smt(get_set_sameE).
  auto; rewrite /b2i; smt(get_set_sameE).
qed.
lemma wots_hash_increment c :
  hoare [WotsMemo(WotsAcceptedSamples).hash : WotsMemo.accepted_calls=c ==>
    c<=WotsMemo.accepted_calls<=c+1 /\
    (!count_accepts res => WotsMemo.accepted_calls=c)].
proof.
  proc*; exists* (wots_count_query x); elim* => marked.
  call (wots_hash_count c marked); auto; rewrite /b2i; smt().
qed.
lemma wots_noncount_hash c :
  hoare [WotsMemo(WotsAcceptedSamples).hash : WotsMemo.accepted_calls=c /\ !wots_count_query x ==>
    WotsMemo.accepted_calls=c].
proof. conseq (wots_hash_count c false); rewrite /b2i; smt(). qed.
lemma wots_derive_count c :
  hoare [WotsMemo(WotsAcceptedSamples).derive : WotsMemo.accepted_calls=c ==>
    WotsMemo.accepted_calls=c].
proof. by proc; if; auto. qed.
lemma wots_noncount_width c :
  hoare [WotsMemo(WotsAcceptedSamples).hash :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ !wots_count_query x ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ size res=256].
proof. conseq wots_hash_width (wots_noncount_hash c); smt(). qed.
lemma wots_derive_width_count c :
  hoare [WotsMemo(WotsAcceptedSamples).derive :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ size res=256].
proof. conseq wots_derive_width (wots_derive_count c); smt(). qed.
