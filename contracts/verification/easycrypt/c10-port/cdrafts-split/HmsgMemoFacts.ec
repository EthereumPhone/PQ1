(* Local memo-table widths and exact accepted-call accounting. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import IndependentWidths AcceptedDigestDistribution AcceptedPrefixSampling HmsgMemoOracle.

lemma hmsg_hash_width :
  hoare [HmsgMemo(AcceptedSamples).hash :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ size res=256].
proof.
  have he : equiv [HmsgMemo(AcceptedSamples).hash ~ Independent.hash :
    ={x} /\ HmsgMemo.rawhistory{1}=Independent.rawhistory{2} /\
    HmsgMemo.secrethistory{1}=Independent.secrethistory{2} /\
    HmsgMemo.queries{1}=Independent.queries{2} ==>
    ={res} /\ HmsgMemo.rawhistory{1}=Independent.rawhistory{2} /\
    HmsgMemo.secrethistory{1}=Independent.secrethistory{2} /\
    HmsgMemo.queries{1}=Independent.queries{2}].
  + symmetry; conseq hmsg_memo_hash_refinement; smt().
  conseq he independent_hash_width.
  + move=> &m hv; exists HmsgMemo.queries{m} HmsgMemo.rawhistory{m} HmsgMemo.secrethistory{m} x{m}; smt().
  smt().
qed.
lemma hmsg_derive_width :
  hoare [HmsgMemo(AcceptedSamples).derive :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ size res=256].
proof.
  proc; if; auto => />.
  + move=> &m hp hs0 hn y hy; have hs : size y=256
      by move: hy; rewrite /full_digest DList.supp_dlist /=; smt().
    move: hp hs0; rewrite /valid_history; smt(get_setE get_set_sameE).
  move=> &m hp hs0 hn; move: hp hs0; rewrite /valid_history; smt(domE).
qed.

lemma hmsg_hash_count c marked :
  hoare [HmsgMemo(AcceptedSamples).hash : HmsgMemo.accepted_calls=c /\ (size x=160)=marked ==>
    HmsgMemo.accepted_calls=c+b2i(marked /\ accept_digest res)].
proof.
  proc; wp; sp 1; if; last by auto; rewrite /b2i; smt().
  wp; if.
  + call (_ : HmsgMemo.accepted_calls=c ==> HmsgMemo.accepted_calls=c).
    - conseq (split_accepted_lossless AcceptedSamples accepted_samples_lossless); smt().
    auto; rewrite /b2i; smt(get_set_sameE).
  auto; rewrite /b2i; smt(get_set_sameE).
qed.
lemma hmsg_hash_increment c :
  hoare [HmsgMemo(AcceptedSamples).hash : HmsgMemo.accepted_calls=c ==>
    c<=HmsgMemo.accepted_calls<=c+1 /\
    (!accept_digest res => HmsgMemo.accepted_calls=c)].
proof.
  proc*; exists* (size x=160); elim* => marked.
  call (hmsg_hash_count c marked); auto; rewrite /b2i; smt().
qed.
lemma hmsg_nonmessage_hash c :
  hoare [HmsgMemo(AcceptedSamples).hash : HmsgMemo.accepted_calls=c /\ size x<>160 ==>
    HmsgMemo.accepted_calls=c].
proof. conseq (hmsg_hash_count c false); rewrite /b2i; smt(). qed.
lemma hmsg_derive_count c :
  hoare [HmsgMemo(AcceptedSamples).derive : HmsgMemo.accepted_calls=c ==>
    HmsgMemo.accepted_calls=c].
proof. by proc; if; auto. qed.
lemma hmsg_nonmessage_width c :
  hoare [HmsgMemo(AcceptedSamples).hash :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size x<>160 ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size res=256].
proof. conseq hmsg_hash_width (hmsg_nonmessage_hash c); smt(). qed.
lemma hmsg_derive_width_count c :
  hoare [HmsgMemo(AcceptedSamples).derive :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    HmsgMemo.accepted_calls=c /\ size res=256].
proof. conseq hmsg_derive_width (hmsg_derive_count c); smt(). qed.
