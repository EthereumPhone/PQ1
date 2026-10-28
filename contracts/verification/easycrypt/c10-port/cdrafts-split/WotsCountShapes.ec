(* Private derivations and short shuffle calls preserve the accepted WOTS census. *)
require import AllCore List Distr DList.
require import C10RawOracle C10Bytes C10Randomizer C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawSignature RawShuffle ClientGuessCandidates IndependentWidths.
require import HmsgShapes NodeQueryDomain ForsInputSeparation WotsCountDomain.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts.
module WotsPreparation = PreparationView(WotsMemo(WotsAcceptedSamples)).

lemma wots_census_hash_width_increment c :
  hoare[WotsMemo(WotsAcceptedSamples).hash :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ size res=256 /\
    c<=WotsMemo.accepted_calls<=c+1 /\ (!RawWots.count_accepts res => WotsMemo.accepted_calls=c)].
proof. conseq wots_hash_width (wots_hash_increment c); smt(). qed.

lemma wots_census_noncount_chain seed a value :
  size seed=32 => size a=32 => size value=16 => !wots_count_query (seed++a++pad value).
proof. move=> hs ha hv; apply count_query_no_short; smt(hash_chain_width). qed.

lemma wots_census_noncount_pair seed layer tree kind kp ci cp ha lhs rhs :
  size seed=32 => be 4 kind<>be 4 0 =>
  !wots_count_query (seed++address layer tree kind kp ci cp ha++pad lhs++pad rhs).
proof. move=> hs hk; rewrite -catA; exact (count_query_no_other_kind _ _ _ _ _ _ _ _ _ hs hk). qed.

lemma wots_census_compress_kind : be 4 1<>be 4 0.
proof. smt(be4_injective). qed.
lemma wots_census_forest_kind : be 4 4<>be 4 0.
proof. smt(be4_injective). qed.

lemma wots_census_wots_private c :
  hoare [WotsPreparation.wots :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=256].
proof. proc; call (wots_derive_width_count c); auto. qed.
lemma wots_census_fors_private c :
  hoare [WotsPreparation.fors :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=256].
proof. proc; call (wots_derive_width_count c); auto. qed.

lemma wots_census_shuffle_derive c :
  hoare [RawShuffle(WotsPreparation).derive :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    size seed=32 /\ size label<=7 ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size res=32].
proof.
  proc; sp 1; if; last by auto; smt(size_nseq).
  wp; call (wots_noncount_width c); auto.
  move=> &hr [[_ [hv [hc [hs hl]]]] _]; split.
  + rewrite /wots_count_query /shuffle_tag !size_cat /= hs; smt().
  move=> _ d count history [hv' [hc' hd]].
  by rewrite bits_to_bytes_size hd /= hv' hc'.
qed.
lemma wots_census_shuffle_permutation c :
  hoare [RawShuffle(WotsPreparation).permutation :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\ size seed=32 ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c].
proof.
  proc; sp 1; if; last by auto.
  while (independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c);
    first by auto.
  wp; while (independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\
    WotsMemo.accepted_calls=c /\ size seed=32).
  + wp; call (wots_noncount_width c); auto.
    move=> &hr [[hv [hc hs]] hb]; split.
    - rewrite /wots_count_query /fisher_tag !size_cat be_width //= hs; smt().
    by move=> _ d count history [hv' [hc' hd]]; rewrite hv' hc' hs.
  auto.
qed.
