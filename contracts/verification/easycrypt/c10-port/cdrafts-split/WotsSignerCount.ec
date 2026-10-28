(* The actual signer adds at most four accepted WOTS calls, including both
   reconstructions; verification adds at most two. H_msg trials add none. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Randomizer PrefixGuess PrefixHybrid RoleGrind.
require import RawKeygen RawSigner RawSignature RawWidths IndependentWidths.
require import HmsgShapes HmsgSignerCount WotsCountDomain.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts WotsCountShapes WotsForestCount WotsLayerCount.

lemma wots_census_role_grind_count c :
  hoare[RoleGrind(WotsMemo(WotsAcceptedSamples)).run :
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    (res<>None => size (oget res).`1=16 /\ size (oget res).`2=256)].
proof.
  proc; while (independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    (result<>None => size (oget result).`1=16 /\ size (oget result).`2=256)).
  + wp; call (wots_noncount_width c); wp; call (wots_derive_width_count c);
      auto; smt(count_query_no_hmsg randomizer_width).
  auto; smt().
qed.

lemma wots_census_finish_count c :
  hoare[RawSigner(WotsMemo(WotsAcceptedSamples)).finish : size seed=32 /\ size randomizer=16 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+4 /\
    (res<>None => signature_width (oget res))].
proof.
  proc; wp; while (size seed=32 /\ size randomizer=16 /\ size shuffle=32 /\ size current=16 /\
    rows_width 13 forest.`1 /\ size forest.`2=12 /\ all (rows_width 11) forest.`2 /\
    0<=layer<=2 /\ (ok=>size layers=layer /\ all layer_width layers) /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+2*layer).
  + wp; exists* WotsMemo.accepted_calls; elim*=> k.
    call (wots_census_layer_sign_count k); auto; smt(all_cat cats1 size_rcons).
  wp; call (wots_census_forest_sign_count c); auto; rewrite /signature_width; smt().
qed.

lemma wots_census_sign_count c :
  hoare[RawSigner(WotsMemo(WotsAcceptedSamples)).sign : size seed=32 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+4 /\
    (res<>None => signature_width (oget res))].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c /\
    (accepted<>None => size (oget accepted).`1=16)).
  + call (wots_census_role_grind_count c); auto; smt().
  sp 1; if; last by auto; smt().
  call (wots_census_finish_count c); auto; smt().
qed.

lemma wots_census_verify_count c :
  hoare[RawSigner(WotsMemo(WotsAcceptedSamples)).verify : size seed=32 /\ signature_width sig /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+2].
proof.
  proc; seq 1 : (size seed=32 /\ signature_width sig /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c).
  + call (wots_noncount_width c); auto; smt(count_query_no_hmsg).
  sp 1; if; last by auto; smt().
  wp; while (size seed=32 /\ signature_width sig /\ size current=16 /\ 0<=layer<=2 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+layer).
  + wp; exists* WotsMemo.accepted_calls; elim*=> k.
    call (wots_census_layer_recover_count k); auto; smt(signature_layer_width).
  wp; call (wots_census_forest_recover_count c); auto; rewrite /signature_width; smt().
qed.
