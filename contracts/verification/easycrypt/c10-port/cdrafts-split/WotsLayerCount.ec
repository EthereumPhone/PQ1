(* A layer sign counts both the search and its signer-side reconstruction. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawLayer RawShuffle RawSignature RawWidths.
require import IndependentWidths HmsgShapes HmsgLayerCount.
require import WotsAcceptedPrefix WotsMemoOracle WotsMemoFacts WotsCountShapes WotsTreeCount WotsSignCount.

lemma wots_census_layer_recover_count c :
  hoare[RawLayer(WotsPreparation).recover : size seed=32 /\ size message=16 /\ layer_width sig /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1 /\ size res=16].
proof.
  proc; seq 1 : (size seed=32 /\ rows_width 9 sig.`3 /\ size pk=16 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1).
  + call (wots_census_wots_recover_count c); auto; rewrite /layer_width; smt().
  exists* WotsMemo.accepted_calls; elim*=> k; call (wots_census_merkle_recover_count k); auto; smt().
qed.

lemma wots_census_layer_sign_count c :
  hoare[RawLayer(WotsPreparation).sign : size seed=32 /\ size message=16 /\ size shuffle=32 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ WotsMemo.accepted_calls=c ==>
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+2 /\
    (res<>None => layer_width (oget res).`1 /\ size (oget res).`2=16)].
proof.
  proc; seq 3 : (size seed=32 /\ size message=16 /\ rows_width 9 built.`1 /\
    independent_tables_valid WotsMemo.rawhistory WotsMemo.secrethistory /\ c<=WotsMemo.accepted_calls<=c+1 /\
    (signed<>None => rows_width 43 (oget signed).`1 /\ 0<=(oget signed).`2<signing_budget)).
  + call (wots_census_wots_sign_count c); call (wots_census_shuffle_derive c);
      call (wots_census_merkle_build_count c); auto; smt(layer_label_width).
  sp 1; if; last by auto; smt().
  wp; exists* WotsMemo.accepted_calls; elim*=> k.
  call (wots_census_layer_recover_count k); auto; rewrite /layer_width /signing_budget; smt().
qed.
