(* Hypertree layer preserves the accepted H_msg-entry count. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import RawKeygen RawLayer RawShuffle RawSignature RawWidths.
require import IndependentWidths AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes HmsgTreeCount HmsgWotsCount.

lemma layer_label_width layer : size (layer_label layer)=7.
proof. by rewrite /layer_label; case (layer=0). qed.
lemma hmsg_layer_recover_count c :
  hoare[RawLayer(HmsgPreparation).recover : size seed=32 /\ size message=16 /\ layer_width sig /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\ size res=16].
proof. proc; call (hmsg_merkle_recover_count c); call (hmsg_wots_recover_count c); auto; rewrite /layer_width; smt(). qed.
lemma hmsg_layer_sign_count c :
  hoare[RawLayer(HmsgPreparation).sign : size seed=32 /\ size message=16 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (res<>None => layer_width (oget res).`1 /\ size (oget res).`2=16)].
proof.
  proc; seq 3 : (size seed=32 /\ size message=16 /\ rows_width 9 built.`1 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (signed<>None => rows_width 43 (oget signed).`1 /\ 0 <= (oget signed).`2 < signing_budget)).
  + call (hmsg_wots_sign_count c); call (hmsg_shuffle_derive c); call (hmsg_merkle_build_count c);
      auto; smt(layer_label_width).
  sp 1; if; last by auto.
  wp; call (hmsg_layer_recover_count c); auto; rewrite /layer_width /signing_budget; smt().
qed.
