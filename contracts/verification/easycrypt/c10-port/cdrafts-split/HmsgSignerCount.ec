(* Signing and verification add at most one accepted H_msg call each. *)
require import AllCore List Distr.
require import C10RawOracle C10RawGrind C10Randomizer PrefixGuess PrefixHybrid RoleGrind.
require import RawKeygen RawSigner RawSignature RawWidths IndependentWidths.
require import AcceptedPrefixSampling HmsgMemoOracle HmsgMemoFacts HmsgShapes HmsgForestCount HmsgLayerCount.

lemma hmsg_hash_width_increment c :
  hoare[HmsgMemo(AcceptedSamples).hash :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ size res=256 /\
    c<=HmsgMemo.accepted_calls<=c+1 /\ (!accept_digest res => HmsgMemo.accepted_calls=c)].
proof. conseq hmsg_hash_width (hmsg_hash_increment c); smt(). qed.
lemma hmsg_role_grind_count c :
  hoare[RoleGrind(HmsgMemo(AcceptedSamples)).run :
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1 /\
    (res=None => HmsgMemo.accepted_calls=c) /\
    (res<>None => size (oget res).`1=16 /\ size (oget res).`2=256)].
proof.
  proc; while (independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\
    c<=HmsgMemo.accepted_calls<=c+1 /\ (result=None => HmsgMemo.accepted_calls=c) /\
    (result<>None => size (oget result).`1=16 /\ size (oget result).`2=256)).
  + wp; call (hmsg_hash_width_increment c); wp; call (hmsg_derive_width_count c);
      auto; smt(randomizer_width).
  auto; smt().
qed.
lemma hmsg_finish_count c :
  hoare[RawSigner(HmsgMemo(AcceptedSamples)).finish : size seed=32 /\ size randomizer=16 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c /\
    (res<>None => signature_width (oget res))].
proof.
  proc; wp; while (size seed=32 /\ size randomizer=16 /\ size shuffle=32 /\ size current=16 /\
    rows_width 13 forest.`1 /\ size forest.`2=12 /\ all (rows_width 11) forest.`2 /\
    0<=layer<=2 /\ (ok=>size layers=layer /\ all layer_width layers) /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c).
  + wp; call (hmsg_layer_sign_count c); auto; smt(all_cat cats1 size_rcons).
  wp; call (hmsg_forest_sign_count c); auto; rewrite /signature_width; smt().
qed.
lemma hmsg_sign_count c :
  hoare[RawSigner(HmsgMemo(AcceptedSamples)).sign : size seed=32 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1 /\
    (res<>None => signature_width (oget res))].
proof.
  proc; seq 1 : (size seed=32 /\ size shuffle=32 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1 /\
    (accepted<>None => size (oget accepted).`1=16)).
  + call (hmsg_role_grind_count c); auto; smt().
  sp 1; if; last by auto.
  exists* HmsgMemo.accepted_calls; elim*=> k; call (hmsg_finish_count k); auto; smt().
qed.
lemma signature_layer_width sig i : signature_width sig => 0<=i<2 =>
  layer_width (nth ([],0,[]) sig.`4 i).
proof. move=> [_ [_ [_ [_ [hs /allP ha]]]]] hi; apply ha; apply mem_nth; smt(). qed.
lemma hmsg_verify_count c :
  hoare[RawSigner(HmsgMemo(AcceptedSamples)).verify : size seed=32 /\ signature_width sig /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=c ==>
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1].
proof.
  proc; seq 1 : (size seed=32 /\ signature_width sig /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ c<=HmsgMemo.accepted_calls<=c+1).
  + call (hmsg_hash_width_increment c); auto; smt().
  sp 1; if; last by auto.
  exists* HmsgMemo.accepted_calls; elim*=> k.
  wp; while (size seed=32 /\ signature_width sig /\ size current=16 /\ 0<=layer<=2 /\
    independent_tables_valid HmsgMemo.rawhistory HmsgMemo.secrethistory /\ HmsgMemo.accepted_calls=k).
  + wp; call (hmsg_layer_recover_count k); auto; smt(signature_layer_width).
  wp; call (hmsg_forest_recover_count k); auto; rewrite /signature_width; smt().
qed.
