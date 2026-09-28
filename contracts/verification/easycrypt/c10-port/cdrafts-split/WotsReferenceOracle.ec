(* Both memoized oracle tables preserve already completed WOTS references. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts WotsReference.

lemma hash_keeps_wots_reference seed0 layer0 tree0 kp0 n values key sd :
  hoare [Independent.hash :
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some sd ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some sd].
proof.
  proc; sp 1; if; auto; smt(wots_prefix_extends extends_insert extends_refl).
qed.

lemma derive_records_wots_reference seed0 layer0 tree0 kp0 n values key :
  hoare [Independent.derive :
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\ tail=key ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[key] = Some res].
proof.
  proc; if; auto; smt(wots_prefix_extends extends_insert extends_refl get_set_sameE domE).
qed.

lemma wots_records_reference seed0 layer0 tree0 kp0 n values :
  hoare [PreparationView(Independent).wots :
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    tail=wots_tail layer0 tree0 kp0 n ==>
    wots_prefix Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n /\
    wots_elements Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 kp0 n = values /\
    Independent.secrethistory.[wots_key layer0 tree0 kp0 n] = Some res].
proof.
  proc; call (derive_records_wots_reference seed0 layer0 tree0 kp0 n values (wots_key layer0 tree0 kp0 n)).
  auto; rewrite /wots_key; smt().
qed.
