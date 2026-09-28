require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts NodeCatalog SecretLeafOrigins.

lemma hash_keeps_secret_leaves f g c :
  hoare [Independent.hash :
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c ==>
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c].
proof.
  proc; sp 1; if; auto; smt(secret_leaf_public_extends extends_insert).
qed.

lemma hash_records_secret_leaves f g c x0 :
  hoare [Independent.hash :
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\ x = x0 ==>
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\
    Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(secret_leaf_public_extends extends_insert get_set_sameE domE).
qed.

lemma derive_records_secret_leaves f g c tail0 :
  hoare [Independent.derive :
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\ tail = tail0 ==>
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\
    Independent.secrethistory.[tail0] = Some res].
proof.
  proc; if; auto;
    smt(secret_leaf_private_extends extends_insert get_set_sameE domE).
qed.

lemma fors_records_secret_leaves f g c tail0 :
  hoare [PreparationView(Independent).fors :
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\ tail = tail0 ==>
    secret_leaf_origins Independent.rawhistory Independent.secrethistory f g c /\
    Independent.secrethistory.[fors_tag ++ tail0] = Some res].
proof.
  proc; call (derive_records_secret_leaves f g c (fors_tag ++ tail0)); auto.
qed.
