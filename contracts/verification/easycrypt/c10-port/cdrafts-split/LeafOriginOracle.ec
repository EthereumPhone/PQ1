require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts NodeCatalog LeafOrigins.

lemma hash_keeps_leaf_origins f c :
  hoare [Independent.hash : leaf_origins Independent.rawhistory f c ==>
    leaf_origins Independent.rawhistory f c].
proof.
  proc; sp 1; if; auto; smt(leaf_origins_history_extends extends_insert).
qed.

lemma hash_records_leaf_origins f c x0 :
  hoare [Independent.hash : leaf_origins Independent.rawhistory f c /\ x = x0 ==>
    leaf_origins Independent.rawhistory f c /\ Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(leaf_origins_history_extends extends_insert get_set_sameE domE).
qed.

lemma fors_keeps_leaf_origins f c :
  hoare [PreparationView(Independent).fors : leaf_origins Independent.rawhistory f c ==>
    leaf_origins Independent.rawhistory f c].
proof. by proc; inline *; sp; if; auto. qed.
