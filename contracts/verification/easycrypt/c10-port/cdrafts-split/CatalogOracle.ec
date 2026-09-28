require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen.
require import PersistentGrind AcceptedContexts NodeCatalog.

lemma hash_keeps_catalog f c :
  hoare[Independent.hash : catalog_sound Independent.rawhistory f c ==>
    catalog_sound Independent.rawhistory f c].
proof.
  proc; sp 1; if; auto; smt(catalog_sound_history_extends extends_insert).
qed.

lemma hash_records_catalog f c x0 :
  hoare[Independent.hash : catalog_sound Independent.rawhistory f c /\ x = x0 ==>
    catalog_sound Independent.rawhistory f c /\ Independent.rawhistory.[x0] = Some res].
proof.
  proc; sp 1; if; auto;
    smt(catalog_sound_history_extends extends_insert get_set_sameE domE).
qed.

lemma wots_keeps_catalog f c :
  hoare[PreparationView(Independent).wots : catalog_sound Independent.rawhistory f c ==>
    catalog_sound Independent.rawhistory f c].
proof. by proc; inline *; sp; if; auto. qed.

module type CatalogLeaf (O : PreparationOracle) = {
  proc leaf(seed : raw_input, layer tree kp : int) : raw_input { O.hash, O.wots }
}.

lemma leaf_keeps_catalog (L <: CatalogLeaf {-Independent}) f c :
  hoare[L(PreparationView(Independent)).leaf : catalog_sound Independent.rawhistory f c ==>
    catalog_sound Independent.rawhistory f c].
proof.
  proc (catalog_sound Independent.rawhistory f c) => //.
  + exact (hash_keeps_catalog f c).
  exact (wots_keeps_catalog f c).
qed.

lemma fors_keeps_catalog f c :
  hoare[PreparationView(Independent).fors : catalog_sound Independent.rawhistory f c ==>
    catalog_sound Independent.rawhistory f c].
proof. by proc; inline *; sp; if; auto. qed.
