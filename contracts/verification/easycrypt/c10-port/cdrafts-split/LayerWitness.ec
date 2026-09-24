(* The actual builder's WOTS leaf and Merkle path persist through shuffling. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawShuffle.
require import PersistentGrind AcceptedContexts PathReplay LayerPath WotsReferenceRoot.

op layer_witness h s seed layer tree index leaf auth root =
  wots_root h s seed layer tree index leaf /\ layer_path h seed layer tree index leaf auth root.

lemma layer_witness_extends h h' s s' seed layer tree index leaf auth root :
  extends h h' => extends s s' => layer_witness h s seed layer tree index leaf auth root =>
  layer_witness h' s' seed layer tree index leaf auth root.
proof.
  rewrite /layer_witness /layer_path; smt(wots_root_extends path_recorded_extends).
qed.

lemma hash_keeps_layer_witness seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [Independent.hash :
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof. proc; sp 1; if; auto; smt(layer_witness_extends extends_insert extends_refl). qed.

lemma shuffle_keeps_layer_witness seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [RawShuffle(PreparationView(Independent)).derive :
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_witness Independent.rawhistory Independent.secrethistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  proc; sp 1; if; auto; wp.
  call (hash_keeps_layer_witness seed0 layer0 tree0 index0 leaf0 auth0 root0); auto.
qed.
