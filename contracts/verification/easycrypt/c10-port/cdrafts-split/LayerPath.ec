(* WOTS activity retains the actual Merkle path supplied by layer construction. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawWots RawLayer.
require import PathReplay PathOracle RawPathReplay PersistentGrind AcceptedContexts.

op layer_path h seed layer tree index leaf auth root =
  size auth=9 /\ path_recorded h (merkle_pair seed layer tree) (leaf,0,index) auth /\
    (path_value h (merkle_pair seed layer tree) (leaf,0,index) auth).`1=root.

module type WotsSigning (O : PreparationOracle) = {
  proc sign(seed : raw_input, layer tree kp : int, message shuffle : raw_input) :
    (raw_input list * int) option { O.hash, O.wots }
}.
module type WotsRecovery (O : PreparationOracle) = {
  proc recover(seed : raw_input, layer tree kp : int, message : raw_input,
    sigma : raw_input list, count : int) : raw_input { O.hash }
}.

lemma hash_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [Independent.hash :
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  proc; sp 1; if; auto; rewrite /layer_path; smt(path_recorded_extends extends_insert).
qed.

lemma wots_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [PreparationView(Independent).wots :
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof. proc; inline *; sp; if; auto. qed.

lemma signing_keeps_layer_path (S <: WotsSigning {-Independent}) seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [S(PreparationView(Independent)).sign :
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  proc (layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0) => //.
  + exact (hash_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0).
  exact (wots_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0).
qed.

lemma recovery_keeps_layer_path (R <: WotsRecovery {-Independent}) seed0 layer0 tree0 index0 leaf0 auth0 root0 :
  hoare [R(PreparationView(Independent)).recover :
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0].
proof.
  proc (layer_path Independent.rawhistory seed0 layer0 tree0 index0 leaf0 auth0 root0) => //.
  exact (hash_keeps_layer_path seed0 layer0 tree0 index0 leaf0 auth0 root0).
qed.
