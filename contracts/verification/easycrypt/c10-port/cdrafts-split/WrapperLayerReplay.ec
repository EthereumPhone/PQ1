(* An honest layer opening justifies every WOTS and Merkle recovery query.
   These actual calls retain both memo tables; no query-log equality is claimed. *)
require import AllCore List FMap IntDiv.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawMerkle RawWots RawLayer.
require import PathReplay RawPathReplay RawChainCached LayerPath LayerSignOpening WotsSignWitness WotsOpeningPersistent.
require import WrapperForsReplay WrapperWotsReplay.

lemma wrapper_merkle_recover_tables seed0 layer0 tree0 leaf0 index0 auth0 root0 h0 :
  hoare [RawMerkle(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ index=index0 /\ auth=auth0 /\
    Independent.rawhistory=h0 /\ layer_path h0 seed0 layer0 tree0 index0 leaf0 auth0 root0 ==>
    Independent.rawhistory=h0 /\ res=root0].
proof.
  proc; while (seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ auth=auth0 /\
    0<=h<=9 /\ Independent.rawhistory=h0 /\
    layer_path h0 seed0 layer0 tree0 index0 leaf0 auth0 root0 /\
    path_value h0 (merkle_pair seed0 layer0 tree0) (leaf0,0,index0) (take h auth0)=(current,h,idx)).
  + exists* h,current,idx; elim* => k current0 idx0.
    wp; call (hash_existing_entry h0
      (path_input (merkle_pair seed0 layer0 tree0) (current0,k,idx0) (nth (nseq 16 0) auth0 k))
      (oget h0.[path_input (merkle_pair seed0 layer0 tree0) (current0,k,idx0) (nth (nseq 16 0) auth0 k)])).
    auto; move=> &m hp.
    have hi : 0<=k<size auth0 by move: hp; rewrite /layer_path; smt().
    have hr : path_recorded h0 (merkle_pair seed0 layer0 tree0) (leaf0,0,index0) auth0
      by move: hp; rewrite /layer_path; smt().
    have he : path_value h0 (merkle_pair seed0 layer0 tree0) (leaf0,0,index0) (take k auth0)=(current0,k,idx0)
      by smt().
    have [d0 [hd hv]] := wrapper_path_recorded_next h0 (merkle_pair seed0 layer0 tree0) (leaf0,0,index0) auth0 k hi hr.
    rewrite he /path_input /merkle_pair /= in hd.
    rewrite he /merkle_pair /= in hv.
    move: hp; rewrite /path_input /merkle_pair /=; smt().
  auto; rewrite /layer_path /path_value /= take0; smt(take_size).
qed.

lemma wrapper_layer_opening_tables seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) root0 h0 s0 :
  hoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    Independent.rawhistory=h0 /\ layer_opening h0 s0 seed0 layer0 tree0 index0 message0 sig0 root0 ==>
    Independent.rawhistory=h0 /\ res=root0].
proof.
  conseq (_ : exists pk,
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    Independent.rawhistory=h0 /\
    wots_opening h0 s0 seed0 layer0 tree0 index0 message0 pk (sig0.`1,sig0.`2) /\
    layer_path h0 seed0 layer0 tree0 index0 pk sig0.`3 root0 ==> _).
  + rewrite /layer_opening; smt(wots_opening_extends).
  elim* => pk0; proc.
  call (wrapper_merkle_recover_tables seed0 layer0 tree0 pk0 index0 sig0.`3 root0 h0).
  call (wrapper_wots_opening_tables seed0 layer0 tree0 index0 message0 (sig0.`1,sig0.`2) pk0 h0 s0).
  auto.
qed.

lemma wrapper_layer_recover_total seed0 layer0 tree0 index0 message0 (sig0 : layer_signature) root0 h0 s0 :
  phoare [RawLayer(PreparationView(Independent)).recover :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=index0 /\ message=message0 /\ sig=sig0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    layer_opening h0 s0 seed0 layer0 tree0 index0 message0 sig0 root0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=root0] = 1%r.
proof.
  conseq (layer_recover_lossless (PreparationView(Independent)) independent_hash_ll)
    (wrapper_layer_opening_tables seed0 layer0 tree0 index0 message0 sig0 root0 h0 s0); smt().
qed.
