(* Honest forest recovery reads only entries already retained in its opening.
   The actual public query log grows; both oracle maps are unchanged. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawSignature.
require import PathReplay RawForsPathReplay RawChainCached ForsOpening ForestOpenings ForestWitness ForestOpening.
require import WrapperForsReplay.

lemma wrapper_fors_opening_tables seed0 ht0 tree0 target0 secret0 auth0 root0 h0 :
  hoare [RawFors(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\
    Independent.rawhistory=h0 /\ fors_opening h0 seed0 ht0 tree0 target0 secret0 auth0 root0 ==>
    Independent.rawhistory=h0 /\ res=root0].
proof.
  conseq (_ : exists d,
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ secret=secret0 /\ auth=auth0 /\
    Independent.rawhistory=h0 /\ size auth0=11 /\
    h0.[fors_leaf_input seed0 ht0 tree0 target0 secret0]=Some d /\
    path_recorded h0 (fors_pair seed0 ht0 tree0) (node d,0,target0) auth0 /\
    (path_value h0 (fors_pair seed0 ht0 tree0) (node d,0,target0) auth0).`1=root0 ==> _).
  + rewrite /fors_opening /rows_width; smt().
  elim* => d.
  conseq (wrapper_fors_recover_tables seed0 ht0 tree0 target0 secret0 auth0 d h0); smt().
qed.

lemma wrapper_forest_fixed_tables seed0 ht0 digest0 secrets0 auths0 roots0 lastd finald h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\ Independent.rawhistory=h0 ==>
    Independent.rawhistory=h0 /\ res=node finald].
proof.
  proc; call (hash_existing_entry h0 (forest_compress_input seed0 ht0 roots0) finald).
  wp; call (hash_existing_entry h0 (forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)) lastd).
  wp; while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\ 0<=t<=12 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\ roots=take t roots0 /\ Independent.rawhistory=h0).
  + exists* t; elim* => t0; wp.
    call (wrapper_fors_opening_tables seed0 ht0 t0 (forest_index digest0 t0)
      (nth (nseq 16 0) secrets0 t0) (nth [] auths0 t0) (nth (nseq 16 0) roots0 t0) h0).
    auto; rewrite /forest_openings; smt(mem_range take_nth).
  auto; rewrite /forest_special_input /fors_leaf_input /forest_compress_input /forest_openings;
    smt(take_nth take_size take0).
qed.

lemma wrapper_forest_opening_tables seed0 ht0 digest0 secrets0 auths0 root0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    Independent.rawhistory=h0 /\ forest_opening h0 seed0 ht0 digest0 secrets0 auths0 root0 ==>
    Independent.rawhistory=h0 /\ res=root0].
proof.
  conseq (_ : exists roots finald lastd,
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots]=Some finald /\ root0=node finald /\ Independent.rawhistory=h0 ==> _).
  + rewrite /forest_opening /forest_witness; smt().
  elim* => roots finald lastd.
  conseq (wrapper_forest_fixed_tables seed0 ht0 digest0 secrets0 auths0 roots lastd finald h0); smt().
qed.

lemma wrapper_forest_recover_total seed0 ht0 digest0 secrets0 auths0 root0 h0 s0 :
  phoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\
    forest_opening h0 seed0 ht0 digest0 secrets0 auths0 root0 ==>
    Independent.rawhistory=h0 /\ Independent.secrethistory=s0 /\ res=root0] = 1%r.
proof.
  conseq (forest_recover_lossless (PreparationView(Independent)) independent_hash_ll)
    (wrapper_forest_opening_tables seed0 ht0 digest0 secrets0 auths0 root0 h0); smt().
qed.
