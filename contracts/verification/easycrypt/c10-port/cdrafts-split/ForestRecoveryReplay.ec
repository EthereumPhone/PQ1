(* Actual forest recovery repeats twelve paths, the special last hash, and
   the exact padded-root compression already retained by signing. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawForsPathReplay.
require import PersistentGrind ForestOpenings ForestWitness ForsOpeningReplay FixedHashReplay.

lemma forest_recover_fixed seed0 ht0 digest0 secrets0 auths0 roots0 lastd finald s0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=node finald /\ extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory].
proof.
  proc; call (hash_from_history (forest_compress_input seed0 ht0 roots0) finald s0 h0).
  wp; call (hash_from_history (forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)) lastd s0 h0).
  wp; while (seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\ 0<=t<=12 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\ roots=take t roots0 /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory).
  + exists* t; elim* => t0; wp.
    call (fixed_fors_recover seed0 ht0 t0 (forest_index digest0 t0)
      (nth (nseq 16 0) secrets0 t0) (nth [] auths0 t0) (nth (nseq 16 0) roots0 t0) s0 h0).
    auto; rewrite /forest_openings; smt(mem_range take_nth).
  auto; rewrite /forest_special_input /fors_leaf_input /forest_compress_input /forest_openings;
    smt(take_nth take_size take0).
qed.

lemma forest_recover_witness seed0 ht0 digest0 secrets0 auths0 roots0 finald s0 h0 :
  hoare [RawForest(PreparationView(Independent)).recover :
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_witness h0 seed0 ht0 digest0 secrets0 auths0 roots0 /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==>
    res=node finald].
proof.
  conseq (_ : exists lastd,
    seed=seed0 /\ ht=ht0 /\ digest=digest0 /\ secrets=secrets0 /\ auths=auths0 /\
    forest_openings h0 seed0 ht0 digest0 secrets0 auths0 roots0 (range 0 12) /\
    h0.[forest_special_input seed0 ht0 (nth (nseq 16 0) secrets0 12)]=Some lastd /\
    nth (nseq 16 0) roots0 12=node lastd /\
    h0.[forest_compress_input seed0 ht0 roots0]=Some finald /\
    extends s0 Independent.secrethistory /\ extends h0 Independent.rawhistory ==> res=node finald).
  + rewrite /forest_witness; smt().
  elim* => lastd.
  conseq (forest_recover_fixed seed0 ht0 digest0 secrets0 auths0 roots0 lastd finald s0 h0); smt().
qed.
