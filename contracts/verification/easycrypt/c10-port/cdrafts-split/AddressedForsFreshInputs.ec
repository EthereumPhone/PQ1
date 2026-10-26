(* Canonicity concerns newly inserted inputs. Recovery still logs all calls,
   but an actual honestly generated path adds no new memo entries. *)
require import AllCore List FMap.
require import C10RawOracle PrefixGuess PrefixHybrid KeygenPrefixes RawKeygen RawFors RawForest RawSignature.
require import PersistentGrind AcceptedContexts PathReplay RawForsPathReplay ForsSignRecord WrapperForsReplay.
require import ForsComponentHistory AddressedForsCanonicity AddressedForsLog AddressedForsTreeQueries AddressedQueryProvenance.

op canonical_fors_new_inputs (old h s : (raw_input,digest) fmap) (seed : raw_input) =
  forall x, x \in h => x \in old \/ canonical_fors_input h s seed x.

lemma canonical_fors_new_inputs_from_log old base h s seed queries :
  appended_query_history old base h queries => canonical_fors_log h s seed base queries =>
  canonical_fors_new_inputs old h s seed.
proof.
  move=> hp [inputs [hq hi]] x hx; case (x \in old) => ho; first smt().
  have hm := appended_query_history_member old base h queries inputs x hp hq hx ho.
  move: hi; rewrite allP; smt().
qed.

lemma canonical_fors_new_inputs_initial h s seed : canonical_fors_new_inputs h h s seed.
proof. rewrite /canonical_fors_new_inputs; smt(). qed.

lemma canonical_fors_new_inputs_compose old h h' s s' seed :
  extends h h' => extends s s' => canonical_fors_new_inputs old h s seed =>
  canonical_fors_new_inputs h h' s' seed => canonical_fors_new_inputs old h' s' seed.
proof.
  move=> hh hs hp hn x hx; have hc := hn x hx.
  case (x \in h) => hm; first smt(canonical_fors_input_extends).
  smt().
qed.

lemma raw_fors_sign_fresh_inputs seed0 ht0 tree0 old base :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    Independent.rawhistory=old /\ Independent.queries=base ==>
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (raw_fors_sign_canonical_queries seed0 ht0 tree0 base)
    (fors_sign_appended_query_history RawFors old base);
    smt(canonical_fors_log_empty appended_query_history_initial canonical_fors_new_inputs_from_log).
qed.

lemma raw_fors_root_fresh_inputs seed0 ht0 tree0 old base :
  hoare [RawFors(PreparationView(Independent)).root :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    Independent.rawhistory=old /\ Independent.queries=base ==>
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  conseq (raw_fors_root_canonical_queries seed0 ht0 tree0 base)
    (fors_root_appended_query_history RawFors old base);
    smt(canonical_fors_log_empty appended_query_history_initial canonical_fors_new_inputs_from_log).
qed.

lemma raw_fors_sign_fresh_recorded seed0 ht0 tree0 target0 old base :
  hoare [RawFors(PreparationView(Independent)).sign :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ target=target0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    0<=target0<2048 /\ Independent.rawhistory=old /\ Independent.queries=base ==>
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    rows_width 11 res.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 res.`1]=Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0) (node d,0,target0) res.`2].
proof.
  conseq (raw_fors_sign_fresh_inputs seed0 ht0 tree0 old base)
    (fors_sign_recorded seed0 ht0 tree0 target0); smt().
qed.

lemma raw_forest_one_fresh_inputs seed0 ht0 tree0 target0 old base :
  hoare [RawForest(PreparationView(Independent)).one :
    seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\ 0<=ht0<2^64 /\ 0<=tree0<13 /\
    0<=target0<2048 /\ Independent.rawhistory=old /\ Independent.queries=base ==>
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0].
proof.
  proc; seq 1 : (seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    rows_width 11 sig.`2 /\ exists d,
      Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 sig.`1]=Some d /\
      path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0) (node d,0,target0) sig.`2).
  + call (raw_fors_sign_fresh_recorded seed0 ht0 tree0 target0 old base); auto; smt().
  conseq (_ : exists d, seed=seed0 /\ ht=ht0 /\ tree=tree0 /\ leaf=target0 /\
    canonical_fors_new_inputs old Independent.rawhistory Independent.secrethistory seed0 /\
    rows_width 11 sig.`2 /\
    Independent.rawhistory.[fors_leaf_input seed0 ht0 tree0 target0 sig.`1]=Some d /\
    path_recorded Independent.rawhistory (fors_pair seed0 ht0 tree0) (node d,0,target0) sig.`2 ==> _);
    first smt().
  elim* => d0; exists* sig,Independent.rawhistory; elim* => sig0 h0.
  call (wrapper_fors_recover_tables seed0 ht0 tree0 target0 sig0.`1 sig0.`2 d0 h0).
  auto; rewrite /rows_width; smt().
qed.
