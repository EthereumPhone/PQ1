(* WOTS and layer failures originate in the actual physical count search.
   Successful reconstructed nodes satisfy the finite-domain byte premises. *)
require import AllCore List Distr FMap IntDiv.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid KeygenPrefixes.
require import PreparedGrind KeygenExhaustion RObservedSigner RoleGrind.
require import RawWots RawLayer RawForest RawSigner RawCompositeWidths.
require import ByteSession RawByteValues RawCompositeBytes.
require import MemoRejectCompletion WotsRejectDomain WotsPhysicalFailure.

lemma physical_count_failure seed0 layer0 tree0 kp0 message0 :
  hoare[RawWots(PreparationView(Physical)).count :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  conseq (physical_count_complete seed0 layer0 tree0 kp0 message0) => //.
  move=> &hr [#] _ _ _ _ _ hw hb result history hp hn.
  have [c [hc hs]] := wots_context_covered seed0 layer0 tree0 kp0 message0 hw hb.
  rewrite /wots_domain_exhausted; exists c; split; first exact hc.
  rewrite hs -wots_context_stem_actual; exact (hp hn).
qed.

lemma physical_wots_failure seed0 layer0 tree0 kp0 message0 :
  hoare[RawWots(PreparationView(Physical)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ kp=kp0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; seq 1 : (accepted=None => wots_domain_exhausted seed0 signing_budget Shared.history).
  + call (physical_count_failure seed0 layer0 tree0 kp0 message0); auto.
  sp 1; if; last by auto; smt().
  wp; while true.
  + wp; call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma physical_layer_failure seed0 layer0 tree0 leaf0 message0 :
  hoare[RawLayer(PreparationView(Physical)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; seq 3 : (signed=None => wots_domain_exhausted seed0 signing_budget Shared.history).
  + call (physical_wots_failure seed0 layer0 tree0 leaf0 message0).
    call (_ : true ==> true); first by trivial.
    call (_ : true ==> true); first by trivial.
    auto.
  sp 1; if; last by auto; smt().
  wp; call (_ : true ==> true); first by trivial.
  auto.
qed.

lemma physical_layer_node :
  hoare[RawLayer(PreparationView(Physical)).sign : true ==>
    res<>None => size (oget res).`2=16 /\ byte_values (oget res).`2].
proof.
  have [#] hh hw hf := preparation_view_lossless Physical physical_hash_ll physical_derive_ll.
  conseq (raw_layer_width (PreparationView(Physical)) hh hw)
    (raw_layer_bytes (PreparationView(Physical)) hh hw); smt().
qed.

lemma physical_forest_node :
  hoare[RawForest(PreparationView(Physical)).sign : true ==>
    size res.`3=16 /\ byte_values res.`3].
proof.
  have [#] hh hw hf := preparation_view_lossless Physical physical_hash_ll physical_derive_ll.
  conseq (raw_forest_width (PreparationView(Physical)) hh hf)
    (raw_forest_bytes (PreparationView(Physical)) hh hf); smt().
qed.

lemma physical_layer_outcome seed0 layer0 tree0 leaf0 message0 :
  hoare[RawLayer(PreparationView(Physical)).sign :
    seed=seed0 /\ layer=layer0 /\ tree=tree0 /\ leaf=leaf0 /\ message=message0 /\
    size message0=16 /\ byte_values message0 ==>
    (res=None => wots_domain_exhausted seed0 signing_budget Shared.history) /\
    (res<>None => size (oget res).`2=16 /\ byte_values (oget res).`2)].
proof.
  conseq (physical_layer_failure seed0 layer0 tree0 leaf0 message0) physical_layer_node; smt().
qed.

lemma physical_finish_failure seed0 :
  hoare[RawSigner(Physical).finish : seed=seed0 ==>
    res=None => wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; wp; while (seed=seed0 /\ 0<=layer<=2 /\
    (ok => size current=16 /\ byte_values current) /\
    (!ok => wots_domain_exhausted seed0 signing_budget Shared.history)).
  + exists* layer, idx_tree, current; elim* => l t m.
    wp; call (physical_layer_outcome seed0 l (t %/ 512) (t %% 512) m); auto; smt().
  wp; call physical_forest_node; auto; smt().
qed.

lemma physical_observed_sign_failure seed0 :
  hoare[RObservedSigner(Physical).sign : seed=seed0 ==>
    res=None => RFailure.bad \/ wots_domain_exhausted seed0 signing_budget Shared.history].
proof.
  proc; seq 1 : (seed=seed0).
  + call (_ : true ==> true); first by trivial.
    auto.
  sp 2; if; last by auto; smt().
  call (physical_finish_failure seed0); auto; smt().
qed.
