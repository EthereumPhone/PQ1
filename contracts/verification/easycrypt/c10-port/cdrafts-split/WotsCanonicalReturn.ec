(* At one component message, successful signer returns expose identical WOTS positions. *)
require import AllCore List FMap.
require import C10RawOracle RawKeygen RawCountRecorded WotsFirstCount LayerMinimumCounts.
require import WotsSignatureValue WotsSignWitness LayerSignOpening WotsOpeningPersistent.

lemma minimal_opening_digest h s seed layer tree kp message signature root :
  minimal_layer_count h seed layer tree kp message signature =>
  layer_opening h s seed layer tree kp message signature root =>
  exists d, first_wots_count h seed layer tree kp message signature.`2 d /\
    wots_signature h s seed layer tree kp d signature.`1.
proof.
  move=> [d hc] ho.
  have [leaf [hr [hn [d' [ha [hd hw]]]]]] :=
    layer_current_wots_opening h s seed layer tree kp message signature root ho.
  exists d; move: hc; rewrite /first_wots_count; smt().
qed.

lemma canonical_layer_return h s seed layer tree kp message signature signature' root root' :
  minimal_layer_count h seed layer tree kp message signature =>
  minimal_layer_count h seed layer tree kp message signature' =>
  layer_opening h s seed layer tree kp message signature root =>
  layer_opening h s seed layer tree kp message signature' root' =>
  signature.`2=signature'.`2 /\ signature.`1=signature'.`1.
proof.
  move=> hc hc' ho ho'.
  have [d [hd hw]] := minimal_opening_digest h s seed layer tree kp message signature root hc ho.
  have [d' [hd' hw']] := minimal_opening_digest h s seed layer tree kp message signature' root' hc' ho'.
  have [he he'] := first_wots_count_unique h seed layer tree kp message signature.`2 d signature'.`2 d' hd hd'.
  split; first exact he.
  apply (wots_same_digest_signature h s seed layer tree kp d signature.`1 signature'.`1); smt().
qed.
