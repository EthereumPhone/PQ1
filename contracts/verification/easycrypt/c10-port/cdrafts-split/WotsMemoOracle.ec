(* Acceptance is split only for fresh count-shaped public inputs. Private derivation
   and every other public input keep their original full-digest distribution. *)
require import AllCore List Distr FMap DBool.
require import C10RawOracle RawWots C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import WotsAcceptanceMass WotsAcceptedDistribution WotsAcceptedPrefix WotsCountDomain.
import DBool.Biased.

module WotsFullFreshDigest = {
  proc sample() : digest = { var d; d <$ full_digest; return d; }
}.
module SplitWotsAcceptedDigest (S : WotsAcceptedSampler) = {
  proc sample() : digest = {
    var accepted, d;
    accepted <$ dbiased wots_acceptance_mass;
    if (accepted) { d <@ S.sample(); } else { d <$ rejected_wots_digest; }
    return d;
  }
}.

module PlainWotsAcceptedSplit = {
  proc sample() : digest = {
    var accepted, d;
    accepted <$ dbiased wots_acceptance_mass;
    d <$ if accepted then accepted_wots_digest else rejected_wots_digest;
    return d;
  }
}.
lemma plain_wots_accepted_split_refinement :
  equiv [WotsFullFreshDigest.sample ~ PlainWotsAcceptedSplit.sample : true ==> ={res}].
proof.
  proc; rndsem*{2} 0.
  auto=>/>.
  have he : dlet (dbiased wots_acceptance_mass) (fun b =>
      dmap (if b then accepted_wots_digest else rejected_wots_digest) (fun d => d)) = full_digest.
  + rewrite full_digest_wots_acceptance_split; apply eq_dlet => // b.
    by rewrite dmap_id.
  by rewrite he; smt().
qed.

lemma split_wots_accepted_digest_refinement :
  equiv [WotsFullFreshDigest.sample ~ SplitWotsAcceptedDigest(WotsAcceptedSamples).sample : true ==> ={res}].
proof.
  transitivity PlainWotsAcceptedSplit.sample (true ==> ={res}) (true ==> ={res}) => //.
  + exact plain_wots_accepted_split_refinement.
  proc; inline WotsAcceptedSamples.sample.
  seq 1 1 : (={accepted}); first by auto.
  by if{2}; auto; smt().
qed.

module WotsMemo (S : WotsAcceptedSampler) = {
  var rawhistory, secrethistory : (raw_input,digest) fmap
  var queries, accepted_keys : raw_input list
  var accepted_calls : int
  proc init() : unit = {
    rawhistory <- empty; secrethistory <- empty; queries <- []; accepted_keys <- []; accepted_calls <- 0;
  }
  proc hash(x : raw_input) : digest = {
    var d;
    queries <- rcons queries x;
    if (x \notin rawhistory) {
      if (wots_count_query x) { d <@ SplitWotsAcceptedDigest(S).sample(); }
      else { d <$ full_digest; }
      rawhistory.[x] <- d;
      if (wots_count_query x /\ count_accepts d) { accepted_keys <- rcons accepted_keys x; }
    }
    d <- oget rawhistory.[x];
    if (wots_count_query x /\ count_accepts d) { accepted_calls <- accepted_calls+1; }
    return d;
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail \notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

lemma wots_accepted_samples_lossless : islossless WotsAcceptedSamples.sample.
proof. proc; auto; smt(accepted_wots_digest_ll). qed.
lemma split_wots_accepted_lossless (S <: WotsAcceptedSampler) :
  islossless S.sample => islossless SplitWotsAcceptedDigest(S).sample.
proof.
  move=> hs; proc; seq 1 : true 1%r 1%r 0%r 0%r => //; first by auto; smt(dbiased_ll).
  if; auto; first by call hs; auto.
  smt(rejected_wots_digest_ll).
qed.
lemma wots_memo_hash_lossless (S <: WotsAcceptedSampler {-WotsMemo}) :
  islossless S.sample => islossless WotsMemo(S).hash.
proof.
  move=> hs; proc; wp; sp 1; if; last by auto.
  wp; if.
  + call (split_wots_accepted_lossless S hs); auto.
  auto; smt(full_digest_ll).
qed.
lemma wots_memo_derive_lossless (S <: WotsAcceptedSampler) : islossless WotsMemo(S).derive.
proof. proc; if; auto; smt(full_digest_ll). qed.

module WotsFactoredIndependentHash = {
  proc hash(x : raw_input) : digest = {
    var y;
    Independent.queries <- rcons Independent.queries x;
    if (x \notin Independent.rawhistory) {
      y <@ WotsFullFreshDigest.sample(); Independent.rawhistory.[x] <- y;
    }
    return oget Independent.rawhistory.[x];
  }
}.
lemma wots_factored_independent_hash :
  equiv [Independent.hash ~ WotsFactoredIndependentHash.hash :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. proc; inline WotsFullFreshDigest.sample; sp 1 1; if; auto; smt(). qed.

lemma wots_factored_hash_refinement :
  equiv [WotsFactoredIndependentHash.hash ~ WotsMemo(WotsAcceptedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2}].
proof.
  proc; wp; sp 1 1; if.
  + auto; smt().
  + wp; if{2}; last by inline WotsFullFreshDigest.sample; auto; smt().
    call split_wots_accepted_digest_refinement; auto; smt().
  auto; smt().
qed.
lemma wots_memo_hash_refinement :
  equiv [Independent.hash ~ WotsMemo(WotsAcceptedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2}].
proof.
  transitivity WotsFactoredIndependentHash.hash
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={x} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
      Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
      Independent.queries{1}=WotsMemo.queries{2} ==>
      ={res} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
      Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
      Independent.queries{1}=WotsMemo.queries{2}) => //.
  + by move=> &1 &2 h; exists Independent.queries{1} Independent.rawhistory{1} Independent.secrethistory{1} x{1}; smt().
  + exact wots_factored_independent_hash.
  exact wots_factored_hash_refinement.
qed.
lemma wots_memo_derive_refinement :
  equiv [Independent.derive ~ WotsMemo(WotsAcceptedSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2}].
proof. proc; if; auto. qed.
lemma wots_memo_context_refinement (A <: PrefixContext {-Independent,-WotsMemo,-WotsAcceptedSamples}) :
  equiv [A(Independent).run ~ A(WotsMemo(WotsAcceptedSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=WotsMemo.rawhistory{2} /\
    Independent.secrethistory{1}=WotsMemo.secrethistory{2} /\
    Independent.queries{1}=WotsMemo.queries{2}) => //.
  + exact wots_memo_hash_refinement.
  exact wots_memo_derive_refinement.
qed.
