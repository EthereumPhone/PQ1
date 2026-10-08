(* Acceptance is split only for fresh 160-byte public inputs. Private derivation
   and every other public input keep their original full-digest distribution. *)
require import AllCore List Distr FMap DBool.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess PrefixHybrid.
require import AcceptedSampling AcceptedDigestDistribution AcceptedPrefixSampling.
import DBool.Biased.

module FullFreshDigest = {
  proc sample() : digest = { var d; d <$ full_digest; return d; }
}.
module SplitAcceptedDigest (S : AcceptedSampler) = {
  proc sample() : digest = {
    var accepted, d;
    accepted <$ dbiased acceptance_rate;
    if (accepted) { d <@ S.sample(); } else { d <$ rejected_digest; }
    return d;
  }
}.

module PlainAcceptedSplit = {
  proc sample() : digest = {
    var accepted, d;
    accepted <$ dbiased acceptance_rate;
    d <$ if accepted then accepted_digest else rejected_digest;
    return d;
  }
}.
lemma plain_accepted_split_refinement :
  equiv [FullFreshDigest.sample ~ PlainAcceptedSplit.sample : true ==> ={res}].
proof.
  proc; rndsem*{2} 0.
  auto=>/>.
  have he : dlet (dbiased acceptance_rate) (fun b =>
      dmap (if b then accepted_digest else rejected_digest) (fun d => d)) = full_digest.
  + rewrite full_digest_acceptance_split; apply eq_dlet => // b.
    by rewrite dmap_id.
  by rewrite he; smt().
qed.

lemma split_accepted_digest_refinement :
  equiv [FullFreshDigest.sample ~ SplitAcceptedDigest(AcceptedSamples).sample : true ==> ={res}].
proof.
  transitivity PlainAcceptedSplit.sample (true ==> ={res}) (true ==> ={res}) => //.
  + exact plain_accepted_split_refinement.
  proc; inline AcceptedSamples.sample.
  seq 1 1 : (={accepted}); first by auto.
  by if{2}; auto; smt().
qed.

module HmsgMemo (S : AcceptedSampler) = {
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
      if (size x=160) { d <@ SplitAcceptedDigest(S).sample(); }
      else { d <$ full_digest; }
      rawhistory.[x] <- d;
      if (size x=160 /\ accept_digest d) { accepted_keys <- rcons accepted_keys x; }
    }
    d <- oget rawhistory.[x];
    if (size x=160 /\ accept_digest d) { accepted_calls <- accepted_calls+1; }
    return d;
  }
  proc derive(tail : raw_input) : digest = {
    var d;
    if (tail \notin secrethistory) { d <$ full_digest; secrethistory.[tail] <- d; }
    return oget secrethistory.[tail];
  }
}.

lemma accepted_samples_lossless : islossless AcceptedSamples.sample.
proof. proc; auto; smt(accepted_digest_ll). qed.
lemma split_accepted_lossless (S <: AcceptedSampler) :
  islossless S.sample => islossless SplitAcceptedDigest(S).sample.
proof.
  move=> hs; proc; seq 1 : true 1%r 1%r 0%r 0%r => //; first by auto; smt(dbiased_ll).
  if; auto; first by call hs; auto.
  smt(rejected_digest_ll).
qed.
lemma hmsg_memo_hash_lossless (S <: AcceptedSampler {-HmsgMemo}) :
  islossless S.sample => islossless HmsgMemo(S).hash.
proof.
  move=> hs; proc; wp; sp 1; if; last by auto.
  wp; if.
  + call (split_accepted_lossless S hs); auto.
  auto; smt(full_digest_ll).
qed.
lemma hmsg_memo_derive_lossless (S <: AcceptedSampler) : islossless HmsgMemo(S).derive.
proof. proc; if; auto; smt(full_digest_ll). qed.

module FactoredIndependentHash = {
  proc hash(x : raw_input) : digest = {
    var y;
    Independent.queries <- rcons Independent.queries x;
    if (x \notin Independent.rawhistory) {
      y <@ FullFreshDigest.sample(); Independent.rawhistory.[x] <- y;
    }
    return oget Independent.rawhistory.[x];
  }
}.
lemma factored_independent_hash :
  equiv [Independent.hash ~ FactoredIndependentHash.hash :
    ={arg,glob Independent} ==> ={res,glob Independent}].
proof. proc; inline FullFreshDigest.sample; sp 1 1; if; auto; smt(). qed.

lemma hmsg_factored_hash_refinement :
  equiv [FactoredIndependentHash.hash ~ HmsgMemo(AcceptedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2}].
proof.
  proc; wp; sp 1 1; if.
  + auto; smt().
  + wp; if{2}; last by inline FullFreshDigest.sample; auto; smt().
    call split_accepted_digest_refinement; auto; smt().
  auto; smt().
qed.
lemma hmsg_memo_hash_refinement :
  equiv [Independent.hash ~ HmsgMemo(AcceptedSamples).hash :
    ={x} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2}].
proof.
  transitivity FactoredIndependentHash.hash
    (={arg,glob Independent} ==> ={res,glob Independent})
    (={x} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
      Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
      Independent.queries{1}=HmsgMemo.queries{2} ==>
      ={res} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
      Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
      Independent.queries{1}=HmsgMemo.queries{2}) => //.
  + by move=> &1 &2 h; exists Independent.queries{1} Independent.rawhistory{1} Independent.secrethistory{1} x{1}; smt().
  + exact factored_independent_hash.
  exact hmsg_factored_hash_refinement.
qed.
lemma hmsg_memo_derive_refinement :
  equiv [Independent.derive ~ HmsgMemo(AcceptedSamples).derive :
    ={tail} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2} ==>
    ={res} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2}].
proof. proc; if; auto. qed.
lemma hmsg_memo_context_refinement (A <: PrefixContext {-Independent,-HmsgMemo,-AcceptedSamples}) :
  equiv [A(Independent).run ~ A(HmsgMemo(AcceptedSamples)).run :
    ={glob A} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2} ==>
    ={res,glob A} /\ Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2}].
proof.
  proc (Independent.rawhistory{1}=HmsgMemo.rawhistory{2} /\
    Independent.secrethistory{1}=HmsgMemo.secrethistory{2} /\
    Independent.queries{1}=HmsgMemo.queries{2}) => //.
  + exact hmsg_memo_hash_refinement.
  exact hmsg_memo_derive_refinement.
qed.
