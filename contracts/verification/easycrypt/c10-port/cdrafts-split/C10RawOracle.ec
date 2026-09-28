(* Classical shared raw-input idealization with private persistent history and explicit query counters. Arbitrary raw queries remain available. *)
require import AllCore List Distr DList DBool FMap C10Randomizer.

(* Classical shared raw-input idealization, with persistent history and costs.
   Arbitrary raw queries and all role adapters use the same table. *)

type raw_input = int list.
type digest = bool list.

module type Hash = { proc hash(x : raw_input) : digest }.

module Shared = {
  var history : (raw_input,digest) fmap
  var calls : int
  var draws : int
  proc init() : unit = {
    history <- empty; calls <- 0; draws <- 0;
  }
  proc hash(x : raw_input) : digest = {
    var y : digest;
    calls <- calls + 1;
    if (x \notin history) {
      y <$ full_digest;
      history.[x] <- y;
      draws <- draws + 1;
    }
    return oget history.[x];
  }
}.

lemma full_digest_ll : is_lossless full_digest.
proof. by rewrite /full_digest; apply dlist_ll; exact dbool_ll. qed.

lemma hash_ll : islossless Shared.hash.
proof. proc; sp 1; if; auto; smt(full_digest_ll). qed.

lemma hash_cost c d :
  hoare[Shared.hash : Shared.calls = c /\ Shared.draws = d ==>
    Shared.calls = c+1 /\ d <= Shared.draws <= d+1].
proof. by proc; sp 1; if; auto; smt(). qed.

lemma hash_history h x0 :
  hoare[Shared.hash : Shared.history = h /\ x = x0 ==>
    Shared.history.[x0] = Some res /\
    (if x0 \in h then Shared.history = h else Shared.history = h.[x0 <- res])].
proof.
  proc; sp 1; if; auto => />; smt(get_set_sameE domE).
qed.

lemma hash_replay h x0 y c d :
  h.[x0] = Some y =>
  hoare[Shared.hash : Shared.history = h /\ x = x0 /\ Shared.calls = c /\ Shared.draws = d ==>
    res = y /\ Shared.history = h /\ Shared.calls = c+1 /\ Shared.draws = d].
proof. move=> hy; proc; rcondf 2; by auto; smt(domE). qed.

(* Reference oracle without counters: arbitrary adaptive contexts retain both
   their result and their complete final shared table under instrumentation. *)
module Reference = {
  var history : (raw_input,digest) fmap
  proc init() : unit = { history <- empty; }
  proc hash(x : raw_input) : digest = {
    var y : digest;
    if (x \notin history) {
      y <$ full_digest;
      history.[x] <- y;
    }
    return oget history.[x];
  }
}.

module type Context (H : Hash) = { proc run() : bool { H.hash } }.
module Experiment (H : Hash, A : Context) = {
  proc run() : bool = { var r; r <@ A(H).run(); return r; }
}.

lemma instrumented_query :
  equiv[Reference.hash ~ Shared.hash :
    ={x} /\ Reference.history{1} = Shared.history{2} ==>
    ={res} /\ Reference.history{1} = Shared.history{2}].
proof. by proc; sim. qed.

lemma adaptive_instrumentation (A <: Context {-Shared,-Reference}) :
  equiv[A(Reference).run ~ A(Shared).run :
    ={glob A} /\ Reference.history{1} = Shared.history{2} ==>
    ={res,glob A} /\ Reference.history{1} = Shared.history{2}].
proof.
  proc (Reference.history{1} = Shared.history{2}) => //.
  exact instrumented_query.
qed.

op valid_history (h : (raw_input,digest) fmap) =
  forall x y, h.[x] = Some y => size y = 256.

lemma hash_width :
  hoare[Shared.hash : valid_history Shared.history ==>
    valid_history Shared.history /\ size res = 256].
proof.
  proc; sp 1; if; auto => />.
  + move=> &m hh hn y hy; have hs : size y = 256
      by move: hy; rewrite /full_digest supp_dlist /=; smt().
    rewrite /valid_history in hh; rewrite /valid_history; smt(get_setE get_set_sameE).
  move=> &m hh hn; rewrite /valid_history in hh; smt(domE).
qed.

(* The two deployed R-derivation input lengths are disjoint from the other
   documented call shapes. Raw callers can still query either partition. *)
op r_domain (x : raw_input) = size x = 103 \/ size x = 119.

module Split = {
  var rhistory : (raw_input,digest) fmap
  var hhistory : (raw_input,digest) fmap
  proc init() : unit = { rhistory <- empty; hhistory <- empty; }
  proc hash(x : raw_input) : digest = {
    var y : digest;
    if (r_domain x) {
      if (x \notin rhistory) { y <$ full_digest; rhistory.[x] <- y; }
      y <- oget rhistory.[x];
    } else {
      if (x \notin hhistory) { y <$ full_digest; hhistory.[x] <- y; }
      y <- oget hhistory.[x];
    }
    return y;
  }
}.

lemma split_query :
  equiv[Reference.hash ~ Split.hash :
    ={x} /\ Reference.history{1} = union_map Split.rhistory{2} Split.hhistory{2} /\
    (forall x, x \in Split.rhistory{2} => r_domain x) /\
    (forall x, x \in Split.hhistory{2} => !r_domain x) ==>
    ={res} /\ Reference.history{1} = union_map Split.rhistory{2} Split.hhistory{2} /\
    (forall x, x \in Split.rhistory{2} => r_domain x) /\
    (forall x, x \in Split.hhistory{2} => !r_domain x)].
proof.
  proc; if{2}.
  + if.
    - auto; smt(mem_union_map).
    - auto => />; smt(get_setE set_union_map_l mem_set mergeE).
    auto => />; smt(mergeE domE).
  if.
  + auto; smt(mem_union_map).
  + auto => />; smt(get_setE set_union_map_r mem_set mergeE).
  auto => />; smt(mergeE domE).
qed.

lemma adaptive_split (A <: Context {-Reference,-Split}) :
  equiv[A(Reference).run ~ A(Split).run :
    ={glob A} /\ Reference.history{1} = union_map Split.rhistory{2} Split.hhistory{2} /\
    (forall x, x \in Split.rhistory{2} => r_domain x) /\
    (forall x, x \in Split.hhistory{2} => !r_domain x) ==>
    ={res,glob A} /\ Reference.history{1} = union_map Split.rhistory{2} Split.hhistory{2} /\
    (forall x, x \in Split.rhistory{2} => r_domain x) /\
    (forall x, x \in Split.hhistory{2} => !r_domain x)].
proof.
  proc (Reference.history{1} = union_map Split.rhistory{2} Split.hhistory{2} /\
    (forall x, x \in Split.rhistory{2} => r_domain x) /\
    (forall x, x \in Split.hhistory{2} => !r_domain x)) => //.
  exact split_query.
qed.
