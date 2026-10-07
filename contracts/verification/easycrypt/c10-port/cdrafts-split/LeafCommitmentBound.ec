(* Adaptive hidden-node guesses despite any number of memoized commitments.
   The context has no opening oracle. An actual signer reduction must discharge
   this condition and count every non-encapsulated public hash query. *)
require import AllCore List Distr FMap StdOrder.
require import C10RawOracle C10Randomizer SecretPrefix PrefixGuess PrefixHybrid.
require import RawKeygen NodeDistribution LeafCommitmentHybrid.
import RealOrder.

op leaf_commitment_candidates queries outputs = map leaf_suffix_candidate queries ++ outputs.
op leaf_commitment_hit key queries = List.mem (map leaf_suffix_candidate queries) key.

lemma leaf_commitment_hit_rcons key queries x :
  leaf_commitment_hit key (rcons queries x)=
    (leaf_commitment_hit key queries \/ leaf_suffix_candidate x=key).
proof. rewrite /leaf_commitment_hit map_rcons mem_rcons; smt(). qed.
lemma leaf_commitment_candidate_mass queries outputs :
  mu full_digest (fun d => mem (leaf_commitment_candidates queries outputs) (node d)) <=
    (size queries+size outputs)%r*(1%r/2%r)^128.
proof.
  have h := node_history_mass (leaf_commitment_candidates queries outputs).
  by rewrite /leaf_commitment_candidates size_cat size_map in h.
qed.
module RealLeafGuess (A : LeafCommitmentContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest; LeafCommitmentReal.key <- node key;
    Shared.init(); outputs <@ A(LeafCommitmentReal).run();
    return mem outputs (node key);
  }
}.
module HybridLeafGuess (A : LeafCommitmentContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest; LeafCommitmentHybrid.key <- node key;
    LeafCommitmentHybrid.bad <- false;
    Independent.init(); outputs <@ A(LeafCommitmentHybrid).run();
    return mem outputs (node key);
  }
}.
module IndependentLeafGuess (A : LeafCommitmentContext) = {
  proc run() : bool = {
    var key, outputs;
    key <$ full_digest;
    Independent.init(); outputs <@ A(Independent).run();
    return mem (leaf_commitment_candidates Independent.queries outputs) (node key);
  }
}.
module LateLeafGuess (A : LeafCommitmentContext) = {
  proc run() : bool = {
    var key, outputs;
    Independent.init(); outputs <@ A(Independent).run();
    key <$ full_digest;
    return mem (leaf_commitment_candidates Independent.queries outputs) (node key);
  }
}.
lemma leaf_guess_games_upto
  (A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) :
  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless A(O).run) =>
  equiv [RealLeafGuess(A).run ~ HybridLeafGuess(A).run :
    ={glob A} ==> !LeafCommitmentHybrid.bad{2} => ={res}].
proof.
  move=> hll; proc; call (adaptive_leaf_commitment A hll).
  inline *; auto => /> key hkey; rewrite node_width /leaf_commitment_tables /=; smt(emptyE).
qed.
lemma leaf_commitment_instrumentation
  (A <: LeafCommitmentContext {-LeafCommitmentHybrid,-Independent}) key :
  equiv [A(LeafCommitmentHybrid).run ~ A(Independent).run :
    ={glob A,glob Independent} /\ LeafCommitmentHybrid.key{1}=node key /\
    LeafCommitmentHybrid.bad{1}=leaf_commitment_hit (node key) Independent.queries{2} ==>
    ={res,glob A,glob Independent} /\ LeafCommitmentHybrid.key{1}=node key /\
    LeafCommitmentHybrid.bad{1}=leaf_commitment_hit (node key) Independent.queries{2}].
proof.
  proc (={glob Independent} /\ LeafCommitmentHybrid.key{1}=node key /\
    LeafCommitmentHybrid.bad{1}=leaf_commitment_hit (node key) Independent.queries{2}) => //.
  + proc; inline *; sp 3 1; if; auto; smt(leaf_commitment_hit_rcons).
  proc; if; auto; smt().
qed.
lemma hybrid_leaf_guess_is_independent
  (A <: LeafCommitmentContext {-LeafCommitmentHybrid,-Independent}) &m :
  Pr[HybridLeafGuess(A).run() @ &m : res \/ LeafCommitmentHybrid.bad] =
  Pr[IndependentLeafGuess(A).run() @ &m : res].
proof.
  byequiv (_ : ={glob A} ==> (res{1} \/ LeafCommitmentHybrid.bad{1})=res{2}) => //.
  proc; seq 1 1 : (={glob A,key}); first by auto.
  exists* key{1}; elim* => key0.
  call (leaf_commitment_instrumentation A key0); inline *; auto;
    rewrite /leaf_commitment_hit /leaf_commitment_candidates /=; smt(mem_cat).
qed.
lemma leaf_guess_late (A <: LeafCommitmentContext {-Independent}) :
  equiv [IndependentLeafGuess(A).run ~ LateLeafGuess(A).run : ={glob A} ==> ={res}].
proof. proc; swap{1} 1 2; sim. qed.
lemma independent_leaf_guess_bound (A <: LeafCommitmentContext {-Independent}) q n &m :
  0<=q => 0<=n =>
  hoare [A(Independent).run : Independent.queries=[] ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[IndependentLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hq hn hb.
  have he : Pr[IndependentLeafGuess(A).run() @ &m : res]=Pr[LateLeafGuess(A).run() @ &m : res]
    by byequiv (leaf_guess_late A) => //.
  rewrite he; byphoare (_ : true ==> res) => //.
  proc; rnd; call hb; inline Independent.init; auto => /> outputs queries hqs hos.
  have hm := leaf_commitment_candidate_mass queries outputs.
  have hp : 0%r <= (1%r/2%r)^128 by apply expr_ge0; smt().
  smt(le_fromint).
qed.
lemma adaptive_hidden_leaf_guess_bound
  (A <: LeafCommitmentContext {-LeafCommitmentReal,-LeafCommitmentHybrid,-Shared,-Independent}) q n &m :
  (forall (O <: PrefixOracle {-A}), islossless O.hash => islossless O.derive => islossless A(O).run) =>
  0<=q => 0<=n =>
  hoare [A(Independent).run : Independent.queries=[] ==>
    size Independent.queries<=q /\ size res<=n] =>
  Pr[RealLeafGuess(A).run() @ &m : res] <= (q+n)%r*(1%r/2%r)^128.
proof.
  move=> hll hq hn hb.
  have he : Pr[RealLeafGuess(A).run() @ &m : res] <=
    Pr[HybridLeafGuess(A).run() @ &m : res \/ LeafCommitmentHybrid.bad].
  + byequiv (_ : ={glob A} ==> res{1} => res{2} \/ LeafCommitmentHybrid.bad{2}) => //.
    conseq (leaf_guess_games_upto A hll); smt().
  rewrite (hybrid_leaf_guess_is_independent A &m) in he.
  have hbnd := independent_leaf_guess_bound A q n &m hq hn hb.
  smt().
qed.
