(* A successful actual raw run supplies a persistent witness for its repeats. *)
require import AllCore List Distr FMap.
require import C10RawOracle C10RawGrind C10Counter C10HashDomains.
require import GrindReplay GrindWitness.

op extends (h0 h : (raw_input,digest) fmap) =
  forall x y, h0.[x] = Some y => h.[x] = Some y.

lemma accepted_extends h0 h secret random message seed root :
  extends h0 h => accepted_witness h0 secret random message seed root =>
  accepted_witness h secret random message seed root.
proof. rewrite /extends /accepted_witness; smt(). qed.

lemma hash_extends h0 :
  hoare[Shared.hash : extends h0 Shared.history ==> extends h0 Shared.history].
proof. proc; sp 1; if; auto; rewrite /extends; smt(get_setE domE). qed.

lemma cached_witness_failure_zero secret0 random0 message0 seed0 root0 &m :
  accepted_witness Shared.history{m} secret0 random0 message0 seed0 root0 =>
  Pr[StatefulGrind(Shared).run(secret0,random0,message0,seed0,root0) @ &m : res = None] = 0%r.
proof.
  rewrite /accepted_witness => hex.
  elim hex => j rd0 hd0 [#] hj0 hj1 ha hr hh.
  have hj : 0 <= j < signing_budget by smt().
  byphoare (_ : secret = secret0 /\ random = random0 /\ message = message0 /\
    seed = seed0 /\ root = root0 /\
    Shared.history.[r_input secret0 random0 message0 (U32.insubd j)] = Some rd0 /\
    Shared.history.[hmsg_input seed0 root0 (compact_r rd0 ++ nseq 16 0) message0] = Some hd0 ==>
    res = None) => //.
  hoare; conseq (grind_cached_success secret0 random0 message0 seed0 root0 j rd0 hd0 hj ha); smt().
qed.
