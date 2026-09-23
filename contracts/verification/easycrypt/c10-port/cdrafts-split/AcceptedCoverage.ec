(* External Q research: FORS opening sets fixed before the grind begins.
   Future enlarged sets require a separate adaptive argument. *)
require import AllCore List Distr DList DBool FMap StdOrder StdBigop.
require import C10RawOracle C10Randomizer C10RawGrind PrefixGuess RawTrial.
require import RTailFresh RoleGrind StreamBound GrindExhaustion.
require import DigestPrefix FreshCoverage AcceptedSampling StreamAccepted.
import RField RealOrder Bigreal Bigreal.BRM.

op prior_covered (opened : bool list list list) (d : digest) =
  forall i, 0 <= i < 12 => take 11 (drop (11*i) d) \in nth [] opened i.
op prior_coverage_mass (opened : bool list list list) =
  bigi predT (fun i => mu (dlist dbool 11)
    (fun chunk => chunk \in nth [] opened i)) 0 12.
op prior_coverage_cardinality (opened : bool list list list) =
  bigi predT (fun i => (size (nth [] opened i))%r * (1%r/2%r)^11) 0 12.

lemma accepted_coverage_probability opened :
  accepted_probability (prior_covered opened) = prior_coverage_mass opened.
proof.
  rewrite /accepted_probability /accepted_mass /prior_covered fresh_c10_coverage.
  rewrite /prior_coverage_mass /acceptance_rate mulrK; smt(expr_gt0).
qed.

lemma prior_coverage_cardinality_bound opened :
  prior_coverage_mass opened <= prior_coverage_cardinality opened.
proof.
  rewrite /prior_coverage_mass /prior_coverage_cardinality.
  apply ler_prod => i _; split.
  + have h := mu_bounded (dlist dbool 11) (fun chunk => chunk \in nth [] opened i); smt().
  move=> _ /=; apply mu_mem_le_mu1; move=> t; apply prefix_atom_bound; smt().
qed.

lemma role_grind_prior_coverage opened q0 random message seed root &m :
  0 <= q0 => size Independent.queries{m} = q0 =>
  history_recorded Independent.rawhistory{m} Independent.queries{m} =>
  future_fresh Independent.secrethistory{m} random message 0 =>
  size seed = 32 => size root = 32 =>
  Pr[RoleGrind(Independent).run(random,message,seed,root) @ &m :
    res <> None /\ prior_covered opened (oget res).`2]
    <= prior_coverage_cardinality opened + revisit_charge q0.
proof.
  move=> hq hsize hrecord hf hs hr.
  have h := role_grind_accepted_bound (prior_covered opened)
    q0 random message seed root &m hq hsize hrecord hf hs hr.
  rewrite accepted_coverage_probability in h.
  have hc := prior_coverage_cardinality_bound opened.
  smt().
qed.
