(* The full-digest distribution conditioned on the actual sum-205 predicate.
   Encoding atoms retain their exact deployed cardinality. *)
require import AllCore List Distr DList DBool StdOrder Ring.
require import C10RawOracle C10RawGrind C10Randomizer RawWots WotsAcceptanceMass.
import RField RealOrder DBool.Biased.

op accepted_wots_digest = dcond full_digest count_accepts.
op accepted_word_mass = (1%r/2%r)^129 / wots_acceptance_mass.

lemma accepted_wots_digest_ll : is_lossless accepted_wots_digest.
proof.
  apply dcond_ll; rewrite raw_wots_acceptance_mass.
  exact wots_acceptance_mass_positive.
qed.

lemma accepted_wots_digest_support d :
  d \in accepted_wots_digest => size d=256 /\ count_accepts d.
proof.
  rewrite /accepted_wots_digest dcond_supp /full_digest supp_dlist 1://.
  smt().
qed.

lemma accepted_wots_word_mass d : count_accepts d =>
  mu accepted_wots_digest (fun e => raw_digits d=raw_digits e)=accepted_word_mass.
proof.
  move=> hd; rewrite /accepted_wots_digest dcondE /predI raw_wots_acceptance_mass.
  have he : mu full_digest (fun e => count_accepts e /\ raw_digits d=raw_digits e)=
      mu full_digest (fun e => raw_digits d=raw_digits e).
  + apply mu_eq=> e; move: hd; rewrite /count_accepts; smt().
  by rewrite he raw_digits_atom /accepted_word_mass.
qed.

lemma accepted_word_mass_exact :
  accepted_word_mass=1%r/22169393903687611906220091621190388%r.
proof.
  rewrite /accepted_word_mass wots_acceptance_mass_value.
  have hp : (1%r/2%r)^129<>0%r by smt(expr_gt0).
  field; smt().
qed.

lemma accepted_wots_digest_accepts : mu accepted_wots_digest count_accepts=1%r.
proof.
  rewrite /accepted_wots_digest dcondE /predI.
  rewrite (mu_eq _ _ count_accepts) 1:/# raw_wots_acceptance_mass divff;
    smt(wots_acceptance_mass_positive).
qed.

op rejected_wots_digest = dcond full_digest (predC count_accepts).

lemma wots_acceptance_mass_lt_one : wots_acceptance_mass<1%r.
proof.
  rewrite wots_acceptance_mass_value (_ : 129=128+1) 1:// exprSr 1://
    (_ : 128=2*2*2*2*2*2*2) 1:// !exprM !expr2.
  smt().
qed.

lemma rejected_wots_digest_ll : is_lossless rejected_wots_digest.
proof.
  apply dcond_ll; rewrite mu_not full_digest_ll raw_wots_acceptance_mass.
  smt(wots_acceptance_mass_lt_one).
qed.

lemma rejected_wots_digest_support d :
  d \in rejected_wots_digest => size d=256 /\ !count_accepts d.
proof.
  rewrite /rejected_wots_digest dcond_supp /predC /full_digest supp_dlist 1://.
  smt().
qed.

lemma full_digest_wots_acceptance_split :
  full_digest=dlet (dbiased wots_acceptance_mass)
    (fun b=>if b then accepted_wots_digest else rejected_wots_digest).
proof.
  rewrite (marginal_sampling_pred full_digest count_accepts full_digest_ll)
    raw_wots_acceptance_mass /accepted_wots_digest /rejected_wots_digest.
  by [].
qed.
