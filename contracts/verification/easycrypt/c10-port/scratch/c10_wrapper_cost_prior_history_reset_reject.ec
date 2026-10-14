(* Each admitted wrapper attempt includes up to TWO complete signing calls
   and ONE internal verification, including attempts that refuse to release. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RawSigner RawSignerCost.
(* Abstract query-bearing schedule of the sequential secure wrapper.
   Environmental rate/entropy/sentinel/delay gates are explicit booleans, not
   a model of their hardware implementations. Other dependencies have separate
   cost obligations. This is not a cross-language whole-program refinement. *)
require import AllCore List Distr.
require import C10RawOracle PrefixGuess PrefixHybrid RawSigner.

module RawWrapper (O : PrefixOracle) = {
  proc sign(seed root random message shuffle_a shuffle_b : raw_input,
            ready final_guard : bool) : raw_signature option = {
    var first, second, valid, result;
    Shared.calls <- 0; result <- None;
    if (ready) {
      first <@ RawSigner(O).sign(seed,root,random,message,shuffle_a);
      if (first <> None) {
        second <@ RawSigner(O).sign(seed,root,random,message,shuffle_b);
        if (second <> None /\ first = second) {
          valid <@ RawSigner(O).verify(seed,root,message,oget first);
          if (valid /\ final_guard) { result <- first; }
        }
      }
    }
    return result;
  }
}.


op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.
op wrapper_public_budget : int = 2*(3*signing_budget+364892)+771.

(* These identities expose the two-sign/one-verify charge to consumers and
   make a changed charge fail before an expensive solver fallback. *)
lemma wrapper_physical_budget_shape :
  wrapper_physical_budget = 2*(4*signing_budget+435646)+771.
proof. by rewrite /wrapper_physical_budget.
qed.
lemma wrapper_public_budget_shape :
  wrapper_public_budget = 2*(3*signing_budget+364892)+771.
proof. by rewrite /wrapper_public_budget.
qed.

lemma wrapper_physical_cost c :
  hoare[RawWrapper(Physical).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+wrapper_physical_budget].
proof.
  proc; sp 1; if; last by auto; rewrite wrapper_physical_budget_shape /signing_budget; smt().
  seq 1 : (c <= Shared.calls <= c+4*signing_budget+435646).
  + call (signer_sign_physical_cost c); auto.
  if; last by auto; rewrite wrapper_physical_budget_shape /signing_budget; smt().
  seq 1 : (c <= Shared.calls <= c+2*(4*signing_budget+435646)).
  + exists* Shared.calls; elim* => z; call (signer_sign_physical_cost z); auto; smt().
  if; last by auto; rewrite wrapper_physical_budget_shape /signing_budget; smt().
  wp; exists* Shared.calls; elim* => z; call (signer_verify_physical_cost z);
    auto; rewrite wrapper_physical_budget_shape; smt().
qed.

lemma wrapper_public_cost q :
  hoare[RawWrapper(Independent).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+wrapper_public_budget].
proof.
  proc; sp 1; if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt().
  seq 1 : (q <= size Independent.queries <= q+3*signing_budget+364892).
  + call (signer_sign_public_cost q); auto.
  if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt().
  seq 1 : (q <= size Independent.queries <= q+2*(3*signing_budget+364892)).
  + exists* Independent.queries; elim* => zs; call (signer_sign_public_cost (size zs)); auto; smt().
  if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt().
  wp; exists* Independent.queries; elim* => zs; call (signer_verify_public_cost (size zs));
    auto; rewrite wrapper_public_budget_shape; smt().
qed.
