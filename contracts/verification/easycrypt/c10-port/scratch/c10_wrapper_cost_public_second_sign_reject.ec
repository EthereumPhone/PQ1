(* Each admitted wrapper attempt includes up to TWO complete signing calls
   and ONE internal verification, including attempts that refuse to release. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RawSigner RawSignerCost RawWrapper.

op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.
op wrapper_public_budget : int = 1*(3*signing_budget+364892)+771.

(* These identities expose the two-sign/one-verify charge to consumers and
   are changed with the definition in budget controls, so those controls
   reach the consuming inequalities below. *)
lemma wrapper_physical_budget_shape :
  wrapper_physical_budget = 2*(4*signing_budget+435646)+771.
proof. by rewrite /wrapper_physical_budget.
qed.
lemma wrapper_public_budget_shape :
  wrapper_public_budget = 1*(3*signing_budget+364892)+771.
proof. by rewrite /wrapper_public_budget.
qed.

lemma wrapper_physical_cost c :
  hoare[RawWrapper(Physical).sign : Shared.calls = c ==>
    c <= Shared.calls <= c+wrapper_physical_budget].
proof.
  have step : forall (l z x a b t : int),
    l <= z => z <= l+a => z <= x => x <= z+b => a+b <= t =>
    l <= x <= l+t by smt(@Int).
  have hbudget : 2*(4*signing_budget+435646)+771 <= wrapper_physical_budget
    by rewrite wrapper_physical_budget_shape /signing_budget.
  proc; sp 1; if; last by auto => />; rewrite wrapper_physical_budget_shape /signing_budget ?lez_addl.
  seq 1 : (c <= Shared.calls <= c+4*signing_budget+435646).
  + call (signer_sign_physical_cost c); auto.
  if; last by auto; rewrite wrapper_physical_budget_shape /signing_budget; smt(@Int).
  seq 1 : (c <= Shared.calls <= c+2*(4*signing_budget+435646)).
  + exists* Shared.calls; elim* => z; call (signer_sign_physical_cost z); auto; smt(@Int).
  if; last by auto; rewrite wrapper_physical_budget_shape /signing_budget; smt(@Int).
  seq 1 : (c <= Shared.calls <= c+wrapper_physical_budget).
  + exists* Shared.calls; elim* => z.
    try call (signer_verify_physical_cost z).
    try call (signer_sign_physical_cost z).
    (* Infer the charge from the callee contract, then discharge the
       remaining numerical budget without a failing SMT search. *)
    auto => /> &hr hcz hza _ calls hzx hxb.
    try rewrite -addzA in hxb.
    have hb := step c z calls (2*(4*signing_budget+435646)) _ wrapper_physical_budget hcz hza hzx hxb.
    suff : c <= calls <= c+wrapper_physical_budget by smt(@Int).
    apply hb; by rewrite wrapper_physical_budget_shape /signing_budget.
  by auto.
qed.

lemma wrapper_public_cost q :
  hoare[RawWrapper(Independent).sign : size Independent.queries = q ==>
    q <= size Independent.queries <= q+wrapper_public_budget].
proof.
  have hbudget : 2*(3*signing_budget+364892)+771 <= wrapper_public_budget
    by rewrite wrapper_public_budget_shape /signing_budget.
  proc; sp 1; if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt(@Int).
  seq 1 : (q <= size Independent.queries <= q+3*signing_budget+364892).
  + call (signer_sign_public_cost q); auto.
  if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt(@Int).
  seq 1 : (q <= size Independent.queries <= q+2*(3*signing_budget+364892)).
  + exists* Independent.queries; elim* => zs; call (signer_sign_public_cost (size zs)); auto; smt(@Int).
  if; last by auto; rewrite wrapper_public_budget_shape /signing_budget; smt(@Int).
  wp; exists* Independent.queries; elim* => zs; call (signer_verify_public_cost (size zs));
    auto; smt(@Int).
qed.
