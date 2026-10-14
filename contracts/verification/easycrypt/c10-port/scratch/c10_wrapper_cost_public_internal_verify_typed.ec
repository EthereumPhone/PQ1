(* Each admitted wrapper attempt includes up to TWO complete signing calls
   and ONE internal verification, including attempts that refuse to release. *)
require import AllCore List Distr.
require import C10RawOracle C10Counter PrefixGuess PrefixHybrid.
require import RawSigner RawSignerCost RawWrapper.

op wrapper_physical_budget : int = 2*(4*signing_budget+435646)+771.
op wrapper_public_budget : int = 2*(3*signing_budget+364892)+0.

(* These identities expose the two-sign/one-verify charge to consumers and
   are changed with the definition in budget controls, so those controls
   reach the consuming inequalities below. *)


