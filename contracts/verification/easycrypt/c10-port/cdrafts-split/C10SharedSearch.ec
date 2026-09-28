(* C10's actual WOTS predicate and byte payload in a classical random oracle.
   The arbitrary entry history is retained. No theorem identifies this oracle
   with the abstract ThC or with real SHA-256. *)
require import AllCore List Distr.
require import C10BoundedIID C10BoundedGrind C10DeployedInstance SharedROBounded C10Encoding WOTS_C_Real.
import SPHINCS_PLUS FSSLXMTWES FSSLXMTWES.WTWES C10Counter.

op counter_inputs (seed address : int list) (m : dgstblock) =
  map (fun i => seed ++ address ++ c10_payload (m, of_int i))
    (range 0 signing_budget).

lemma counter_inputs_size (seed address : int list) (m : dgstblock) :
  size (counter_inputs seed address m) = signing_budget.
proof. by rewrite /counter_inputs size_map size_range /signing_budget. qed.

lemma counter_inputs_unique (seed address : int list) (m : dgstblock) :
  uniq (counter_inputs seed address m).
proof.
  rewrite /counter_inputs; apply map_inj_in_uniq; last exact (range_uniq _ _).
  move=> i j; rewrite !mem_range /= => hi hj he.
  have hp : c10_payload (m,of_int i) = c10_payload (m,of_int j).
  + exact (catsI (seed ++ address) _ _ he).
  have hc := c10_payload_injective (m,of_int i) (m,of_int j) hp.
  have hi32 : 0 <= i < 4294967296 by move: hi; rewrite /signing_budget; smt().
  have hj32 : 0 <= j < 4294967296 by move: hj; rewrite /signing_budget; smt().
  have hcounter : of_int i = of_int j by smt().
  by rewrite -(of_int_value i hi32) -(of_int_value j hj32) hcounter.
qed.

op shared_search (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) =
  ro_search uniform_digest predC history (counter_inputs seed address m).

lemma shared_history_exhaustion (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  mu1 (shared_search seed address m history) None <=
    (1%r - acceptance) ^ fresh_count history (counter_inputs seed address m).
proof.
  rewrite /shared_search -acceptance_exact.
  by apply history_search_exhaustion; [exact uniform_digest_ll | exact counter_inputs_unique].
qed.

lemma shared_fresh_exhaustion (seed address : int list) (m : dgstblock)
  (history : (int list * msgWOTS) list) :
  (forall x, x \in counter_inputs seed address m => assoc history x = None) =>
  mu1 (shared_search seed address m history) None =
    (1%r - acceptance) ^ signing_budget.
proof.
  by move=> hf; rewrite /shared_search fresh_search_exhaustion
    1:uniform_digest_ll 1:counter_inputs_unique // acceptance_exact counter_inputs_size.
qed.
