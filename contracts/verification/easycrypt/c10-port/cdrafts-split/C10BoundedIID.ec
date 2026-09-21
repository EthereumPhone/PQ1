(* IID companion experiment, not the deterministic SHA-256 nonce loop.
   All draws are independent uniform 256-bit strings. Repetition is allowed.
   Instantiating the actual search needs a shared-oracle/adaptive-history proof. *)
require import AllCore List Distr StdOrder.
require import SPHINCS_PLUS WOTS_C_Real C10Counter C10Encoding C10Surface BoundedIID.
import FSSLXMTWES FSSLXMTWES.WTWES RealOrder.

op acceptance : real = 22169393903687611906220091621190388%r / (8 ^ 43)%r.
op fuel : unit list = nseq signing_budget tt.
op iid_search : msgWOTS option distr = bounded uniform_digest predC fuel.

lemma acceptance_exact : mu uniform_digest predC = acceptance.
proof. exact consumer_uniform_acceptance. qed.

lemma acceptance_positive : 0%r < acceptance.
proof. by rewrite /acceptance pow8_43; apply divr_gt0. qed.

lemma fuel_size : size fuel = signing_budget.
proof. by rewrite /fuel size_nseq /signing_budget. qed.

lemma iid_search_ll : is_lossless iid_search.
proof. by apply bounded_ll; exact uniform_digest_ll. qed.

lemma iid_exhaustion : mu1 iid_search None = (1%r - acceptance) ^ signing_budget.
proof. by rewrite /iid_search bounded_exhaustion 1:uniform_digest_ll acceptance_exact fuel_size. qed.

(* The success factor is retained. It cannot be dropped to turn a bounded
   sampler into an always-successful conditioned draw. *)
lemma iid_success_mass (event : msgWOTS -> bool) :
  mu iid_search (fun r => oapp event false r) =
    (1%r - (1%r - acceptance) ^ signing_budget) * mu (dcond uniform_digest predC) event.
proof.
  rewrite /iid_search bounded_success_mass 1:uniform_digest_ll.
  + by rewrite acceptance_exact acceptance_positive.
  by rewrite acceptance_exact fuel_size.
qed.

lemma iid_full_mixture (event : msgWOTS option -> bool) :
  mu iid_search event =
    (1%r - acceptance) ^ signing_budget * b2r (event None)
    + (1%r - (1%r - acceptance) ^ signing_budget)
      * mu (dcond uniform_digest predC) (fun d => event (Some d)).
proof.
  rewrite /iid_search bounded_as_conditioned_mixture 1:uniform_digest_ll.
  + by rewrite acceptance_exact acceptance_positive.
  by rewrite acceptance_exact fuel_size.
qed.
