require import AllCore StdOrder.
require import WotsEncodingCharge AcceptedEncodingPool WotsAcceptedPool WotsAcceptedDistribution.
import RealOrder.

lemma witness q n : best_wots_encoding_charge q n<=accepted_encoding_charge q.
proof. exact (best_wots_encoding_charge_retains q n). qed.
