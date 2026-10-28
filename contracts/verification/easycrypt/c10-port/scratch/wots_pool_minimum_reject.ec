require import AllCore StdOrder.
require import WotsEncodingCharge AcceptedEncodingPool WotsAcceptedPool WotsAcceptedDistribution.
import RealOrder.

lemma checked q n : accepted_encoding_charge q<=best_wots_encoding_charge q n.
proof. exact (best_wots_encoding_charge_retains q n). qed.
