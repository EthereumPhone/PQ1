require import AllCore StdOrder.
require import WotsEncodingCharge AcceptedEncodingPool WotsAcceptedPool WotsAcceptedDistribution.
import RealOrder.

lemma ordinary_regrouped qr qs : qr+2*(1+2*qs)=qr+4*qs+2.
proof. smt(). qed.
lemma wrapper_regrouped qr qs : qr+(4+4+2)*qs+2=qr+10*qs+2.
proof. smt(). qed.
