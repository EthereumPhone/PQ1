require import AllCore IntDiv StdOrder Ring.
require import C10Counter WotsAcceptanceMass WotsRejectDomain GrindTail.
require import ByteRAvailability ByteTotalAvailability FullRBound FullSessionCost FullPrefix.
import RField RealOrder.
require import AvailabilityNumerics.

lemma checked :
  byte_total_availability_charge (2^32) (2^25) <= (1%r/2%r)^38.
proof. exact total_availability_numerical. qed.
