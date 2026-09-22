require import AllCore List Distr DList DBool StdOrder StdBigop.
require C10Counter Birthday.
import RField RealOrder.
require import C10Randomizer.

lemma checked_truncate_uniform : dmap full_digest truncate_r = randomizer.
proof. exact truncate_uniform. qed.

lemma checked_randomizer_history_bound (history : bool list list) :
  mu randomizer (mem history) <= (size history)%r * (1%r / 2%r) ^ 128.
proof. exact randomizer_history_bound. qed.

lemma high_half : truncate_r (nseq 128 false ++ nseq 128 true) = nseq 128 true.
proof. by rewrite /truncate_r drop_cat size_nseq /= drop0. qed.
