(* A selected digest is uniform whether drawn from the hidden or visible sample stream. *)
require import AllCore List Distr.
require import C10RawOracle C10Randomizer.
module FullDigestDraw = {
  proc sample() : digest = { var d; d <$ full_digest; return d; }
}.
module DualDigest = {
  var hidden, visible : digest list
  proc draw(select : bool) : digest = {
    var h,v;
    h <$ full_digest; v <$ full_digest;
    hidden <- rcons hidden h; visible <- rcons visible v;
    return if select then h else v;
  }
}.
lemma dual_digest_projection :
  equiv [FullDigestDraw.sample ~ DualDigest.draw : true ==> ={res}].
proof.
  proc; wp; case (select{2}).
  + swap{2} 1 1; rnd; rnd{2}; auto; smt(full_digest_ll).
  rnd; rnd{2}; auto; smt(full_digest_ll).
qed.
