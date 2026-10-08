require import AllCore List.
require import C10RawOracle RawSigner FullPrefix NumericalByteBound.
lemma physical_charge qr qs :
  physical_euf_charge qr qs = independent_euf_charge qr qs +
    0%r.
proof. by rewrite /physical_euf_charge. qed.
